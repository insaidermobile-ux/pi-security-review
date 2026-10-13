import assert from "node:assert/strict";
import { existsSync, readdirSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import { AGENT_RETRY, createAuditSession, createSdkAgentRunner, UsageLedger } from "../extensions/security-review/agent-runtime.ts";
import { mapBounded } from "../extensions/security-review/pool.ts";
import { createReadOnlyTools, isInsideProject } from "../extensions/security-review/read-tools.ts";
import { git } from "../extensions/security-review/scope.ts";
import { checkCommand, createShellTool, ShellRejection } from "../extensions/security-review/shell.ts";
import {
	checkAnchors,
	createAffirmTool,
	createHypothesisTool,
	createTriageTool,
	type HypothesisCollector,
	type TriageCollector,
} from "../extensions/security-review/submit-tools.ts";
import type { AffirmArgument } from "../extensions/security-review/schema.ts";
import { failTimes, fauxAssistantMessage, fauxToolCall, hang, providerError, RATE_LIMITED, scriptedRuntime, type ScriptStep } from "./faux.ts";
import { affirm, hypothesisInput } from "./fixtures.ts";
import { makeRepo, sh, write } from "./git-fixtures.ts";
import { tempDir } from "./temp.ts";

const SYSTEM = "You are a test auditor.";

describe("audit session", () => {
	test("has only read-only tools plus the role's submission tool and is not persisted", async () => {
		const { runtime, model, root } = await scriptedRuntime({});
		const collector: HypothesisCollector = { hypotheses: [] };
		const session = await createAuditSession(
			{ root, modelRuntime: runtime, timeoutMs: 1000, ledger: new UsageLedger() },
			{ model, systemPrompt: SYSTEM, tools: [createHypothesisTool(root, collector)] },
		);
		try {
			const tools = session.getActiveToolNames().sort();
			assert.deepEqual(tools, ["find", "grep", "ls", "read", "shell", "submit_hypothesis"]);
			for (const forbidden of ["write", "edit", "bash", "powershell"]) assert.ok(!tools.includes(forbidden));
			assert.equal(session.sessionFile, undefined);
			assert.equal(session.systemPrompt.startsWith(SYSTEM), true);
		} finally {
			session.dispose();
		}
	});

	test("its read tool cannot leave the project", async () => {
		const repo = makeRepo({ "src/a.ts": "const inside = 1;\n" });
		const outside = join(tempDir("sr-outside-"), "secret.txt");
		writeFileSync(outside, "SECRET\n");
		const { runtime, model } = await scriptedRuntime({
			"READ-AGENT": [fauxAssistantMessage(fauxToolCall("read", { path: outside })), fauxAssistantMessage(fauxToolCall("read", { path: "src/a.ts" })), fauxAssistantMessage("done")],
		});
		const session = await createAuditSession({ root: repo, modelRuntime: runtime, timeoutMs: 10_000, ledger: new UsageLedger() }, { model, systemPrompt: SYSTEM, tools: [] });
		const toolResults: string[] = [];
		session.subscribe((event) => {
			if (event.type !== "message_end" || event.message.role !== "toolResult") return;
			const content = event.message.content[0];
			toolResults.push(content?.type === "text" ? content.text : "");
		});
		await session.prompt("READ-AGENT go");
		session.dispose();
		assert.match(toolResults[0]!, /outside the project/);
		assert.doesNotMatch(toolResults.join("\n"), /SECRET/);
		assert.match(toolResults[1]!, /const inside = 1/);
	});
});

describe("read-only shell", () => {
	const root = "/project";

	test("allows inspection commands", () => {
		assert.deepEqual(checkCommand("rg -n 'select .* from' src", root), ["rg", "-n", "select .* from", "src"]);
		assert.deepEqual(checkCommand("cat src/a.ts", root), ["cat", "src/a.ts"]);
		assert.deepEqual(checkCommand("git log -n 3 -- src/a.ts", root), [
			"git", "-c", "core.pager=cat", "--no-pager", "log", "--no-ext-diff", "--no-textconv", "-n", "3", "--", "src/a.ts",
		]);
		assert.deepEqual(checkCommand("git blame -L 10,20 src/a.ts", root).slice(4), ["blame", "--no-textconv", "-L", "10,20", "src/a.ts"]);
		assert.deepEqual(checkCommand("ls -laR src", root), ["ls", "-laR", "src"]);
		assert.deepEqual(checkCommand("wc -l src/a.ts", root), ["wc", "-l", "src/a.ts"]);
		assert.ok(checkCommand("git diff HEAD~3..HEAD", root).includes("diff"));
	});

	test("allows options that only resemble denied ones", () => {
		// The pickaxe value and the pattern contain "O", which is a pager option only as a `git grep` flag.
		assert.ok(checkCommand("git log -SOAuth", root).includes("-SOAuth"));
		assert.ok(checkCommand("git grep -eOAuth src", root).includes("-eOAuth"));
		assert.ok(checkCommand("git diff --text HEAD~1", root).includes("--text"));
		assert.ok(checkCommand("git diff --output-indicator-new=x HEAD~1", root).includes("diff"));
		assert.deepEqual(checkCommand("rg -tzig main", root), ["rg", "-tzig", "main"]);
		assert.deepEqual(checkCommand("rg foo -- -z", root), ["rg", "foo", "--", "-z"]);
	});

	const rejected: Array<[string, RegExp]> = [
		["rm -rf src", /not allowed/],
		["bash -c ls", /not allowed/],
		["node -e 1", /not allowed/],
		["cat a.ts | sh", /operator "\|"/],
		["cat a.ts; rm a.ts", /operator ";"/],
		["cat a.ts && rm a.ts", /operator "&"/],
		["cat $(whoami)", /operator "\$"/],
		["cat `whoami`", /operator "`"/],
		["cat a.ts > b.ts", /operator ">"/],
		["git -c core.pager=sh log", /must come first/],
		["git commit -m x", /must come first/],
		["git push", /must come first/],
		["git checkout main", /must come first/],
		["git log --output=pwned", /--output=pwned is not allowed/],
		["git diff --ext-diff", /not allowed/],
		["git grep -Ocat foo", /not allowed/],
		["git grep --open-files-in-pager=sh x", /not allowed/],
		// git accepts unambiguous abbreviations of long options.
		["git grep \"--op=sh -c 'id > pwned' #\" x", /--op=sh .* is not allowed/],
		["git grep --open x", /not allowed/],
		["git log --outp=pwned", /not allowed/],
		["git diff --ext", /not allowed/],
		["git show --textc", /not allowed/],
		["git grep -nO sh x", /not allowed/],
		["git grep -5Osh x", /not allowed/],
		["rg --follow foo", /not allowed/],
		// ls and wc must not reach files outside the project through a symbolic link inside it.
		["ls -lRL src", /not allowed/],
		["ls -H src", /not allowed/],
		["ls --dereference src", /not allowed/],
		["ls --deref src", /not allowed/],
		["wc --files0-from=list.txt", /not allowed/],
		// A submodule's config, and so its filter drivers, are not neutralized.
		["git status --ignore-submodules=none", /not allowed/],
		["git diff --submodule=diff", /not allowed/],
		["git grep --recurse-submodules x", /not allowed/],
		["rg -L foo", /not allowed/],
		["rg -f/etc/passwd foo", /outside the project/],
		["rg -f=/etc/passwd foo", /outside the project/],
		["cat -- /etc/passwd", /outside the project/],
		// Names inherited from Object.prototype are not commands.
		["constructor", /not allowed/],
		["toString x", /not allowed/],
		["__proto__", /not allowed/],
		["rg --pre sh foo", /not allowed/],
		["rg --pre=./x foo", /not allowed/],
		["rg -zl foo", /not allowed/],
		["tail -f log.txt", /not allowed/],
		["cat ../secret", /outside the project/],
		["cat /etc/passwd", /outside the project/],
		["cat ~/.ssh/id_rsa", /outside the project/],
		["rg --file=/etc/passwd x", /outside the project/],
		["cat 'unterminated", /Unterminated/],
	];
	for (const [command, pattern] of rejected) {
		test(`rejects: ${command}`, () => {
			assert.throws(() => checkCommand(command, root), (error: unknown) => error instanceof ShellRejection && pattern.test(error.message));
		});
	}

	test("executes allowed commands inside the project without a shell", async () => {
		const repo = makeRepo({ "src/a.ts": "const token = 'x';\n" });
		const tool = createShellTool(repo);
		const result = await tool.execute("1", { command: "rg -n token src" }, undefined, undefined, undefined as never);
		const text = result.content[0]!.type === "text" ? result.content[0]!.text : "";
		assert.match(text, /^exit 0\nsrc\/a\.ts:1:const token/);
		const log = await tool.execute("2", { command: "git log --oneline" }, undefined, undefined, undefined as never);
		assert.match(log.content[0]!.type === "text" ? log.content[0]!.text : "", /initial/);
	});

	test("searches the project when no path is given instead of waiting on stdin", async () => {
		const repo = makeRepo({ "src/a.ts": "const token = 'x';\n" });
		const started = Date.now();
		const result = await createShellTool(repo).execute("1", { command: "rg -n token" }, undefined, undefined, undefined as never);
		assert.match(result.content[0]!.type === "text" ? result.content[0]!.text : "", /^exit 0\nsrc\/a\.ts:1:const token/);
		assert.ok(Date.now() - started < 10_000);
	});

	test("an abbreviated pager option cannot run a program", async () => {
		const repo = makeRepo({ "src/a.ts": "const token = 'x';\n" });
		const command = `git grep "--op=sh -c 'echo pwned > pwned' #" token`;
		await assert.rejects(createShellTool(repo).execute("1", { command }, undefined, undefined, undefined as never), ShellRejection);
		assert.equal(existsSync(join(repo, "pwned")), false);
	});

	test("programs configured by the repository do not run while reading it", async () => {
		const repo = makeRepo({ "a.txt": "hello\n", ".gitattributes": "a.txt filter=x diff=x\n" });
		const marks = tempDir("sr-marks-");
		sh(repo, "config", "filter.x.clean", `sh -c 'touch ${marks}/clean; cat'`);
		sh(repo, "config", "filter.x.smudge", `sh -c 'touch ${marks}/smudge; cat'`);
		sh(repo, "config", "filter.x.required", "true");
		sh(repo, "config", "diff.x.textconv", `sh -c 'touch ${marks}/textconv; cat "$0"'`);
		sh(repo, "config", "log.showSignature", "true");
		sh(repo, "config", "gpg.program", `sh -c 'touch ${marks}/gpg' --`);
		const tool = createShellTool(repo);
		for (const command of ["git status", "git blame a.txt", "git cat-file --filters HEAD:a.txt", "git diff HEAD", "git log -p --format=%G?"]) {
			// A stale modification time makes git re-read the file through the clean filter.
			utimesSync(join(repo, "a.txt"), new Date(0), new Date(0));
			const result = await tool.execute("1", { command }, undefined, undefined, undefined as never);
			assert.match(result.content[0]!.type === "text" ? result.content[0]!.text : "", /^exit 0/, command);
		}
		utimesSync(join(repo, "a.txt"), new Date(0), new Date(0));
		assert.equal((await git(repo, ["status", "--porcelain"])).code, 0);
		assert.deepEqual(readdirSync(marks), []);
	});

	test("refuses a symbolic link that leaves the project", () => {
		const repo = makeRepo({ "src/a.ts": "1\n" });
		const outside = join(tempDir("sr-outside-"), "secret.txt");
		writeFileSync(outside, "SECRET\n");
		symlinkSync(outside, join(repo, "src/link.txt"));
		symlinkSync("a.ts", join(repo, "src/inside.txt"));
		assert.throws(() => checkCommand("cat src/link.txt", repo), /outside the project/);
		assert.deepEqual(checkCommand("cat src/inside.txt", repo), ["cat", "src/inside.txt"]);
	});
});

describe("confined read tools", () => {
	function fixture() {
		const repo = makeRepo({ "src/a.ts": "const inside = 1;\n" });
		const outsideDir = tempDir("sr-outside-");
		const outside = join(outsideDir, "secret.txt");
		writeFileSync(outside, "SECRET\n");
		symlinkSync(outside, join(repo, "src/link.txt"));
		symlinkSync(outsideDir, join(repo, "linked-dir"));
		const tools = new Map(createReadOnlyTools(repo).map((tool) => [tool.name, tool]));
		const run = async (name: string, params: Record<string, unknown>): Promise<string> => {
			try {
				const result = await tools.get(name)!.execute("1", params as never, undefined, undefined, undefined as never);
				const content = result.content[0];
				return content?.type === "text" ? content.text : "";
			} catch (error) {
				return `ERROR: ${(error as Error).message}`;
			}
		};
		return { repo, outside, outsideDir, tools, run };
	}

	test("replace pi's read, grep, find, and ls", () => {
		assert.deepEqual([...fixture().tools.keys()], ["read", "grep", "find", "ls"]);
	});

	test("read files and list directories inside the project", async () => {
		const { run } = fixture();
		assert.match(await run("read", { path: "src/a.ts" }), /const inside = 1/);
		assert.match(await run("ls", { path: "src" }), /a\.ts/);
		assert.match(await run("ls", {}), /src\//);
	});

	test("refuse absolute, home, parent, and symlinked paths outside the project", async () => {
		const { run, outside, outsideDir } = fixture();
		const refused = /^ERROR: Path .* is outside the project/;
		for (const path of [outside, `@${outside}`, "~/.ssh/id_rsa", "../secret.txt", "src/link.txt", "linked-dir/secret.txt"]) {
			assert.match(await run("read", { path }), refused, `read ${path}`);
		}
		for (const name of ["grep", "find", "ls"]) {
			for (const path of [outsideDir, `@${outsideDir}`, "~", "..", "linked-dir", `file://${outsideDir}`]) {
				assert.match(await run(name, { path, pattern: "SECRET" }), refused, `${name} ${path}`);
			}
		}
	});

	test("isInsideProject accepts paths that do not exist yet", () => {
		const { repo } = fixture();
		assert.equal(isInsideProject(repo, "src/missing.ts"), true);
		assert.equal(isInsideProject(repo, "."), true);
		assert.equal(isInsideProject("/no/such/root", "src/a.ts"), true);
		assert.equal(isInsideProject("/no/such/root", "/etc/passwd"), false);
		// A missing file behind a link out of the project is refused like an existing one.
		const { repo: linked, outsideDir } = fixture();
		symlinkSync(join(outsideDir, "missing.txt"), join(linked, "dangling.txt"));
		for (const path of ["linked-dir/missing.txt", "linked-dir/no/such/dir", "dangling.txt"]) assert.equal(isInsideProject(linked, path), false, path);
	});
});

describe("anchor checks", () => {
	test("refuse a file reached through a symbolic link that leaves the project, without revealing it", () => {
		const repo = makeRepo({ "src/a.ts": "1\n2\n" });
		const outside = tempDir("sr-outside-");
		writeFileSync(join(outside, "secret.txt"), "S\n".repeat(50));
		symlinkSync(outside, join(repo, "vendor"));
		symlinkSync(join(outside, "missing.txt"), join(repo, "src/dangling.txt"));
		for (const file of ["vendor/secret.txt", "vendor/missing.txt", "src/dangling.txt"]) {
			assert.throws(() => checkAnchors(repo, [{ file, line: 999_999 }]), /is outside the project\.$/);
		}
		assert.deepEqual(checkAnchors(repo, [{ file: "./src/a.ts", line: 2 }]), [{ file: "src/a.ts", line: 2 }]);
	});

	test("refuse a file name with control characters", () => {
		const repo = makeRepo({ "src/a.ts": "1\n" });
		const name = "src/a\u001b]8;;evil.example\u0007ok.ts";
		writeFileSync(join(repo, name), "1\n");
		assert.throws(() => checkAnchors(repo, [{ file: name, line: 1 }]), /control characters/);
	});
});

describe("submission tools through a real session", () => {
	test("invalid submissions are rejected with actionable errors and valid ones are captured", async () => {
		const repo = makeRepo({ "src/users.ts": "x\n".repeat(30) });
		const { runtime, model } = await scriptedRuntime({
			"HUNT-AGENT": [
				fauxAssistantMessage(fauxToolCall("submit_hypothesis", { ...hypothesisInput(), anchors: [] })),
				fauxAssistantMessage(fauxToolCall("submit_hypothesis", { ...hypothesisInput(), anchors: [{ file: "src/missing.ts", line: 1 }] })),
				fauxAssistantMessage(fauxToolCall("submit_hypothesis", hypothesisInput())),
				fauxAssistantMessage("done hunting"),
			],
		});
		const collector: HypothesisCollector = { hypotheses: [] };
		const toolResults: string[] = [];
		const session = await createAuditSession({ root: repo, modelRuntime: runtime, timeoutMs: 10_000, ledger: new UsageLedger() }, {
			model,
			systemPrompt: SYSTEM,
			tools: [createHypothesisTool(repo, collector)],
		});
		session.subscribe((event) => {
			if (event.type === "message_end" && event.message.role === "toolResult") {
				const content = event.message.content[0];
				toolResults.push(content?.type === "text" ? content.text : "");
			}
		});
		await session.prompt("HUNT-AGENT go");
		session.dispose();
		assert.match(toolResults[0]!, /Validation failed[\s\S]*anchors/);
		assert.match(toolResults[1]!, /src\/missing\.ts does not exist/);
		assert.match(toolResults[2]!, /Hypothesis #1 recorded/);
		assert.equal(collector.hypotheses.length, 1);
		assert.equal(collector.hypotheses[0]!.anchors[0]!.file, "src/users.ts");
	});

	test("an argument for the wrong hypothesis is rejected and the agent can retry", async () => {
		const repo = makeRepo();
		const { runtime, model } = await scriptedRuntime({
			"AFFIRM-AGENT": [
				fauxAssistantMessage(fauxToolCall("submit_argument", affirm("H-999"))),
				fauxAssistantMessage(fauxToolCall("submit_argument", affirm("H-001"))),
			],
		});
		const collector: { argument?: AffirmArgument } = {};
		const runner = createSdkAgentRunner({ root: repo, modelRuntime: runtime, timeoutMs: 10_000, ledger: new UsageLedger() });
		const outcome = await runner.run({
			label: "affirmer:H-001",
			role: "affirmer",
			model,
			systemPrompt: SYSTEM,
			prompt: "AFFIRM-AGENT go",
			tools: [createAffirmTool("H-001", collector)],
			done: () => collector.argument !== undefined,
		});
		assert.equal(outcome.ok, true, outcome.error);
		assert.equal(collector.argument?.hypothesis_id, "H-001");
	});
});

describe("triage tool", () => {
	const labels = ["C-1", "C-2", "C-3"];
	async function submitTriage(groups: unknown): Promise<{ text: string; collector: TriageCollector; terminate?: boolean }> {
		const collector: TriageCollector = {};
		const tool = createTriageTool(labels, collector);
		try {
			const result = await tool.execute("1", { groups } as never, undefined, undefined, undefined as never);
			const content = result.content[0];
			return { text: content?.type === "text" ? content.text : "", collector, terminate: (result as { terminate?: boolean }).terminate };
		} catch (error) {
			return { text: (error as Error).message, collector };
		}
	}

	const cases: [string, unknown, RegExp][] = [
		["unknown label", [{ primary: "C-1", members: ["C-1", "C-9"], reason: "r" }], /unknown candidates: C-9\. Known candidates are C-1, C-2, C-3/],
		["label in two groups", [{ primary: "C-1", members: ["C-1", "C-2"], reason: "r" }, { primary: "C-3", members: ["C-3", "C-2"], reason: "r" }], /C-2 appears in group 1 and group 2/],
		["single member", [{ primary: "C-1", members: ["C-1", "C-1"], reason: "r" }], /fewer than two distinct members/],
		["primary outside its group", [{ primary: "C-3", members: ["C-1", "C-2"], reason: "r" }], /primary C-3 must be one of its members/],
	];
	for (const [name, groups, pattern] of cases) {
		test(`rejects ${name} and records nothing`, async () => {
			const { text, collector } = await submitTriage(groups);
			assert.match(text, pattern);
			assert.match(text, /call submit_triage again/);
			assert.equal(collector.groups, undefined);
		});
	}

	test("accepts a valid grouping and an empty list, and terminates", async () => {
		const valid = await submitTriage([{ primary: "C-2", members: ["C-1", "C-2"], reason: "same query" }]);
		assert.match(valid.text, /Triage recorded \(1 groups\)/);
		assert.equal(valid.terminate, true);
		assert.deepEqual(valid.collector.groups?.[0]?.members, ["C-1", "C-2"]);
		const empty = await submitTriage([]);
		assert.deepEqual(empty.collector.groups, []);
	});
});

describe("transient provider errors", () => {
	const FAST_RETRY = { maxRetries: 2, baseDelayMs: 1, maxAgentDelayMs: 1 };

	async function runOnce(step: ScriptStep, options: { timeoutMs?: number; done?: () => boolean } = {}) {
		const repo = makeRepo();
		const { runtime, model, calls } = await scriptedRuntime({ "FLAKY-AGENT": [step] });
		const runner = createSdkAgentRunner({ root: repo, modelRuntime: runtime, timeoutMs: options.timeoutMs ?? 10_000, ledger: new UsageLedger(), retry: FAST_RETRY });
		const outcome = await runner.run({ label: "hunt:x", role: "hunt", model, systemPrompt: SYSTEM, prompt: "FLAKY-AGENT go", tools: [], done: options.done ?? (() => true) });
		return { outcome, calls };
	}

	test("the default budget waits about three minutes in total", () => {
		const waits = Array.from({ length: AGENT_RETRY.maxRetries }, (_, i) => Math.min(AGENT_RETRY.baseDelayMs * 2 ** i, AGENT_RETRY.maxAgentDelayMs));
		assert.deepEqual(waits, [5000, 10_000, 20_000, 40_000, 60_000, 60_000]);
	});

	test("a rate limit within the retry budget is retried and the agent finishes ok", async () => {
		const { outcome, calls } = await runOnce(failTimes(2, RATE_LIMITED, fauxAssistantMessage("done")));
		assert.equal(outcome.ok, true, outcome.error);
		assert.equal(outcome.transient, undefined);
		assert.equal(calls.length, 3);
	});

	test("a rate limit that outlasts the budget fails as transient", async () => {
		const { outcome, calls } = await runOnce(failTimes(99, RATE_LIMITED, fauxAssistantMessage("done")));
		assert.equal(outcome.ok, false);
		assert.equal(outcome.transient, true);
		assert.match(outcome.error!, /Rate limit reached/);
		assert.equal(calls.length, 1 + FAST_RETRY.maxRetries);
	});

	test("a failed model request is not followed by a nudge", async () => {
		const repo = makeRepo();
		const { runtime, model, calls } = await scriptedRuntime({ "FLAKY-AGENT": [providerError("401 invalid api key"), fauxAssistantMessage("nudged")] });
		const runner = createSdkAgentRunner({ root: repo, modelRuntime: runtime, timeoutMs: 10_000, ledger: new UsageLedger(), retry: FAST_RETRY });
		const spec = { label: "profile", role: "profile" as const, model, systemPrompt: SYSTEM, prompt: "FLAKY-AGENT go", tools: [], done: () => false, nudge: "Submit now." };
		const outcome = await runner.run(spec);
		assert.equal(outcome.error, "401 invalid api key");
		assert.equal(outcome.rejected, true);
		assert.deepEqual(calls, ["FLAKY-AGENT#0"]);
	});

	test("non-retryable provider errors are rejected, not transient", async () => {
		for (const message of ["insufficient_quota: You exceeded your current quota", "400 invalid request: unknown parameter", "prompt-capture: no capture for this 3719-char system prompt"]) {
			const { outcome, calls } = await runOnce(providerError(message));
			assert.equal(outcome.ok, false);
			assert.equal(outcome.transient, undefined, message);
			assert.equal(outcome.rejected, true, message);
			assert.equal(calls.length, 1, message);
		}
	});

	test("rate limits, context overflow, timeouts, and missing submissions are not rejected", async () => {
		const limited = await runOnce(failTimes(99, RATE_LIMITED, fauxAssistantMessage("done")));
		assert.equal(limited.outcome.rejected, undefined);
		// pi handles context overflow itself and drops the error from the conversation.
		const overflow = await runOnce(providerError("prompt is too long: 250000 tokens > 200000 maximum"), { done: () => false });
		assert.equal(overflow.outcome.ok, false);
		assert.equal(overflow.outcome.rejected, undefined);
		assert.equal(overflow.outcome.transient, undefined);
		const timedOut = await runOnce(hang, { timeoutMs: 200 });
		assert.equal(timedOut.outcome.timedOut, true);
		assert.equal(timedOut.outcome.transient, undefined);
		assert.equal(timedOut.outcome.rejected, undefined);
		const unsubmitted = await runOnce(fauxAssistantMessage("nothing to report"), { done: () => false });
		assert.match(unsubmitted.outcome.error!, /without submitting/);
		assert.equal(unsubmitted.outcome.transient, undefined);
		assert.equal(unsubmitted.outcome.rejected, undefined);
	});
});

describe("bounded runner", () => {
	test("a timed-out agent does not block others and usage is aggregated", async () => {
		const repo = makeRepo();
		write(repo, "README.md", "x\n");
		const { runtime, model } = await scriptedRuntime({
			"AGENT-SLOW": [hang],
			"AGENT-A": [fauxAssistantMessage("a")],
			"AGENT-B": [fauxAssistantMessage("b")],
			"AGENT-C": [fauxAssistantMessage("c")],
		});
		const ledger = new UsageLedger();
		const runner = createSdkAgentRunner({ root: repo, modelRuntime: runtime, timeoutMs: 500, ledger });
		const labels = ["AGENT-SLOW", "AGENT-A", "AGENT-B", "AGENT-C"];
		const started = Date.now();
		const results = await mapBounded(labels, 2, (label) =>
			runner.run({ label, role: "hunt", model, systemPrompt: SYSTEM, prompt: `${label} go`, tools: [], done: () => true }),
		);
		const elapsed = Date.now() - started;
		const outcomes = results.map((r) => (r.status === "fulfilled" ? r.value : assert.fail("runner rejected")));
		assert.equal(outcomes[0]!.ok, false);
		assert.equal(outcomes[0]!.timedOut, true);
		assert.match(outcomes[0]!.error!, /timed out/);
		assert.deepEqual(outcomes.slice(1).map((o) => o.ok), [true, true, true]);
		assert.ok(elapsed < 5000, `took ${elapsed}ms`);

		const sum = outcomes.reduce((acc, o) => acc + o.usage.totalTokens, 0);
		assert.ok(sum > 0);
		assert.equal(ledger.total().totalTokens, sum);
		assert.equal(ledger.entries().length, 1);
		assert.equal(ledger.entries()[0]!.model, "auditor");
	});

	test("mapBounded respects the concurrency limit and isolates failures", async () => {
		let active = 0;
		let peak = 0;
		const results = await mapBounded([1, 2, 3, 4, 5, 6], 3, async (n) => {
			active++;
			peak = Math.max(peak, active);
			await new Promise((r) => setTimeout(r, 10));
			active--;
			if (n === 2) throw new Error("boom");
			return n * 10;
		});
		assert.equal(peak, 3);
		assert.equal(results[1]!.status, "rejected");
		assert.deepEqual(results.filter((r) => r.status === "fulfilled").map((r) => (r as PromiseFulfilledResult<number>).value), [10, 30, 40, 50, 60]);
	});
});
