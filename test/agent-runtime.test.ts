import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { createAuditSession, createSdkAgentRunner, UsageLedger } from "../extensions/security-review/agent-runtime.ts";
import { mapBounded } from "../extensions/security-review/pool.ts";
import { checkCommand, createShellTool, ShellRejection } from "../extensions/security-review/shell.ts";
import { createAffirmTool, createHypothesisTool, type HypothesisCollector } from "../extensions/security-review/submit-tools.ts";
import type { AffirmArgument } from "../extensions/security-review/schema.ts";
import { scriptedRuntime, fauxAssistantMessage, fauxToolCall, hang } from "./faux.ts";
import { affirm, hypothesisInput } from "./fixtures.ts";
import { makeRepo, write } from "./git-fixtures.ts";

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
});

describe("read-only shell", () => {
	const root = "/project";

	test("allows inspection commands", () => {
		assert.deepEqual(checkCommand("rg -n 'select .* from' src", root), ["rg", "-n", "select .* from", "src"]);
		assert.deepEqual(checkCommand("cat src/a.ts", root), ["cat", "src/a.ts"]);
		assert.deepEqual(checkCommand("git log -n 3 -- src/a.ts", root), [
			"git", "-c", "core.fsmonitor=false", "-c", "core.pager=cat", "--no-pager", "log", "--no-ext-diff", "--no-textconv", "-n", "3", "--", "src/a.ts",
		]);
		assert.ok(checkCommand("git blame -L 10,20 src/a.ts", root).includes("blame"));
		assert.ok(checkCommand("git diff HEAD~3..HEAD", root).includes("diff"));
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
