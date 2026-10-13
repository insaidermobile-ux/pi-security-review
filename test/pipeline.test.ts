import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { describe, test } from "node:test";
import type { Api, Model } from "@earendil-works/pi-ai";
import { type AgentOutcome, createSdkAgentRunner, UsageLedger } from "../extensions/security-review/agent-runtime.ts";
import { applyHypothesisCap, applyTriageGroups, candidateLabel, huntAssignments, mergeDuplicateHypotheses, subtreePartitions } from "../extensions/security-review/partition.ts";
import { fingerprint } from "../extensions/security-review/fingerprint.ts";
import { huntStage, type PipelineDeps, profileStage, type Progress, runPipeline, verifyHypothesis } from "../extensions/security-review/pipeline.ts";
import { VULN_CLASSES } from "../extensions/security-review/prompts.ts";
import type { AffirmArgument, Hypothesis, HypothesisInput } from "../extensions/security-review/schema.ts";
import { resolveScope } from "../extensions/security-review/scope.ts";
import { DEFAULT_SETTINGS, ROLES } from "../extensions/security-review/settings.ts";
import { loadStore, saveStore } from "../extensions/security-review/store.ts";
import { failTimes, fauxAssistantMessage, fauxToolCall, hang, inTurn, providerError, RATE_LIMITED, type ScriptStep, scriptedRuntime } from "./faux.ts";
import { affirm, challenge, hypothesisInput } from "./fixtures.ts";
import { makeFixtureRepo, makeRepo, sh } from "./git-fixtures.ts";

const PROFILE = {
	summary: "Express API with user search and file download.",
	stack: ["javascript", "express", "pg"],
	entry_points: [{ location: "src/server.js:10", description: "GET /files" }],
	trust_boundaries: ["anonymous vs authenticated user"],
	auth_model: "Bearer session tokens via requireUser",
	external_inputs: ["query parameters"],
};

const SQLI: HypothesisInput = hypothesisInput({
	anchors: [{ file: "src/users.js", line: 6, function: "searchUsers" }],
	suspected_sink: "db.query with concatenated SQL",
	severity_estimate: "high",
});
const TRAVERSAL: HypothesisInput = hypothesisInput({
	anchors: [{ file: "src/files.js", line: 9, function: "download" }],
	claim: "name is resolved against the upload root and streamed",
	vuln_type: "path-traversal",
	cwe: "CWE-22",
	suspected_sink: "fs.createReadStream",
	severity_estimate: "medium",
});

const submit = (tool: string, args: object) => fauxAssistantMessage(fauxToolCall(tool, args as Parameters<typeof fauxToolCall>[1]));
const say = (text: string) => fauxAssistantMessage(text);

/** One in-session retry with no wait, so a step must fail twice for the agent to fail. */
const FAST_RETRY = { maxRetries: 1, baseDelayMs: 1, maxAgentDelayMs: 1 };

async function setup(scripts: Record<string, ScriptStep[]>, options: { timeoutMs?: number; settings?: Partial<typeof DEFAULT_SETTINGS> } = {}) {
	const faux = await scriptedRuntime(scripts);
	const ledger = new UsageLedger();
	const progress: Progress[] = [];
	const makeDeps = (root: string): PipelineDeps => ({
		runner: createSdkAgentRunner({ root, modelRuntime: faux.runtime, timeoutMs: options.timeoutMs ?? 20_000, ledger, retry: FAST_RETRY }),
		models: Object.fromEntries(ROLES.map((role) => [role, faux.model])) as Record<(typeof ROLES)[number], Model<Api>>,
		settings: { ...DEFAULT_SETTINGS, ...options.settings },
		onProgress: (p) => progress.push(p),
	});
	return { ...faux, ledger, progress, makeDeps };
}

/** Scripts for a full fixture run: SQL injection confirmed, guarded traversal refuted, duplicate merged. */
function fixtureScripts(): Record<string, ScriptStep[]> {
	return {
		"Agent: profile": [submit("submit_profile", PROFILE)],
		"Agent: hunt:injection": [submit("submit_hypothesis", SQLI), say("one finding")],
		"Agent: hunt:access-control": [submit("submit_hypothesis", { ...SQLI, anchors: [{ file: "src/users.js", line: 7, function: "searchUsers" }], severity_estimate: "medium" }), say("done")],
		"Agent: hunt:files-deserialization": [submit("submit_hypothesis", TRAVERSAL), say("done")],
		"Agent: triage": [submit("submit_triage", { groups: [] })],
		"Agent: affirmer:H-001": [submit("submit_argument", affirm("H-001", { attack_path: [{ location: "src/users.js:6", description: "name concatenated into SQL" }] }))],
		"Agent: challenger:H-001": [submit("submit_argument", challenge("H-001", "confirmed"))],
		"Agent: affirmer:H-002": [submit("submit_argument", affirm("H-002", { component: "File download (src/files.js)", consequence: "reading arbitrary files" }))],
		"Agent: challenger:H-002": [
			submit("submit_argument", challenge("H-002", "refuted", { defenses_found: [{ defense: "resolve and prefix check", location: "src/files.js:9", effect: "blocks" }] })),
		],
		"Agent: report": [submit("submit_summary", { summary: "One SQL injection in user search." })],
	};
}

const PARTIAL_XSS: HypothesisInput = hypothesisInput({
	anchors: [{ file: "src/users.js", line: 7, function: "searchUsers" }],
	claim: "Submitted before the rate limit; the re-run does not repeat it",
	vuln_type: "xss",
	suspected_sink: "res.json",
	severity_estimate: "low",
});

/** The injection hunter submits a different hypothesis on its first attempt and the SQL injection on its re-run. */
function rateLimitedInjection(failures: number): ScriptStep[] {
	return [inTurn(submit("submit_hypothesis", PARTIAL_XSS), submit("submit_hypothesis", SQLI)), failTimes(failures, RATE_LIMITED, say("done"))];
}

describe("profile stage", () => {
	test("reuses the cached profile in default mode without a model call", async () => {
		const root = makeFixtureRepo();
		const env = await setup({ "Agent: profile": [submit("submit_profile", PROFILE)] });
		const scope = await resolveScope(root, "diff");
		const agents: AgentOutcome[] = [];
		const first = await profileStage(scope, env.makeDeps(root), agents);
		assert.equal(first.cached, false);
		assert.deepEqual(first.profile, PROFILE);
		const callsAfterFirst = env.calls.length;
		const second = await profileStage(scope, env.makeDeps(root), agents);
		assert.equal(second.cached, true);
		assert.deepEqual(second.profile, PROFILE);
		assert.equal(env.calls.length, callsAfterFirst, "no model call for the cached profile");
		assert.deepEqual(env.progress.at(-1), { stage: "profile", cached: true });
	});

	test("refreshes the profile in full mode", async () => {
		const root = makeFixtureRepo();
		const env = await setup({ "Agent: profile": [submit("submit_profile", PROFILE)] });
		const agents: AgentOutcome[] = [];
		await profileStage(await resolveScope(root, "diff"), env.makeDeps(root), agents);
		const calls = env.calls.length;
		const full = await profileStage(await resolveScope(root, "full"), env.makeDeps(root), agents);
		assert.equal(full.cached, false);
		assert.ok(env.calls.length > calls);
	});
});

describe("hunt partitioning", () => {
	test("default mode partitions by vulnerability class over the whole scope", async () => {
		const scope = await resolveScope(makeFixtureRepo(), "diff");
		const assignments = huntAssignments(scope);
		assert.deepEqual(assignments.map((a) => a.label), VULN_CLASSES.map((c) => c.id));
		for (const assignment of assignments) {
			assert.equal(assignment.kind, "class");
			assert.deepEqual(assignment.files, scope.files);
		}
	});

	test("full mode partitions by subtree with every file owned exactly once", () => {
		const files = [
			...Array.from({ length: 320 }, (_, i) => `src/api/v${i % 4}/file${i}.ts`),
			...Array.from({ length: 40 }, (_, i) => `src/ui/c${i}.tsx`),
			...Array.from({ length: 5 }, (_, i) => `scripts/s${i}.sh`),
			"README.md",
			"package.json",
		];
		const groups = subtreePartitions(files);
		assert.ok(groups.length > 1 && groups.length <= 12, `${groups.length} groups`);
		assert.deepEqual(groups.flatMap((g) => g.files).sort(), [...files].sort());
		assert.ok(groups.every((g) => g.files.length <= 150 || !g.label.includes("+")));
		assert.ok(groups.some((g) => g.label.startsWith("src/api/")), groups.map((g) => g.label).join(", "));
	});

	test("full mode on a small project uses one subtree agent", async () => {
		const scope = await resolveScope(makeFixtureRepo(), "full");
		const assignments = huntAssignments(scope);
		assert.equal(assignments.length, 1);
		assert.equal(assignments[0]!.kind, "subtree");
		assert.deepEqual(assignments[0]!.files, scope.files);
	});

	test("duplicates with the same type and overlapping anchors are merged", () => {
		const merged = mergeDuplicateHypotheses([
			{ ...SQLI, source_partition: "injection", severity_estimate: "medium" },
			{ ...SQLI, anchors: [{ file: "src/users.js", line: 40, function: "searchUsers" }], severity_estimate: "high", source_partition: "access-control" },
			{ ...SQLI, vuln_type: "xss", source_partition: "injection" },
			{ ...SQLI, anchors: [{ file: "src/users.js", line: 9 }], source_partition: "injection" },
			{ ...SQLI, anchors: [{ file: "src/other.js", line: 6 }], source_partition: "injection" },
		]);
		assert.equal(merged.length, 3);
		assert.equal(merged[0]!.severity_estimate, "high");
		assert.equal(merged[0]!.source_partition, "injection, access-control");
		assert.equal(merged[0]!.anchors.length, 3);
	});

	test("the cap keeps the most severe hypotheses", () => {
		const { verify, overflow } = applyHypothesisCap(
			[
				{ id: "a", severity_estimate: "low" },
				{ id: "b", severity_estimate: "critical" },
				{ id: "c", severity_estimate: "medium" },
				{ id: "d", severity_estimate: "critical" },
			],
			2,
		);
		assert.deepEqual(verify.map((h) => h.id), ["b", "d"]);
		assert.deepEqual(overflow.map((h) => h.id), ["c", "a"]);
	});

	test("hunt stage merges duplicates, assigns deterministic ids, and reports overflow", async () => {
		const root = makeFixtureRepo();
		const env = await setup(fixtureScripts(), { settings: { maxHypotheses: 1 } });
		const agents: AgentOutcome[] = [];
		const hunt = await huntStage(await resolveScope(root, "diff"), PROFILE, env.makeDeps(root), agents);
		assert.deepEqual(hunt.all.map((h) => [h.id, h.vuln_type]), [
			["H-001", "sql-injection"],
			["H-002", "path-traversal"],
		]);
		assert.deepEqual(hunt.verify.map((h) => h.id), ["H-001"]);
		assert.deepEqual(hunt.overflow.map((h) => h.id), ["H-002"]);
		assert.equal(agents.length, 7);
		assert.equal(agents.at(-1)!.label, "triage");
		assert.deepEqual(env.progress.at(-1), { stage: "triage" });
	});
});

const DISCLOSURE: HypothesisInput = hypothesisInput({
	anchors: [{ file: "src/users.js", line: 6, function: "searchUsers" }],
	claim: "Session digests can be read through the injection",
	vuln_type: "secret-disclosure",
	suspected_sink: "res.json returning session_digest",
	severity_estimate: "critical",
});
const RATE_LIMIT: HypothesisInput = hypothesisInput({
	anchors: [{ file: "src/users.js", line: 4, function: "searchUsers" }],
	claim: "No rate limit on user search",
	vuln_type: "missing-rate-limit",
	suspected_sink: "db.query per request",
	severity_estimate: "low",
});

describe("hunt re-runs", () => {
	test("a re-run that fails again keeps both attempts' hypotheses and records the failure", async () => {
		const root = makeFixtureRepo();
		const env = await setup({ "Agent: hunt:injection": rateLimitedInjection(99), "Agent: triage": [submit("submit_triage", { groups: [] })] });
		const agents: AgentOutcome[] = [];
		const hunt = await huntStage(await resolveScope(root, "diff"), PROFILE, env.makeDeps(root), agents);
		assert.deepEqual(hunt.all.map((h) => h.vuln_type).sort(), ["sql-injection", "xss"]);
		assert.equal(hunt.failures.length, 1);
		assert.match(hunt.failures[0]!, /^hunt:injection \(re-run\): 429/);
		assert.deepEqual(hunt.errors, []);
		assert.deepEqual(agents.filter((a) => a.label.startsWith("hunt:injection")).map((a) => [a.label, a.transient]), [
			["hunt:injection", true],
			["hunt:injection (re-run)", true],
		]);
	});

	test("timeouts and non-transient errors are not re-run", async () => {
		const root = makeFixtureRepo();
		const env = await setup({ "Agent: hunt:network-ssrf": [hang], "Agent: hunt:injection": [providerError("insufficient_quota: quota exceeded")] }, { timeoutMs: 1500 });
		const agents: AgentOutcome[] = [];
		const hunt = await huntStage(await resolveScope(root, "diff"), PROFILE, env.makeDeps(root), agents);
		assert.equal(agents.some((a) => a.label.includes("re-run")), false);
		assert.equal(agents.length, VULN_CLASSES.length);
		assert.deepEqual(hunt.failures.map((f) => f.split(":").slice(0, 2).join(":")).sort(), ["hunt:injection", "hunt:network-ssrf"]);
		assert.deepEqual(env.progress.at(-1), { stage: "hunt", done: 6, total: 6 });
	});
});

describe("triage groups", () => {
	const candidates = [
		{ ...RATE_LIMIT, source_partition: "logic-concurrency" },
		{ ...SQLI, source_partition: "injection" },
		{ ...TRAVERSAL, source_partition: "files-deserialization" },
		{ ...DISCLOSURE, source_partition: "secrets-crypto" },
	];

	test("labels candidates C-1..C-n", () => {
		assert.deepEqual(candidates.map((_, i) => candidateLabel(i)), ["C-1", "C-2", "C-3", "C-4"]);
	});

	test("folds members into the primary as consequences at the first member's position", () => {
		const result = applyTriageGroups(candidates, [{ primary: "C-2", members: ["C-4", "C-2"] }]);
		assert.deepEqual(result.map((h) => h.vuln_type), ["missing-rate-limit", "sql-injection", "path-traversal"]);
		const merged = result[1]!;
		assert.equal(merged.claim, SQLI.claim);
		assert.equal(merged.severity_estimate, "critical");
		assert.equal(merged.source_partition, "injection, secrets-crypto");
		assert.deepEqual(merged.consequences, [{ vuln_type: "secret-disclosure", description: DISCLOSURE.claim, anchors: DISCLOSURE.anchors }]);
		assert.equal(fingerprint(merged), fingerprint(SQLI));
	});

	test("a group placed later than its primary keeps a deterministic order", () => {
		const result = applyTriageGroups(candidates, [{ primary: "C-4", members: ["C-3", "C-4"] }]);
		assert.deepEqual(result.map((h) => h.vuln_type), ["missing-rate-limit", "sql-injection", "secret-disclosure"]);
		assert.equal(result[2]!.consequences![0]!.vuln_type, "path-traversal");
	});

	test("no groups leaves the candidates unchanged", () => {
		assert.deepEqual(applyTriageGroups(candidates, []), candidates);
	});
});

/** SQL injection, the disclosure it enables, and an unrelated rate-limit issue; triage groups the first two. */
function groupingScripts(triage: ScriptStep[] = [submit("submit_triage", { groups: [{ primary: "C-1", members: ["C-1", "C-2"], reason: "same query" }] })]) {
	const scripts: Record<string, ScriptStep[]> = {
		"Agent: profile": [submit("submit_profile", PROFILE)],
		"Agent: hunt:injection": [submit("submit_hypothesis", SQLI), say("done")],
		"Agent: hunt:secrets-crypto": [submit("submit_hypothesis", DISCLOSURE), say("done")],
		"Agent: hunt:logic-concurrency": [submit("submit_hypothesis", RATE_LIMIT), say("done")],
		"Agent: triage": triage,
		"Agent: report": [submit("submit_summary", { summary: "Summary." })],
	};
	for (const id of ["H-001", "H-002", "H-003"]) {
		scripts[`Agent: affirmer:${id}`] = [submit("submit_argument", affirm(id))];
		scripts[`Agent: challenger:${id}`] = [submit("submit_argument", challenge(id, "confirmed"))];
	}
	return scripts;
}

describe("triage stage", () => {
	test("grouping folds a consequence into its root cause and saves verification agents", async () => {
		const root = makeFixtureRepo();
		const env = await setup(groupingScripts());
		const result = await runPipeline(await resolveScope(root, "diff"), env.makeDeps(root));
		assert.deepEqual(result.hypotheses.map((h) => [h.id, h.vuln_type, h.severity_estimate]), [
			["H-001", "sql-injection", "critical"],
			["H-002", "missing-rate-limit", "low"],
		]);
		assert.deepEqual(result.hypotheses[0]!.consequences!.map((c) => c.vuln_type), ["secret-disclosure"]);
		const labels = result.agents.map((a) => a.label);
		assert.ok(labels.includes("triage"));
		assert.ok(!labels.some((l) => l.endsWith(":H-003")), labels.join(", "));
		assert.equal(result.findings.length, 2);
		const stored = loadStore(root).findings.find((f) => f.vuln_type === "sql-injection")!;
		assert.deepEqual(stored.consequences, [{ vuln_type: "secret-disclosure", description: DISCLOSURE.claim, anchors: DISCLOSURE.anchors }]);
		assert.match(readFileSync(result.reportPath, "utf8"), /\*\*Consequences\*\* \(removed by the same fix\)\n\n- secret-disclosure at `src\/users\.js:6`/);
		assert.match(env.prompts.get("Agent: affirmer:H-001")!, /## Consequences[\s\S]*secret-disclosure/);
		assert.match(env.prompts.get("Agent: triage")!, /"label": "C-3"[\s\S]*missing-rate-limit/);
	});

	test("a refuted root cause is recorded with its consequences and creates no finding for them", async () => {
		const root = makeFixtureRepo();
		const scripts = groupingScripts();
		scripts["Agent: challenger:H-001"] = [submit("submit_argument", challenge("H-001", "refuted"))];
		const env = await setup(scripts);
		const result = await runPipeline(await resolveScope(root, "diff"), env.makeDeps(root));
		assert.deepEqual(result.findings.map((f) => f.vuln_type), ["missing-rate-limit"]);
		assert.equal(result.refuted[0]!.hypothesis.consequences![0]!.vuln_type, "secret-disclosure");
		assert.equal(loadStore(root).runs[0]!.refuted[0]!.hypothesis.consequences!.length, 1);
	});

	test("a group counts once against the hypothesis cap", async () => {
		const root = makeFixtureRepo();
		const env = await setup(groupingScripts(), { settings: { maxHypotheses: 2 } });
		const result = await runPipeline(await resolveScope(root, "diff"), env.makeDeps(root));
		assert.equal(result.unverified.length, 0);
		assert.equal(result.run.complete, true, result.run.incomplete_reasons.join("; "));
	});

	test("a single candidate runs no triage agent", async () => {
		const root = makeFixtureRepo();
		const scripts = groupingScripts();
		delete scripts["Agent: hunt:secrets-crypto"];
		delete scripts["Agent: hunt:logic-concurrency"];
		const env = await setup(scripts);
		const result = await runPipeline(await resolveScope(root, "diff"), env.makeDeps(root));
		assert.equal(result.hypotheses.length, 1);
		assert.ok(!result.agents.some((a) => a.label === "triage"));
		assert.ok(!env.progress.some((p) => p.stage === "triage"));
	});

	test("a hung triage agent leaves hypotheses ungrouped and the run complete, with an error", async () => {
		const root = makeFixtureRepo();
		const env = await setup(groupingScripts([hang]), { timeoutMs: 3000 });
		const result = await runPipeline(await resolveScope(root, "diff"), env.makeDeps(root));
		assert.equal(result.hypotheses.length, 3);
		assert.equal(result.run.complete, true, result.run.incomplete_reasons.join("; "));
		assert.ok(result.run.errors.some((e) => e.startsWith("triage unavailable") && e.includes("timed out")), result.run.errors.join("; "));
		assert.match(readFileSync(result.reportPath, "utf8"), /## Errors[\s\S]*triage unavailable/);
	});
});

describe("verify stage", () => {
	async function verifyWith(verdict: "confirmed" | "downgraded" | "refuted") {
		const root = makeFixtureRepo();
		const env = await setup({
			"Agent: affirmer:H-001": [submit("submit_argument", affirm("H-001"))],
			"Agent: challenger:H-001": [submit("submit_argument", challenge("H-001", verdict))],
		});
		const hypothesis: Hypothesis = { ...SQLI, id: "H-001", source_partition: "injection", fingerprint: "fp1" };
		const scope = await resolveScope(root, "diff");
		const result = await verifyHypothesis(scope, PROFILE, hypothesis, undefined, env.makeDeps(root), []);
		return { result, env, root };
	}

	test("the challenger receives the affirmer's complete argument after the affirmer finishes", async () => {
		const { env } = await verifyWith("confirmed");
		const order = env.calls.filter((c) => c.endsWith("#0"));
		assert.deepEqual(order, ["Agent: affirmer:H-001#0", "Agent: challenger:H-001#0"]);
		const challengerPrompt = env.prompts.get("Agent: challenger:H-001")!;
		const argument: AffirmArgument = affirm("H-001");
		assert.ok(challengerPrompt.includes("## Affirmer's argument"));
		assert.ok(challengerPrompt.includes(JSON.stringify(argument, null, 2)));
	});

	test("confirmed maps to a vulnerability finding", async () => {
		const { result, root } = await verifyWith("confirmed");
		assert.equal(result.kind, "finding");
		if (result.kind !== "finding") return;
		assert.equal(result.finding.finding_class, "vulnerability");
		assert.equal(result.finding.verification.verdict, "confirmed");
		assert.equal(result.finding.title, "User search endpoint (src/users.ts): sql injection leading to reading any user's records");
		assert.equal(result.finding.introduced_in, sh(root, "rev-parse", "HEAD").trim());
	});

	test("downgraded maps to a risk finding", async () => {
		const { result } = await verifyWith("downgraded");
		assert.equal(result.kind, "finding");
		if (result.kind === "finding") assert.equal(result.finding.finding_class, "risk");
	});

	test("refuted is recorded with both arguments", async () => {
		const { result } = await verifyWith("refuted");
		assert.equal(result.kind, "refuted");
		if (result.kind === "refuted") assert.equal(result.refuted.challenger.verdict, "refuted");
	});

	test("a prior false-positive verdict is passed to the challenger", async () => {
		const root = makeFixtureRepo();
		const env = await setup({
			"Agent: affirmer:H-001": [submit("submit_argument", affirm("H-001"))],
			"Agent: challenger:H-001": [submit("submit_argument", challenge("H-001", "refuted"))],
		});
		const hypothesis: Hypothesis = { ...SQLI, id: "H-001", source_partition: "injection", fingerprint: "fp1" };
		const prior = {
			id: "SR-007",
			title: "Old title",
			anchors: [{ file: "src/users.js", line: 5 }],
			verification: { challenger: challenge("H-009", "confirmed", { reasoning: "UNIQUE-PRIOR-REASONING" }) },
		} as never;
		await verifyHypothesis(await resolveScope(root, "diff"), PROFILE, hypothesis, prior, env.makeDeps(root), []);
		const prompt = env.prompts.get("Agent: challenger:H-001")!;
		assert.match(prompt, /Previous verdict: false positive/);
		assert.match(prompt, /SR-007/);
		assert.match(prompt, /src\/users\.js:5/);
		assert.match(prompt, /If it concerns a different code path, disregard it\./);
		assert.match(prompt, /UNIQUE-PRIOR-REASONING/);
	});
});

describe("end-to-end with scripted model responses", () => {
	test("produces store, report, summary, and aggregated usage", async () => {
		const root = makeFixtureRepo();
		const env = await setup(fixtureScripts());
		const result = await runPipeline(await resolveScope(root, "diff"), env.makeDeps(root));

		assert.equal(result.run.complete, true, result.run.incomplete_reasons.join("; "));
		assert.equal(result.hypotheses.length, 2);
		assert.deepEqual(result.findings.map((f) => [f.id, f.finding_class, f.severity, f.status]), [["SR-001", "vulnerability", "high", "open"]]);
		assert.equal(result.refuted.length, 1);
		assert.equal(result.refuted[0]!.hypothesis.vuln_type, "path-traversal");
		assert.deepEqual(result.counts, { critical: 0, high: 1, medium: 0, low: 0 });
		assert.equal(result.summary, "One SQL injection in user search.");
		assert.match(result.gitignoreHint!, /not ignored/);

		const store = loadStore(root);
		assert.equal(store.findings.length, 1);
		assert.equal(store.runs.length, 1);
		assert.equal(store.runs[0]!.refuted.length, 1);
		assert.equal(store.gitignore_hint_shown, true);
		const report = readFileSync(result.reportPath, "utf8");
		assert.match(report, /SR-001: User search endpoint/);
		assert.match(report, /## Refuted hypotheses[\s\S]*H-002/);
		assert.match(report, /One SQL injection in user search\./);
		assert.ok(existsSync(result.runLogPath));
		assert.equal(sh(root, "status", "--porcelain").includes(".security-review"), true, "store is untracked, never staged");
		assert.equal(sh(root, "diff", "--cached", "--name-only").trim(), "");

		const total = env.ledger.total().totalTokens;
		assert.ok(total > 0);
		assert.equal(total, result.agents.reduce((sum, a) => sum + a.usage.totalTokens, 0));
		assert.deepEqual(env.progress.map((p) => p.stage).filter((s, i, all) => s !== all[i - 1]), ["profile", "hunt", "triage", "verify", "report"]);
	});

	test("a re-run keeps a false-positive status and passes the prior verdict to the challenger", async () => {
		const root = makeFixtureRepo();
		const first = await setup(fixtureScripts());
		await runPipeline(await resolveScope(root, "diff"), first.makeDeps(root));
		const store = loadStore(root);
		store.findings[0]!.status = "false-positive";
		saveStore(root, store);

		const second = await setup(fixtureScripts());
		const result = await runPipeline(await resolveScope(root, "diff"), second.makeDeps(root));
		assert.equal(loadStore(root).findings[0]!.status, "false-positive");
		assert.equal(result.findings[0]!.id, "SR-001");
		assert.match(second.prompts.get("Agent: challenger:H-001")!, /Previous verdict: false positive/);
		assert.equal(result.gitignoreHint, undefined, "hint shown once per project");
	});

	test("a re-run that describes a dismissed issue differently still passes the prior verdict", async () => {
		const root = makeFixtureRepo();
		const first = await setup(fixtureScripts());
		await runPipeline(await resolveScope(root, "diff"), first.makeDeps(root));
		const store = loadStore(root);
		store.findings[0]!.status = "false-positive";
		saveStore(root, store);

		const scripts = fixtureScripts();
		const reworded = { ...SQLI, anchors: [{ file: "src/users.js", line: 7 }], suspected_sink: "pool.query receiving the LIKE pattern" };
		scripts["Agent: hunt:injection"] = [submit("submit_hypothesis", reworded), say("one finding")];
		scripts["Agent: hunt:access-control"] = [say("nothing")];
		const second = await setup(scripts);
		const result = await runPipeline(await resolveScope(root, "diff"), second.makeDeps(root));
		assert.notEqual(result.hypotheses[0]!.fingerprint, store.findings[0]!.fingerprint);
		assert.match(second.prompts.get("Agent: challenger:H-001")!, /Previous verdict: false positive[\s\S]*SR-001/);
		assert.deepEqual(loadStore(root).findings.map((f) => [f.id, f.status]), [["SR-001", "false-positive"]]);
	});

	test("a failing hunt agent marks the run incomplete while other results proceed", async () => {
		const root = makeFixtureRepo();
		const scripts = fixtureScripts();
		scripts["Agent: hunt:network-ssrf"] = [hang];
		const env = await setup(scripts, { timeoutMs: 3000 });
		const result = await runPipeline(await resolveScope(root, "diff"), env.makeDeps(root));
		assert.equal(result.run.complete, false);
		assert.ok(result.run.incomplete_reasons.some((r) => r.includes("hunt:network-ssrf") && r.includes("timed out")), result.run.incomplete_reasons.join("; "));
		assert.equal(result.findings.length, 1);
		assert.equal(result.refuted.length, 1);
		assert.match(readFileSync(result.reportPath, "utf8"), /Incomplete run/);
	});

	test("a rate-limited hunt agent is re-run after the others and the run stays complete", async () => {
		const root = makeFixtureRepo();
		const scripts = fixtureScripts();
		// Fails the first attempt and its one in-session retry; the re-run succeeds.
		scripts["Agent: hunt:injection"] = rateLimitedInjection(1 + FAST_RETRY.maxRetries);
		const env = await setup(scripts);
		const result = await runPipeline(await resolveScope(root, "diff"), env.makeDeps(root));
		assert.equal(result.run.complete, true, result.run.incomplete_reasons.join("; "));
		assert.deepEqual(result.hypotheses.map((h) => h.vuln_type), ["sql-injection", "path-traversal"], "the re-run replaces the partial attempt");
		assert.equal(result.findings[0]!.vuln_type, "sql-injection");
		assert.match(result.run.errors.join("\n"), /hunt:injection was re-run after a transient error \(429: .*Rate limit reached/);
		assert.match(readFileSync(result.reportPath, "utf8"), /## Errors\n\n- hunt:injection was re-run/);

		const labels = (JSON.parse(readFileSync(result.runLogPath, "utf8")) as { agents: AgentOutcome[] }).agents.map((a) => `${a.label}:${a.ok}`);
		const rerun = labels.indexOf("hunt:injection (re-run):true");
		assert.ok(labels.includes("hunt:injection:false"), labels.join(", "));
		assert.ok(rerun > Math.max(...labels.map((l, i) => (l.startsWith("hunt:") && !l.includes("re-run") ? i : -1))), "re-run starts after the batch");
		assert.deepEqual(env.progress.filter((p) => p.stage === "hunt").at(-1), { stage: "hunt", done: 7, total: 7 });
	});

	test("an invalid store stops the run before any model call", async () => {
		const root = makeRepo();
		sh(root, "checkout", "-q", "-b", "feature");
		const { writeFileSync, mkdirSync } = await import("node:fs");
		writeFileSync(`${root}/a.js`, "1\n");
		mkdirSync(`${root}/.security-review`);
		writeFileSync(`${root}/.security-review/findings.json`, "{ broken");
		const env = await setup(fixtureScripts());
		await assert.rejects(runPipeline(await resolveScope(root, "diff"), env.makeDeps(root)), /not valid JSON/);
		assert.equal(env.calls.length, 0);
	});
});
