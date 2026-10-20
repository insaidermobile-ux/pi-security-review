/**
 * Dry-run individual audit roles against the vulnerable-app fixture with a real model.
 *
 *   node scripts/dry-run.ts [profile|hunt|triage|verify|all] [--model provider/id] [--thinking low]
 *
 * Uses pi's configured credentials and default model unless --model is given. Exits non-zero when a
 * role's output is invalid or misses the expected result.
 */
import { getAgentDir, ModelRuntime, SettingsManager } from "@earendil-works/pi-coding-agent";
import { type AgentOutcome, createSdkAgentRunner, UsageLedger } from "../extensions/security-review/agent-runtime.ts";
import { fingerprint } from "../extensions/security-review/fingerprint.ts";
import { profileStage, type PipelineDeps } from "../extensions/security-review/pipeline.ts";
import { huntPrompt, systemPrompt, triagePrompt, VULN_CLASSES } from "../extensions/security-review/prompts.ts";
import { candidateLabel } from "../extensions/security-review/partition.ts";
import { type AffirmArgument, AffirmArgument as AffirmSchema, type ChallengeArgument, ChallengeArgument as ChallengeSchema, type Hypothesis, type HypothesisInput, type Profile, ProfileInput, validate } from "../extensions/security-review/schema.ts";
import { resolveScope } from "../extensions/security-review/scope.ts";
import { DEFAULT_SETTINGS, ROLES } from "../extensions/security-review/settings.ts";
import { affirmerPrompt, challengerPrompt } from "../extensions/security-review/prompts.ts";
import { createAffirmTool, createChallengeTool, createHypothesisTool, createTriageTool, type HypothesisCollector, type TriageCollector } from "../extensions/security-review/submit-tools.ts";
import { makeFixtureRepo } from "../test/git-fixtures.ts";

const args = process.argv.slice(2);
const which = args.find((a) => !a.startsWith("--")) ?? "all";
const flag = (name: string) => {
	const i = args.indexOf(`--${name}`);
	return i >= 0 ? args[i + 1] : undefined;
};

const runtime = await ModelRuntime.create();
const settings = SettingsManager.create(process.cwd(), getAgentDir()).getGlobalSettings();
const modelSpec = flag("model") ?? `${settings.defaultProvider}/${settings.defaultModel}`;
const [provider, ...rest] = modelSpec.split("/");
const found = runtime.getModel(provider!, rest.join("/"));
if (!found) throw new Error(`model ${modelSpec} not found`);
const model = found;
const thinkingLevel = (flag("thinking") ?? "low") as "low";
console.log(`model: ${model.provider}/${model.id} thinking: ${thinkingLevel}`);

const root = makeFixtureRepo();
const scope = await resolveScope(root, "diff");
console.log(`fixture: ${root}\nscope: ${scope.files.join(", ")} against ${scope.baseRef}`);

const ledger = new UsageLedger();
const runner = createSdkAgentRunner({ root, modelRuntime: runtime, thinkingLevel, timeoutMs: 600_000, ledger });
const models = Object.fromEntries(ROLES.map((role) => [role, model])) as PipelineDeps["models"];
const deps: PipelineDeps = { runner, models, settings: DEFAULT_SETTINGS };
const failures: string[] = [];
const check = (ok: boolean, message: string) => {
	console.log(`${ok ? "PASS" : "FAIL"} ${message}`);
	if (!ok) failures.push(message);
};

let profile: Profile | undefined;
if (which === "profile" || which === "all" || which === "hunt") {
	const agents: AgentOutcome[] = [];
	const result = await profileStage(scope, deps, agents);
	profile = result.profile;
	console.log(JSON.stringify(profile, null, 2));
	if (which !== "hunt") {
		check(profile !== undefined && validate(ProfileInput, profile).length === 0, "profile: schema-valid profile submitted");
		check(profile?.domains.includes("web-auth") === true, `profile: domains include web-auth (${profile?.domains.join(", ") || "none"})`);
		check(JSON.stringify(profile ?? {}).includes("server.js"), "profile: entry points reference src/server.js");
	}
}

if (which === "hunt" || which === "all") {
	const injection = VULN_CLASSES.find((c) => c.id === "injection")!;
	const collector: HypothesisCollector = { hypotheses: [] };
	const outcome = await runner.run({
		label: "hunt:injection",
		role: "hunt",
		model,
		systemPrompt: systemPrompt("hunt"),
		prompt: huntPrompt(profile, scope, { label: injection.id, kind: "class", title: injection.title, focus: injection.focus, files: scope.files }),
		tools: [createHypothesisTool(root, collector)],
		done: () => true,
	});
	console.log(JSON.stringify(collector.hypotheses, null, 2));
	check(outcome.ok, `hunt: agent finished (${outcome.error ?? "ok"})`);
	check(
		collector.hypotheses.some((h) => h.anchors.some((a) => a.file === "src/users.js") && /sql/i.test(h.vuln_type)),
		"hunt: SQL injection hypothesis anchored in src/users.js",
	);
}

if (which === "triage" || which === "all") {
	const candidates: HypothesisInput[] = [
		{
			anchors: [{ file: "src/users.js", line: 6, function: "searchUsers" }],
			claim: "req.query.name is concatenated into the SQL LIKE clause passed to db.query",
			vuln_type: "sql-injection",
			suspected_source: "query parameter name on GET /users/search",
			suspected_sink: "db.query with concatenated SQL",
			severity_estimate: "high",
		},
		{
			anchors: [{ file: "src/users.js", line: 6, function: "searchUsers" }],
			claim: "A UNION payload in name makes the search return other columns of the users table, such as session digests, in the JSON response",
			vuln_type: "secret-disclosure",
			suspected_source: "query parameter name on GET /users/search",
			suspected_sink: "res.json(rows) returning injected columns",
			severity_estimate: "critical",
		},
		{
			anchors: [{ file: "src/server.js", line: 11 }],
			claim: "GET /users/search is registered without requireUser, unlike the other routes",
			vuln_type: "missing-authz",
			suspected_source: "anonymous HTTP request",
			suspected_sink: "users.searchUsers returning user records",
			severity_estimate: "medium",
		},
		{
			anchors: [{ file: "src/users.js", line: 4, function: "searchUsers" }],
			claim: "No rate limit on user search allows bulk enumeration of the directory",
			vuln_type: "missing-rate-limit",
			suspected_source: "repeated HTTP requests",
			suspected_sink: "db.query per request",
			severity_estimate: "low",
		},
	];
	const labels = candidates.map((_, i) => candidateLabel(i));
	const collector: TriageCollector = {};
	const outcome = await runner.run({
		label: "triage",
		role: "triage",
		model,
		systemPrompt: systemPrompt("triage"),
		prompt: triagePrompt(profile, candidates, labels),
		tools: [createTriageTool(labels, collector)],
		done: () => collector.groups !== undefined,
		nudge: "Call submit_triage now.",
	});
	console.log(JSON.stringify(collector.groups, null, 2));
	check(outcome.ok && collector.groups !== undefined, `triage: valid grouping submitted (${outcome.error ?? "ok"})`);
	const groups = collector.groups ?? [];
	check(groups.some((g) => g.primary === "C-1" && g.members.includes("C-2")), "triage: secret disclosure grouped under the SQL injection");
	check(!groups.some((g) => g.members.includes("C-1") && (g.members.includes("C-3") || g.members.includes("C-4"))), "triage: missing authz and rate limit stay separate from the injection");
}

const sqli: Hypothesis = {
	id: "H-001",
	source_partition: "injection",
	fingerprint: "",
	anchors: [{ file: "src/users.js", line: 6, function: "searchUsers" }],
	claim: "req.query.name is concatenated into a SQL LIKE clause passed to db.query",
	vuln_type: "sql-injection",
	cwe: "CWE-89",
	suspected_source: "HTTP query parameter name on GET /users/search",
	suspected_sink: "db.query with concatenated SQL",
	severity_estimate: "high",
};
sqli.fingerprint = fingerprint(sqli);

const traversal: Hypothesis = {
	id: "H-002",
	source_partition: "files-deserialization",
	fingerprint: "",
	anchors: [{ file: "src/files.js", line: 9, function: "download" }],
	claim: "req.query.name is joined to the upload directory and streamed back, allowing ../ traversal",
	vuln_type: "path-traversal",
	cwe: "CWE-22",
	suspected_source: "HTTP query parameter name on GET /files",
	suspected_sink: "fs.createReadStream of a user-influenced path",
	severity_estimate: "high",
};
traversal.fingerprint = fingerprint(traversal);

const traversalAffirm: AffirmArgument = {
	hypothesis_id: "H-002",
	component: "File download endpoint (src/files.js)",
	consequence: "reading arbitrary files on the server",
	attack_path: [
		{ location: "src/server.js:9", description: "GET /files is routed to files.download" },
		{ location: "src/files.js:8", description: "name is taken from req.query.name" },
		{ location: "src/files.js:9", description: "path.resolve joins UPLOAD_ROOT and the attacker-controlled name" },
		{ location: "src/files.js:14", description: "the resolved path is streamed to the response" },
	],
	missing_defenses: [{ defense: "rejecting ../ sequences in name", location: "not found" }],
	preconditions: ["an authenticated session"],
	severity: "high",
	cwe: "CWE-22",
	description: {
		background: "The API serves uploaded files.",
		detail: "The file name from the query string is resolved against the upload directory.",
		attack_scenario: "GET /files?name=../../etc/passwd",
	},
	remediation: { summary: "Validate that the resolved path stays inside the upload directory." },
};

async function runAffirmer(hypothesis: Hypothesis): Promise<AffirmArgument | undefined> {
	const collector: { argument?: AffirmArgument } = {};
	const outcome = await runner.run({
		label: `affirmer:${hypothesis.id}`,
		role: "affirmer",
		model,
		systemPrompt: systemPrompt("affirmer"),
		prompt: affirmerPrompt(profile, hypothesis, scope),
		tools: [createAffirmTool(hypothesis.id, collector)],
		done: () => collector.argument !== undefined,
		nudge: `Call submit_argument now for hypothesis_id "${hypothesis.id}".`,
	});
	if (!outcome.ok) console.log(`affirmer error: ${outcome.error}`);
	return collector.argument;
}

async function runChallenger(hypothesis: Hypothesis, argument: AffirmArgument): Promise<ChallengeArgument | undefined> {
	const collector: { argument?: ChallengeArgument } = {};
	const outcome = await runner.run({
		label: `challenger:${hypothesis.id}`,
		role: "challenger",
		model,
		systemPrompt: systemPrompt("challenger"),
		prompt: challengerPrompt(profile, hypothesis, argument),
		tools: [createChallengeTool(hypothesis.id, collector)],
		done: () => collector.argument !== undefined,
		nudge: `Call submit_argument now for hypothesis_id "${hypothesis.id}".`,
	});
	if (!outcome.ok) console.log(`challenger error: ${outcome.error}`);
	return collector.argument;
}

if (which === "verify" || which === "all") {
	const affirm = await runAffirmer(sqli);
	console.log(JSON.stringify(affirm, null, 2));
	check(affirm !== undefined && validate(AffirmSchema, affirm).length === 0, "affirmer: schema-valid argument for the SQL injection");
	check((affirm?.attack_path.length ?? 0) > 0 && JSON.stringify(affirm?.attack_path).includes("users.js"), "affirmer: attack path cites src/users.js");

	if (affirm) {
		const confirmed = await runChallenger(sqli, affirm);
		console.log(JSON.stringify(confirmed, null, 2));
		check(confirmed !== undefined && validate(ChallengeSchema, confirmed).length === 0, "challenger: schema-valid verdict for the SQL injection");
		check(confirmed?.verdict === "confirmed", `challenger: SQL injection confirmed (got ${confirmed?.verdict})`);
	}

	const refuted = await runChallenger(traversal, traversalAffirm);
	console.log(JSON.stringify(refuted, null, 2));
	check(refuted !== undefined && validate(ChallengeSchema, refuted).length === 0, "challenger: schema-valid verdict for the guarded traversal");
	check(refuted?.verdict === "refuted", `challenger: guarded path traversal refuted (got ${refuted?.verdict})`);
	check(JSON.stringify(refuted?.defenses_found ?? []).includes("files.js"), "challenger: cites the defense location in src/files.js");
}

const total = ledger.total();
console.log(`usage: ${total.totalTokens} tokens, $${total.cost.total.toFixed(4)}`);
if (failures.length) {
	console.log(`\n${failures.length} check(s) failed`);
	process.exit(1);
}
