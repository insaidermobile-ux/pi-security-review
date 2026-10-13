import { randomBytes } from "node:crypto";
import type { Api, Model } from "@earendil-works/pi-ai";
import { type AgentOutcome, type AgentRunner, emptyUsage } from "./agent-runtime.ts";
import { fingerprint, formatTitle, normalizeVulnType } from "./fingerprint.ts";
import { applyHypothesisCap, applyTriageGroups, candidateLabel, huntAssignments, mergeDuplicateHypotheses, type TaggedHypothesis } from "./partition.ts";
import { mapBounded } from "./pool.ts";
import { affirmerPrompt, challengerPrompt, type HuntAssignment, huntPrompt, profilePrompt, reportPrompt, systemPrompt, triagePrompt } from "./prompts.ts";
import { countBySeverity, renderReport, type SeverityCounts } from "./report.ts";
import {
	type AffirmArgument,
	type ChallengeArgument,
	Finding as FindingSchema,
	type Finding,
	type Hypothesis,
	type Profile,
	type RefutedHypothesis,
	type RunRecord,
	validate,
} from "./schema.ts";
import { introducedIn, type Scope } from "./scope.ts";
import type { Role, SecurityReviewSettings } from "./settings.ts";
import {
	FINDINGS_FILE,
	gitignoreHint,
	loadCachedProfile,
	loadStore,
	mergeRun,
	type NewFinding,
	priorFalsePositives,
	projectFingerprint,
	REPORT_FILE,
	saveProfile,
	saveStore,
	storePath,
	writeFileAtomic,
	writeRunLog,
} from "./store.ts";
import {
	type ArgumentCollector,
	createAffirmTool,
	createChallengeTool,
	createHypothesisTool,
	createProfileTool,
	createSummaryTool,
	createTriageTool,
	type HypothesisCollector,
	type ProfileCollector,
	type TriageCollector,
} from "./submit-tools.ts";

export type Progress =
	| { stage: "profile"; cached?: boolean }
	| { stage: "hunt"; done: number; total: number }
	| { stage: "triage" }
	| { stage: "verify"; done: number; total: number }
	| { stage: "report" };

export interface PipelineDeps {
	runner: AgentRunner;
	models: Record<Role, Model<Api>>;
	settings: SecurityReviewSettings;
	now?: () => Date;
	onProgress?: (progress: Progress) => void;
	signal?: AbortSignal;
}

export interface RunResult {
	run: RunRecord;
	scope: Scope;
	profile?: Profile;
	profileCached: boolean;
	hypotheses: Hypothesis[];
	/** Findings observed in this run, as stored. */
	findings: Finding[];
	refuted: RefutedHypothesis[];
	unverified: Hypothesis[];
	counts: SeverityCounts;
	summary?: string;
	gitignoreHint?: string;
	reportPath: string;
	storePath: string;
	runLogPath: string;
	agents: AgentOutcome[];
}

function runId(now: Date): string {
	return `${now.toISOString().replace(/[-:]/g, "").replace(/\..+/, "")}-${randomBytes(2).toString("hex")}`;
}

function describeFailure(outcome: AgentOutcome): string {
	return `${outcome.label}: ${outcome.error ?? "failed"}`;
}

function sameModel(a: Model<Api>, b: Model<Api>): boolean {
	return a.provider === b.provider && a.id === b.id;
}

/** A failed outcome for work that threw instead of returning one. */
function thrown(label: string, reason: unknown): AgentOutcome {
	return { label, ok: false, timedOut: false, error: String(reason), usage: emptyUsage() };
}

const MAX_REASON_LABEL = 60;
const MAX_REASON_ERROR = 300;
const MAX_REASON_LABELS = 3;

function shorten(text: string, max: number): string {
	const flat = text.replace(/\s+/g, " ").trim();
	return flat.length <= max ? flat : `${flat.slice(0, max - 1).trimEnd()}…`;
}

/**
 * Incomplete-run reasons for a stage's failed agents, one per distinct error, in first-seen order.
 * A provider that refuses every request would otherwise repeat the same long error once per agent;
 * the run log keeps each agent's full error.
 */
export function failureReasons(stage: string, failed: AgentOutcome[]): string[] {
	const groups = new Map<string, string[]>();
	for (const outcome of failed) {
		const error = outcome.error ?? "failed";
		groups.set(error, [...(groups.get(error) ?? []), outcome.label]);
	}
	return [...groups].map(([error, labels]) => {
		const shown = labels.slice(0, MAX_REASON_LABELS).map((label) => shorten(label, MAX_REASON_LABEL));
		const more = labels.length - shown.length;
		const message = shorten(error, MAX_REASON_ERROR);
		if (labels.length === 1) return `${stage} agent failed (${shown[0]}: ${message})`;
		return `${labels.length} ${stage} agents failed (${shown.join(", ")}${more ? ` and ${more} more` : ""}): ${message}`;
	});
}

/** Profile stage: reuse the cached profile in diff mode when the project fingerprint matches. */
export async function profileStage(scope: Scope, deps: PipelineDeps, agents: AgentOutcome[]): Promise<{ profile?: Profile; cached: boolean; failure?: AgentOutcome }> {
	const projectFp = await projectFingerprint(scope.root);
	if (scope.mode === "diff") {
		const cached = loadCachedProfile(scope.root, projectFp);
		if (cached) {
			deps.onProgress?.({ stage: "profile", cached: true });
			return { profile: cached, cached: true };
		}
	}
	deps.onProgress?.({ stage: "profile" });
	const collector: ProfileCollector = {};
	const outcome = await deps.runner.run(
		{
			label: "profile",
			role: "profile",
			model: deps.models.profile,
			systemPrompt: systemPrompt("profile"),
			prompt: profilePrompt(scope),
			tools: [createProfileTool(collector)],
			done: () => collector.profile !== undefined,
			nudge: "You have not submitted the profile yet. Call submit_profile now with what you have found.",
		},
		deps.signal,
	);
	agents.push(outcome);
	if (collector.profile) {
		saveProfile(scope.root, projectFp, collector.profile, (deps.now ?? (() => new Date()))().toISOString());
		return { profile: collector.profile, cached: false, failure: outcome.ok ? undefined : outcome };
	}
	return { cached: false, failure: outcome };
}

/**
 * Triage stage: one agent groups candidates that a single fix removes. Without at least two candidates
 * nothing runs; without a valid grouping the candidates proceed unchanged and the error is returned.
 */
export async function triageStage(
	profile: Profile | undefined,
	candidates: TaggedHypothesis[],
	deps: PipelineDeps,
	agents: AgentOutcome[],
): Promise<{ candidates: TaggedHypothesis[]; error?: string }> {
	if (candidates.length < 2) return { candidates };
	deps.onProgress?.({ stage: "triage" });
	const labels = candidates.map((_, i) => candidateLabel(i));
	const collector: TriageCollector = {};
	const outcome = await deps.runner.run(
		{
			label: "triage",
			role: "triage",
			model: deps.models.triage,
			systemPrompt: systemPrompt("triage"),
			prompt: triagePrompt(profile, candidates, labels),
			tools: [createTriageTool(labels, collector)],
			done: () => collector.groups !== undefined,
			nudge: "You have not submitted the triage yet. Call submit_triage now, with an empty groups list if nothing should be merged.",
		},
		deps.signal,
	);
	agents.push(outcome);
	if (!collector.groups) return { candidates, error: `triage unavailable, hypotheses were verified separately (${describeFailure(outcome)})` };
	return { candidates: applyTriageGroups(candidates, collector.groups) };
}

/** Hunt stage: parallel agents per partition, then merge duplicates, triage, apply the cap, and assign ids. */
export async function huntStage(
	scope: Scope,
	profile: Profile | undefined,
	deps: PipelineDeps,
	agents: AgentOutcome[],
): Promise<{ verify: Hypothesis[]; overflow: Hypothesis[]; all: Hypothesis[]; failures: AgentOutcome[]; errors: string[] }> {
	const assignments = huntAssignments(scope);
	let done = 0;
	let total = assignments.length;
	deps.onProgress?.({ stage: "hunt", done, total });
	const perAssignment: TaggedHypothesis[][] = assignments.map(() => []);
	const outcomes: (AgentOutcome | undefined)[] = assignments.map(() => undefined);
	const failures: AgentOutcome[] = [];
	const errors: string[] = [];

	const hunt = async (assignment: HuntAssignment, label: string) => {
		const collector: HypothesisCollector = { hypotheses: [] };
		const outcome = await deps.runner.run(
			{
				label,
				role: "hunt",
				model: deps.models.hunt,
				systemPrompt: systemPrompt("hunt"),
				prompt: huntPrompt(profile, scope, assignment),
				tools: [createHypothesisTool(scope.root, collector)],
				done: () => true,
			},
			deps.signal,
		);
		agents.push(outcome);
		deps.onProgress?.({ stage: "hunt", done: ++done, total });
		// Hypotheses submitted before a failure are schema-valid and still verified.
		return { outcome, hypotheses: collector.hypotheses.map((h): TaggedHypothesis => ({ ...h, source_partition: assignment.label })) };
	};

	const results = await mapBounded(assignments, deps.settings.maxConcurrentAgents, async (assignment, index) => {
		const attempt = await hunt(assignment, `hunt:${assignment.label}`);
		perAssignment[index] = attempt.hypotheses;
		outcomes[index] = attempt.outcome;
	});
	for (const result of results) if (result.status === "rejected") failures.push(thrown("hunt", result.reason));

	// A hunter that failed on a transient provider error (usually a rate limit) is run once more after
	// the batch, when fewer agents compete for the provider. Losing it would lose its vulnerability class.
	const rerun = assignments.flatMap((assignment, index) => (outcomes[index]?.transient && !deps.signal?.aborted ? [{ assignment, index }] : []));
	total += rerun.length;
	if (rerun.length) deps.onProgress?.({ stage: "hunt", done, total });
	const rerunResults = await mapBounded(rerun, deps.settings.maxConcurrentAgents, async ({ assignment, index }) => {
		const first = outcomes[index]!;
		const retry = await hunt(assignment, `hunt:${assignment.label} (re-run)`);
		if (retry.outcome.ok) {
			// The re-run is a complete attempt; keeping the partial one too would add near-duplicates.
			perAssignment[index] = retry.hypotheses;
			outcomes[index] = retry.outcome;
			errors.push(`${first.label} was re-run after a transient error (${first.error})`);
		} else {
			perAssignment[index] = [...perAssignment[index]!, ...retry.hypotheses];
			outcomes[index] = retry.outcome;
		}
	});
	for (const result of rerunResults) if (result.status === "rejected") failures.push(thrown("hunt", result.reason));
	for (const outcome of outcomes) if (outcome && !outcome.ok) failures.push(outcome);

	// Partition order, not completion order, so ids are deterministic for the same submissions.
	const merged = mergeDuplicateHypotheses(perAssignment.flat());
	const triage = await triageStage(profile, merged, deps, agents);
	const { verify, overflow } = applyHypothesisCap(triage.candidates, deps.settings.maxHypotheses);
	const withIds = [...verify, ...overflow].map(
		(h, i): Hypothesis => ({ ...h, id: `H-${String(i + 1).padStart(3, "0")}`, fingerprint: fingerprint(h) }),
	);
	if (triage.error) errors.push(triage.error);
	return { verify: withIds.slice(0, verify.length), overflow: withIds.slice(verify.length), all: withIds, failures, errors };
}

export type VerifyResult =
	| { kind: "finding"; hypothesis: Hypothesis; finding: NewFinding }
	| { kind: "refuted"; hypothesis: Hypothesis; refuted: RefutedHypothesis }
	| { kind: "unverified"; hypothesis: Hypothesis; failure: AgentOutcome }
	| { kind: "invalid"; hypothesis: Hypothesis; reason: string };

export async function buildFinding(scope: Scope, hypothesis: Hypothesis, affirm: AffirmArgument, challenge: ChallengeArgument): Promise<NewFinding> {
	const verdict = challenge.verdict === "confirmed" ? "confirmed" : "downgraded";
	const finding: NewFinding = {
		fingerprint: hypothesis.fingerprint,
		title: formatTitle(affirm.component, hypothesis.vuln_type, affirm.consequence),
		finding_class: verdict === "confirmed" ? "vulnerability" : "risk",
		vuln_type: normalizeVulnType(hypothesis.vuln_type),
		severity: challenge.severity ?? affirm.severity,
		confidence: challenge.confidence,
		anchors: hypothesis.anchors,
		data_flow: affirm.attack_path,
		description: affirm.description,
		verification: { affirmer: affirm, challenger: challenge, verdict },
		remediation: affirm.remediation,
		scope: scope.mode,
	};
	const cwe = affirm.cwe ?? hypothesis.cwe;
	if (cwe) finding.cwe = cwe;
	if (affirm.cvss_vector) finding.cvss_vector = affirm.cvss_vector;
	if (affirm.cvss_score !== undefined) finding.cvss_score = affirm.cvss_score;
	if (hypothesis.consequences?.length) finding.consequences = hypothesis.consequences;
	const introduced = await introducedIn(scope, hypothesis.anchors[0]!.file);
	if (introduced) finding.introduced_in = introduced;
	return finding;
}

/** Verify one hypothesis: affirmer, then challenger with the affirmer's argument and any prior false-positive verdict. */
export async function verifyHypothesis(
	scope: Scope,
	profile: Profile | undefined,
	hypothesis: Hypothesis,
	prior: Finding | undefined,
	deps: PipelineDeps,
	agents: AgentOutcome[],
): Promise<VerifyResult> {
	const affirmCollector: ArgumentCollector<AffirmArgument> = {};
	const affirmOutcome = await deps.runner.run(
		{
			label: `affirmer:${hypothesis.id}`,
			role: "affirmer",
			model: deps.models.affirmer,
			systemPrompt: systemPrompt("affirmer"),
			prompt: affirmerPrompt(profile, hypothesis, scope),
			tools: [createAffirmTool(hypothesis.id, affirmCollector)],
			done: () => affirmCollector.argument !== undefined,
			nudge: `You have not submitted your argument. Call submit_argument now for hypothesis_id "${hypothesis.id}".`,
		},
		deps.signal,
	);
	agents.push(affirmOutcome);
	const affirm = affirmCollector.argument;
	if (!affirm) return { kind: "unverified", hypothesis, failure: affirmOutcome };

	const challengeCollector: ArgumentCollector<ChallengeArgument> = {};
	const challengeOutcome = await deps.runner.run(
		{
			label: `challenger:${hypothesis.id}`,
			role: "challenger",
			model: deps.models.challenger,
			systemPrompt: systemPrompt("challenger"),
			prompt: challengerPrompt(profile, hypothesis, affirm, prior),
			tools: [createChallengeTool(hypothesis.id, challengeCollector)],
			done: () => challengeCollector.argument !== undefined,
			nudge: `You have not submitted your verdict. Call submit_argument now for hypothesis_id "${hypothesis.id}".`,
		},
		deps.signal,
	);
	agents.push(challengeOutcome);
	const challenge = challengeCollector.argument;
	if (!challenge) return { kind: "unverified", hypothesis, failure: challengeOutcome };

	if (challenge.verdict === "refuted") return { kind: "refuted", hypothesis, refuted: { hypothesis, affirmer: affirm, challenger: challenge } };
	const finding = await buildFinding(scope, hypothesis, affirm, challenge);
	const errors = validate(FindingSchema, { ...finding, id: "SR-000", status: "open", first_seen: "-", last_seen: "-" });
	if (errors.length > 0) return { kind: "invalid", hypothesis, reason: `${hypothesis.id}: finding failed validation: ${errors.join("; ")}` };
	return { kind: "finding", hypothesis, finding };
}

export async function verifyStage(
	scope: Scope,
	profile: Profile | undefined,
	hypotheses: Hypothesis[],
	priorFor: (hypothesis: Hypothesis) => Finding | undefined,
	deps: PipelineDeps,
	agents: AgentOutcome[],
): Promise<VerifyResult[]> {
	let done = 0;
	deps.onProgress?.({ stage: "verify", done, total: hypotheses.length });
	const results = await mapBounded(hypotheses, deps.settings.maxConcurrentAgents, async (hypothesis) => {
		const result = await verifyHypothesis(scope, profile, hypothesis, priorFor(hypothesis), deps, agents);
		deps.onProgress?.({ stage: "verify", done: ++done, total: hypotheses.length });
		return result;
	});
	return results.map((result, i) =>
		result.status === "fulfilled" ? result.value : { kind: "unverified", hypothesis: hypotheses[i]!, failure: thrown(hypotheses[i]!.id, result.reason) },
	);
}

/** Run profile, hunt, verify, and report for a resolved scope, and persist the results. */
export async function runPipeline(scope: Scope, deps: PipelineDeps): Promise<RunResult> {
	const now = deps.now ?? (() => new Date());
	const started = now();
	const id = runId(started);
	// Load first: an unreadable store stops the run before any model call and is never overwritten.
	const previousStore = loadStore(scope.root);
	const agents: AgentOutcome[] = [];
	const incomplete: string[] = [];
	const errors: string[] = [];

	const profileResult = await profileStage(scope, deps, agents);
	if (profileResult.failure) incomplete.push(...failureReasons("profile", [profileResult.failure]));

	// The profile agent is the first model request. If the provider refused it outright, every hunt agent
	// on the same model would be refused too, so do not start them.
	const refused = profileResult.failure?.rejected && sameModel(deps.models.profile, deps.models.hunt);
	if (refused) incomplete.push(`hunting skipped: ${deps.models.hunt.provider}/${deps.models.hunt.id} rejected the profile agent's request`);
	const hunt = refused ? { verify: [], overflow: [], all: [], failures: [], errors: [] } : await huntStage(scope, profileResult.profile, deps, agents);
	incomplete.push(...failureReasons("hunt", hunt.failures));
	// Triage failure loses no coverage: it is an error, not a reason the run is incomplete.
	errors.push(...hunt.errors);
	if (hunt.overflow.length) incomplete.push(`${hunt.overflow.length} hypotheses over the cap of ${deps.settings.maxHypotheses} were not verified`);

	const priors = priorFalsePositives(previousStore, hunt.verify);
	const verified = await verifyStage(scope, profileResult.profile, hunt.verify, (h) => priors.get(h.id), deps, agents);
	const newFindings: NewFinding[] = [];
	const refuted: RefutedHypothesis[] = [];
	const unverified: Hypothesis[] = [...hunt.overflow];
	const verifyFailures: AgentOutcome[] = [];
	for (const result of verified) {
		if (result.kind === "finding") newFindings.push(result.finding);
		else if (result.kind === "refuted") refuted.push(result.refuted);
		else if (result.kind === "unverified") {
			unverified.push(result.hypothesis);
			verifyFailures.push(result.failure);
		} else errors.push(result.reason);
	}
	incomplete.push(...failureReasons("verification", verifyFailures));

	deps.onProgress?.({ stage: "report" });
	const finished = now();
	const merged = mergeRun(previousStore, {
		run: {
			id,
			mode: scope.mode,
			...(scope.baseRef ? { base_ref: scope.baseRef } : {}),
			started_at: started.toISOString(),
			finished_at: finished.toISOString(),
			files: scope.files.length,
			complete: incomplete.length === 0,
			incomplete_reasons: incomplete,
			refuted,
			unverified,
			errors,
		},
		findings: newFindings,
		now: finished.toISOString(),
	});
	let summary: string | undefined;
	if (merged.observed.length > 0 || refuted.length > 0) {
		const collector: { summary?: string } = {};
		const outcome = await deps.runner.run(
			{
				label: "report",
				role: "report",
				model: deps.models.report,
				systemPrompt: systemPrompt("report"),
				prompt: reportPrompt(
					{
						mode: scope.mode,
						files: scope.files.length,
						hypotheses: hunt.all.length,
						vulnerabilities: merged.observed.filter((f) => f.finding_class === "vulnerability").length,
						risks: merged.observed.filter((f) => f.finding_class === "risk").length,
						refuted: refuted.length,
						unverified: unverified.length,
						complete: merged.run.complete,
						incompleteReasons: incomplete,
					},
					merged.observed,
				),
				tools: [createSummaryTool(collector)],
				done: () => collector.summary !== undefined,
				nudge: "Call submit_summary now.",
			},
			deps.signal,
		);
		agents.push(outcome);
		summary = collector.summary;
		if (!summary) errors.push(`report summary unavailable (${describeFailure(outcome)})`);
	}

	const hint = await gitignoreHint(scope.root, merged.store);
	saveStore(scope.root, hint.store);

	const reportPath = storePath(scope.root, REPORT_FILE);
	writeFileAtomic(reportPath, renderReport({ run: merged.run, scope, findings: merged.observed, refuted, unverified, summary }));
	const runLogPath = writeRunLog(scope.root, {
		...merged.run,
		errors,
		scope: { mode: scope.mode, base_ref: scope.baseRef, merge_base: scope.mergeBase, files: scope.files },
		profile: profileResult.profile,
		profile_cached: profileResult.cached,
		hypotheses: hunt.all,
		verification: verified.map((result) => ({
			hypothesis_id: result.hypothesis.id,
			outcome: result.kind,
			...(result.kind === "finding" ? { verdict: result.finding.verification.verdict } : {}),
			...(priors.get(result.hypothesis.id) ? { prior_false_positive: priors.get(result.hypothesis.id)!.id } : {}),
		})),
		agents: agents.map(({ label, ok, timedOut, error, transient, rejected, usage }) => ({ label, ok, timedOut, error, transient, rejected, usage })),
		summary,
	});

	return {
		run: merged.run,
		scope,
		profile: profileResult.profile,
		profileCached: profileResult.cached,
		hypotheses: hunt.all,
		findings: merged.observed,
		refuted,
		unverified,
		counts: countBySeverity(merged.observed),
		summary,
		gitignoreHint: hint.hint,
		reportPath,
		storePath: storePath(scope.root, FINDINGS_FILE),
		runLogPath,
		agents,
	};
}
