import { type Static, type TSchema, Type } from "typebox";
import { Value } from "typebox/value";

const Text = (description: string) => Type.String({ minLength: 1, description });

export const Severity = Type.Union([Type.Literal("critical"), Type.Literal("high"), Type.Literal("medium"), Type.Literal("low")], {
	description: "critical | high | medium | low",
});
export type Severity = Static<typeof Severity>;
export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low"];

export const Confidence = Type.Union([Type.Literal("high"), Type.Literal("medium"), Type.Literal("low")]);
export type Confidence = Static<typeof Confidence>;

export const Verdict = Type.Union([Type.Literal("confirmed"), Type.Literal("downgraded"), Type.Literal("refuted")], {
	description: "confirmed: real, independently valuable vulnerability; downgraded: reachable but limited value (risk); refuted: not exploitable",
});
export type Verdict = Static<typeof Verdict>;

export const ScopeMode = Type.Union([Type.Literal("diff"), Type.Literal("full")]);
export type ScopeMode = Static<typeof ScopeMode>;

export const FindingStatus = Type.Union([
	Type.Literal("open"),
	Type.Literal("accepted-risk"),
	Type.Literal("fixed"),
	Type.Literal("false-positive"),
	Type.Literal("stale"),
]);
export type FindingStatus = Static<typeof FindingStatus>;

const Cwe = Type.String({ pattern: "^CWE-[0-9]+$", description: 'CWE identifier such as "CWE-89"' });

export const Anchor = Type.Object(
	{
		file: Text("Path relative to the project root"),
		line: Type.Integer({ minimum: 1 }),
		function: Type.Optional(Type.String({ description: "Enclosing function or method, if any" })),
	},
	{ additionalProperties: false },
);
export type Anchor = Static<typeof Anchor>;

/** A point in a code path, cited as `file:line`. */
export const PathStep = Type.Object(
	{
		location: Text('Code location as "path:line"'),
		description: Text("What happens at this step"),
	},
	{ additionalProperties: false },
);
export type PathStep = Static<typeof PathStep>;

export const ProfileInput = Type.Object(
	{
		summary: Text("One paragraph describing what the project does"),
		stack: Type.Array(Type.String(), { minItems: 1, description: "Languages, frameworks, runtimes" }),
		entry_points: Type.Array(PathStep, { description: "Where external input enters: routes, CLIs, message handlers, file parsers" }),
		trust_boundaries: Type.Array(Type.String(), { description: "Boundaries between differently trusted actors or components" }),
		auth_model: Text("How authentication and authorization work, or that there is none"),
		external_inputs: Type.Array(Type.String(), { description: "Kinds of attacker-influenced input" }),
		sensitive_assets: Type.Optional(Type.Array(Type.String())),
	},
	{ additionalProperties: false },
);
export type Profile = Static<typeof ProfileInput>;

export const HypothesisInput = Type.Object(
	{
		anchors: Type.Array(Anchor, { minItems: 1, description: "Code locations where the issue manifests; the first is the primary anchor" }),
		claim: Text("What is wrong and why it may be exploitable"),
		vuln_type: Text('Short vulnerability type, e.g. "sql-injection", "path-traversal", "missing-authz"'),
		cwe: Type.Optional(Cwe),
		suspected_source: Text("Where attacker-controlled data or action originates"),
		suspected_sink: Text("The dangerous operation reached, e.g. a query call, file open, or privileged action"),
		severity_estimate: Severity,
	},
	{ additionalProperties: false },
);
export type HypothesisInput = Static<typeof HypothesisInput>;

export interface Hypothesis extends HypothesisInput {
	id: string;
	/** Label of the hunt partition that produced it. */
	source_partition: string;
	fingerprint: string;
}

export const MissingDefense = Type.Object(
	{
		defense: Text("A defense that would block or limit the attack"),
		location: Text('Where it should be, as "path:line", or "not found"'),
	},
	{ additionalProperties: false },
);

export const AffirmArgument = Type.Object(
	{
		hypothesis_id: Text("Id of the hypothesis being argued"),
		component: Text("Affected component or location, used in the title"),
		consequence: Text("What an attacker achieves, used in the title"),
		attack_path: Type.Array(PathStep, { minItems: 1, description: "Ordered steps from source to sink" }),
		missing_defenses: Type.Array(MissingDefense),
		preconditions: Type.Array(Type.String(), { description: "What the attacker needs" }),
		severity: Severity,
		cwe: Type.Optional(Cwe),
		cvss_vector: Type.Optional(Type.String({ pattern: "^CVSS:3\\.[01]/" })),
		cvss_score: Type.Optional(Type.Number({ minimum: 0, maximum: 10 })),
		description: Type.Object(
			{
				background: Text("Context needed to understand the issue"),
				detail: Text("Technical explanation of the flaw"),
				attack_scenario: Text("Concrete attack walkthrough"),
			},
			{ additionalProperties: false },
		),
		remediation: Type.Object(
			{
				summary: Text("How to fix it"),
				patch: Type.Optional(Type.String({ description: "Optional unified diff or code snippet" })),
			},
			{ additionalProperties: false },
		),
	},
	{ additionalProperties: false },
);
export type AffirmArgument = Static<typeof AffirmArgument>;

export const DefenseFound = Type.Object(
	{
		defense: Text("Check, validation, precondition, or mitigation examined"),
		location: Text('Where it is, as "path:line", or "not found"'),
		effect: Type.Union([Type.Literal("blocks"), Type.Literal("mitigates"), Type.Literal("none")]),
	},
	{ additionalProperties: false },
);

export const ChallengeArgument = Type.Object(
	{
		hypothesis_id: Text("Id of the hypothesis being challenged"),
		attribution: Type.Object(
			{
				attacker_is_trusted_role: Type.Boolean({ description: "The assumed attacker already holds the capability being abused" }),
				harmful_step_outside_component: Type.Boolean({ description: "The final harmful step depends on a downstream consumer, not the audited code" }),
				reasoning: Text("Explanation of the attribution test"),
			},
			{ additionalProperties: false },
		),
		defenses_found: Type.Array(DefenseFound),
		threat_model_notes: Text("Whether the attack has independent security value under the project's threat model"),
		verdict: Verdict,
		confidence: Confidence,
		reasoning: Text("Summary of why the verdict was reached"),
		severity: Type.Optional(Severity),
	},
	{ additionalProperties: false },
);
export type ChallengeArgument = Static<typeof ChallengeArgument>;

export const SummaryInput = Type.Object(
	{ summary: Text("Short executive summary of the run's results in Markdown") },
	{ additionalProperties: false },
);

export const Finding = Type.Object({
	id: Type.String({ pattern: "^SR-[0-9]{3,}$" }),
	fingerprint: Type.String({ minLength: 1 }),
	title: Type.String({ minLength: 1 }),
	finding_class: Type.Union([Type.Literal("vulnerability"), Type.Literal("risk")]),
	vuln_type: Type.String({ minLength: 1 }),
	cwe: Type.Optional(Cwe),
	severity: Severity,
	cvss_vector: Type.Optional(Type.String()),
	cvss_score: Type.Optional(Type.Number({ minimum: 0, maximum: 10 })),
	confidence: Confidence,
	anchors: Type.Array(Anchor, { minItems: 1 }),
	data_flow: Type.Array(PathStep, { minItems: 1 }),
	description: AffirmArgument.properties.description,
	verification: Type.Object({
		affirmer: AffirmArgument,
		challenger: ChallengeArgument,
		verdict: Type.Union([Type.Literal("confirmed"), Type.Literal("downgraded")]),
	}),
	remediation: AffirmArgument.properties.remediation,
	scope: ScopeMode,
	introduced_in: Type.Optional(Type.String()),
	status: FindingStatus,
	first_seen: Type.String(),
	last_seen: Type.String(),
});
export type Finding = Static<typeof Finding>;

export const StoredHypothesis = Type.Object({
	id: Type.String(),
	source_partition: Type.String(),
	fingerprint: Type.String(),
	...HypothesisInput.properties,
});

export const RefutedHypothesis = Type.Object({
	hypothesis: StoredHypothesis,
	affirmer: AffirmArgument,
	challenger: ChallengeArgument,
});
export type RefutedHypothesis = Static<typeof RefutedHypothesis>;

export const RunRecord = Type.Object({
	id: Type.String(),
	mode: ScopeMode,
	base_ref: Type.Optional(Type.String()),
	started_at: Type.String(),
	finished_at: Type.String(),
	files: Type.Integer({ minimum: 0 }),
	complete: Type.Boolean(),
	incomplete_reasons: Type.Array(Type.String()),
	finding_ids: Type.Array(Type.String()),
	refuted: Type.Array(RefutedHypothesis),
	unverified: Type.Array(StoredHypothesis),
	errors: Type.Array(Type.String()),
});
export type RunRecord = Static<typeof RunRecord>;

export const StoreFile = Type.Object({
	version: Type.Literal(1),
	gitignore_hint_shown: Type.Boolean(),
	findings: Type.Array(Finding),
	runs: Type.Array(RunRecord),
});
export type StoreFile = Static<typeof StoreFile>;

/** Validate a value, returning readable error lines (empty when valid). */
export function validate(schema: TSchema, value: unknown): string[] {
	if (Value.Check(schema, value)) return [];
	const lines = new Set<string>();
	for (const error of Value.Errors(schema, value)) {
		if (error.keyword === "anyOf" || error.keyword === "const") {
			lines.add(`${error.instancePath || "/"}: must be one of the allowed values`);
		} else {
			lines.add(`${error.instancePath || "/"}: ${error.message}`);
		}
	}
	return [...lines];
}

export function severityRank(severity: Severity): number {
	return SEVERITIES.indexOf(severity);
}
