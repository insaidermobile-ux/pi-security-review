import type { AffirmArgument, ChallengeArgument, HypothesisInput, Verdict } from "../extensions/security-review/schema.ts";

export function hypothesisInput(overrides: Partial<HypothesisInput> = {}): HypothesisInput {
	return {
		anchors: [{ file: "src/users.ts", line: 12, function: "searchUsers" }],
		claim: "The name query parameter is concatenated into SQL",
		vuln_type: "sql-injection",
		cwe: "CWE-89",
		suspected_source: "HTTP query parameter name",
		suspected_sink: "db.query with raw SQL",
		severity_estimate: "high",
		...overrides,
	};
}

export function affirm(hypothesisId: string, overrides: Partial<AffirmArgument> = {}): AffirmArgument {
	return {
		hypothesis_id: hypothesisId,
		component: "User search endpoint (src/users.ts)",
		consequence: "reading any user's records",
		attack_path: [
			{ location: "src/server.ts:5", description: "GET /users reads req.query.name" },
			{ location: "src/users.ts:12", description: "name is concatenated into the SQL string passed to db.query" },
		],
		missing_defenses: [{ defense: "parameterized query", location: "not found" }],
		preconditions: ["network access to the API"],
		severity: "high",
		cwe: "CWE-89",
		description: {
			background: "The API exposes a user search endpoint.",
			detail: "User input is concatenated into SQL.",
			attack_scenario: "GET /users?name=' OR 1=1 -- returns every row.",
		},
		remediation: { summary: "Use a parameterized query." },
		...overrides,
	};
}

export function challenge(hypothesisId: string, verdict: Verdict, overrides: Partial<ChallengeArgument> = {}): ChallengeArgument {
	return {
		hypothesis_id: hypothesisId,
		attribution: { attacker_is_trusted_role: false, harmful_step_outside_component: false, reasoning: "Anonymous caller, query runs in the audited code." },
		defenses_found: [{ defense: "input validation", location: "not found", effect: "none" }],
		threat_model_notes: "Unauthenticated data access has independent value.",
		verdict,
		confidence: "high",
		reasoning: verdict === "refuted" ? "A defense blocks the path." : "No defense blocks the path.",
		...overrides,
	};
}
