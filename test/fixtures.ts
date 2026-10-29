import { fingerprint } from "../extensions/security-review/fingerprint.ts";
import type { AffirmArgument, ChallengeArgument, Finding, HypothesisInput, NewFinding, Verdict } from "../extensions/security-review/schema.ts";

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

/** Hypotheses about the vulnerable-app fixture (test/fixtures/vulnerable-app). */
export const SQLI: HypothesisInput = hypothesisInput({
	anchors: [{ file: "src/users.js", line: 6, function: "searchUsers" }],
	suspected_sink: "db.query with concatenated SQL",
	severity_estimate: "high",
});
export const TRAVERSAL: HypothesisInput = hypothesisInput({
	anchors: [{ file: "src/files.js", line: 9, function: "download" }],
	claim: "name is resolved against the upload root and streamed",
	vuln_type: "path-traversal",
	cwe: "CWE-22",
	suspected_sink: "fs.createReadStream",
	severity_estimate: "medium",
});
export const DISCLOSURE: HypothesisInput = hypothesisInput({
	anchors: [{ file: "src/users.js", line: 6, function: "searchUsers" }],
	claim: "Session digests can be read through the injection",
	vuln_type: "secret-disclosure",
	suspected_sink: "res.json returning session_digest",
	severity_estimate: "critical",
});
export const RATE_LIMIT: HypothesisInput = hypothesisInput({
	anchors: [{ file: "src/users.js", line: 4, function: "searchUsers" }],
	claim: "No rate limit on user search",
	vuln_type: "missing-rate-limit",
	suspected_sink: "db.query per request",
	severity_estimate: "low",
});

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

/** The stored finding for hypothesisInput() after a confirmed verification. An override set to undefined removes the field. */
export function finding(overrides: Partial<Finding> = {}): Finding {
	const merged: Partial<Finding> = {
		id: "SR-001",
		fingerprint: fingerprint(hypothesisInput()),
		title: "User search endpoint (src/users.ts): sql injection leading to reading any user's records",
		finding_class: "vulnerability",
		vuln_type: "sql-injection",
		severity: "high",
		confidence: "high",
		anchors: hypothesisInput().anchors,
		data_flow: affirm("H-001").attack_path,
		description: affirm("H-001").description,
		verification: { affirmer: affirm("H-001"), challenger: challenge("H-001", "confirmed"), verdict: "confirmed" },
		remediation: affirm("H-001").remediation,
		scope: "diff",
		status: "open",
		first_seen: "2026-10-12T10:00:00.000Z",
		last_seen: "2026-10-12T10:00:00.000Z",
		...overrides,
	};
	return Object.fromEntries(Object.entries(merged).filter(([, value]) => value !== undefined)) as Finding;
}

/** finding() as a run produces it, before the store assigns identity and lifecycle fields. */
export function newFinding(overrides: Partial<NewFinding> = {}): NewFinding {
	const { id: _id, status: _status, first_seen: _first, last_seen: _last, ...body } = finding(overrides);
	return body;
}
