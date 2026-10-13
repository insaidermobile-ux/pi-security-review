import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { fingerprint, formatTitle, normalizeSink } from "../extensions/security-review/fingerprint.ts";
import { AffirmArgument, ChallengeArgument, Finding, HypothesisInput, ProfileInput, StoreFile, validate } from "../extensions/security-review/schema.ts";
import { affirm, challenge, hypothesisInput } from "./fixtures.ts";

describe("schemas", () => {
	test("accepts a complete hypothesis", () => {
		assert.deepEqual(validate(HypothesisInput, hypothesisInput()), []);
	});

	test("rejects a hypothesis without anchors", () => {
		const errors = validate(HypothesisInput, { ...hypothesisInput(), anchors: [] });
		assert.ok(errors.some((e) => e.startsWith("/anchors")), errors.join("\n"));
	});

	test("rejects a hypothesis missing required fields or with an invalid severity", () => {
		const { suspected_sink: _sink, ...rest } = hypothesisInput();
		assert.ok(validate(HypothesisInput, rest).length > 0);
		assert.ok(validate(HypothesisInput, { ...hypothesisInput(), severity_estimate: "severe" }).length > 0);
	});

	test("accepts complete affirm and challenge arguments", () => {
		assert.deepEqual(validate(AffirmArgument, affirm("H-001")), []);
		assert.deepEqual(validate(ChallengeArgument, challenge("H-001", "confirmed")), []);
	});

	test("rejects a challenge argument without verdict", () => {
		const { verdict: _verdict, ...rest } = challenge("H-001", "confirmed");
		const errors = validate(ChallengeArgument, rest);
		assert.ok(errors.length > 0);
		assert.ok(errors.some((e) => e.includes("verdict")), errors.join("\n"));
	});

	test("rejects an affirm argument with an empty attack path", () => {
		assert.ok(validate(AffirmArgument, { ...affirm("H-001"), attack_path: [] }).length > 0);
	});

	test("rejects a profile without stack", () => {
		assert.ok(validate(ProfileInput, { summary: "x", stack: [], entry_points: [], trust_boundaries: [], auth_model: "none", external_inputs: [] }).length > 0);
	});
});

describe("consequences on findings", () => {
	const finding = {
		id: "SR-001",
		fingerprint: "abc",
		title: "User search endpoint: sql injection leading to data exposure",
		finding_class: "vulnerability",
		vuln_type: "sql-injection",
		severity: "high",
		confidence: "high",
		anchors: [{ file: "src/users.js", line: 6 }],
		data_flow: affirm("H-001").attack_path,
		description: affirm("H-001").description,
		verification: { affirmer: affirm("H-001"), challenger: challenge("H-001", "confirmed"), verdict: "confirmed" },
		remediation: affirm("H-001").remediation,
		scope: "diff",
		status: "open",
		first_seen: "t1",
		last_seen: "t1",
	};
	const consequence = { vuln_type: "secret-disclosure", description: "Session digests are readable through the injection", anchors: [{ file: "src/users.js", line: 6 }] };

	test("validates findings with and without consequences", () => {
		assert.deepEqual(validate(Finding, finding), []);
		assert.deepEqual(validate(Finding, { ...finding, consequences: [consequence] }), []);
	});

	test("rejects a consequence without anchors", () => {
		assert.notDeepEqual(validate(Finding, { ...finding, consequences: [{ ...consequence, anchors: [] }] }), []);
	});

	test("a store written without consequences still loads", () => {
		assert.deepEqual(validate(StoreFile, { version: 1, gitignore_hint_shown: false, findings: [finding], runs: [] }), []);
	});
});

describe("fingerprint", () => {
	test("is identical after line shifts", () => {
		const before = hypothesisInput();
		const after = { ...before, anchors: [{ ...before.anchors[0]!, line: before.anchors[0]!.line + 40 }] };
		assert.equal(fingerprint(before), fingerprint(after));
	});

	test("tolerates wording changes around the sink and function names", () => {
		assert.equal(normalizeSink("db.query() call with raw SQL"), "db.query");
		assert.equal(normalizeSink("raw SQL into db.query"), "db.query");
		assert.equal(normalizeSink("db.query (pool.query) with string-concatenated SQL in src/users.js:7"), "db.query");
		assert.equal(normalizeSink("res.json(rows) returning user records"), "res.json");
		assert.equal(normalizeSink("exec(cmd) with user input"), "exec");
		const a = hypothesisInput();
		assert.equal(fingerprint(a), fingerprint({ ...a, suspected_sink: "db.query (pool.query) receiving concatenated SQL" }));
		const routed = hypothesisInput({ anchors: [{ file: "src/server.js", line: 10, function: "app.get route registration" }] });
		assert.equal(fingerprint(routed), fingerprint({ ...routed, anchors: [{ file: "src/server.js", line: 12, function: "app.get" }] }));
	});

	test("folds common vulnerability type synonyms", () => {
		const a = hypothesisInput();
		assert.equal(fingerprint(a), fingerprint({ ...a, vuln_type: "SQLi" }));
	});

	test("differs for another function, file, type, or sink", () => {
		const a = hypothesisInput();
		const base = fingerprint(a);
		assert.notEqual(base, fingerprint({ ...a, anchors: [{ ...a.anchors[0]!, function: "other" }] }));
		assert.notEqual(base, fingerprint({ ...a, anchors: [{ ...a.anchors[0]!, file: "src/other.ts" }] }));
		assert.notEqual(base, fingerprint({ ...a, vuln_type: "xss" }));
		assert.notEqual(base, fingerprint({ ...a, suspected_sink: "fs.readFile" }));
	});

	test("normalizes vulnerability type spelling", () => {
		const a = hypothesisInput();
		assert.equal(fingerprint(a), fingerprint({ ...a, vuln_type: "SQL Injection" }));
	});
});

describe("formatTitle", () => {
	test("names component, vulnerability type, and consequence", () => {
		assert.equal(
			formatTitle("User search endpoint (src/users.ts)", "sql_injection", "reading any user's records."),
			"User search endpoint (src/users.ts): sql injection leading to reading any user's records",
		);
	});
});
