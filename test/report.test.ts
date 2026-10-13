import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { countBySeverity, renderReport } from "../extensions/security-review/report.ts";
import type { Finding, RunRecord } from "../extensions/security-review/schema.ts";
import { affirm, challenge, hypothesisInput } from "./fixtures.ts";

const SNAPSHOT = join(dirname(fileURLToPath(import.meta.url)), "snapshots", "report.md");

function finding(overrides: Partial<Finding>): Finding {
	return {
		id: "SR-001",
		fingerprint: "f1",
		title: "User search endpoint (src/users.ts): sql injection leading to reading any user's records",
		finding_class: "vulnerability",
		vuln_type: "sql-injection",
		cwe: "CWE-89",
		severity: "high",
		cvss_score: 8.6,
		cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		confidence: "high",
		anchors: [{ file: "src/users.ts", line: 12, function: "searchUsers" }],
		data_flow: affirm("H-001").attack_path,
		description: affirm("H-001").description,
		verification: { affirmer: affirm("H-001"), challenger: challenge("H-001", "confirmed"), verdict: "confirmed" },
		remediation: { summary: "Use a parameterized query.", patch: "- db.query(`... ${name}`)\n+ db.query('... $1', [name])" },
		scope: "diff",
		introduced_in: "0123456789abcdef0123",
		status: "open",
		first_seen: "2026-10-12T10:00:00.000Z",
		last_seen: "2026-10-12T10:00:00.000Z",
		...overrides,
	};
}

const risk = finding({
	id: "SR-002",
	fingerprint: "f2",
	title: "Admin settings (src/admin.ts): ssrf leading to requests to internal hosts",
	finding_class: "risk",
	vuln_type: "ssrf",
	severity: "medium",
	confidence: "medium",
	cwe: undefined,
	cvss_score: undefined,
	cvss_vector: undefined,
	introduced_in: "uncommitted",
	anchors: [{ file: "src/admin.ts", line: 4 }],
	verification: { affirmer: affirm("H-002"), challenger: challenge("H-002", "downgraded"), verdict: "downgraded" },
	remediation: { summary: "Restrict webhook hosts." },
});
delete (risk as Partial<Finding>).cwe;
delete (risk as Partial<Finding>).cvss_score;
delete (risk as Partial<Finding>).cvss_vector;

const refutedHypothesis = { ...hypothesisInput({ vuln_type: "path-traversal", anchors: [{ file: "src/files.ts", line: 9, function: "download" }] }), id: "H-003", source_partition: "files", fingerprint: "f3" };

const run: RunRecord = {
	id: "20261012T100000-abcd",
	mode: "diff",
	base_ref: "origin/main",
	started_at: "2026-10-12T10:00:00.000Z",
	finished_at: "2026-10-12T10:05:00.000Z",
	files: 4,
	complete: false,
	incomplete_reasons: ["hunt agent failed (hunt:network-ssrf: timed out after 600s)"],
	finding_ids: ["SR-001", "SR-002"],
	refuted: [],
	unverified: [],
	errors: [],
};

const CONSEQUENCE = { vuln_type: "sensitive-data-exposure", description: "Password hashes are returned through the same query.", anchors: [{ file: "src/users.ts", line: 14 }] };

function render(): string {
	return renderReport({
		run,
		scope: { mode: "diff", baseRef: "origin/main", mergeBase: "fedcba9876543210" },
		findings: [risk, finding({ consequences: [CONSEQUENCE] })],
		refuted: [
			{
				hypothesis: { ...refutedHypothesis, consequences: [{ ...CONSEQUENCE, vuln_type: "secret-disclosure" }] },
				affirmer: affirm("H-003"),
				challenger: challenge("H-003", "refuted", { defenses_found: [{ defense: "resolve and prefix check", location: "src/files.ts:9", effect: "blocks" }] }),
			},
		],
		unverified: [{ ...hypothesisInput({ severity_estimate: "low" }), id: "H-004", source_partition: "logic", fingerprint: "f4" }],
		summary: "One high-severity SQL injection needs fixing before merge.",
	});
}

describe("report", () => {
	test("matches the snapshot", () => {
		const output = render();
		if (process.env.UPDATE_SNAPSHOTS || !existsSync(SNAPSHOT)) writeFileSync(SNAPSHOT, output);
		assert.equal(output, readFileSync(SNAPSHOT, "utf8"));
	});

	test("groups by severity with vulnerabilities first and includes both arguments, verdict, remediation, and refuted section", () => {
		const output = render();
		const high = output.indexOf("### High");
		const medium = output.indexOf("### Medium");
		assert.ok(high > 0 && medium > high);
		assert.ok(output.indexOf("SR-001") < output.indexOf("SR-002"));
		for (const text of ["**Affirmer**", "**Challenger**", "**Verdict:** confirmed", "**Verdict:** downgraded", "**Remediation.**", "## Refuted hypotheses", "H-003", "resolve and prefix check", "## Unverified hypotheses", "**Incomplete run:**", "## Summary", "**Consequences** (removed by the same fix)", "- sensitive-data-exposure at `src/users.ts:14`: Password hashes", "**Consequences, refuted with it:**"]) {
			assert.ok(output.includes(text), text);
		}
	});

	test("states when nothing was confirmed", () => {
		const output = renderReport({ run: { ...run, complete: true, incomplete_reasons: [] }, scope: { mode: "full" }, findings: [], refuted: [], unverified: [] });
		assert.match(output, /No vulnerabilities or risks were confirmed/);
		assert.match(output, /Scope: full project/);
		assert.doesNotMatch(output, /Incomplete run/);
		assert.doesNotMatch(output, /Stale marking skipped/);
	});

	test("notes skipped stale marking only for incomplete full-mode runs", () => {
		const full = renderReport({ run: { ...run, mode: "full" }, scope: { mode: "full" }, findings: [], refuted: [], unverified: [] });
		assert.match(full, /- \*\*Incomplete run:\*\* .*\n- Stale marking skipped: the run was incomplete\./);
		assert.doesNotMatch(render(), /Stale marking skipped/);
	});

	test("counts by severity", () => {
		assert.deepEqual(countBySeverity([risk, finding({})]), { critical: 0, high: 1, medium: 1, low: 0 });
	});
});
