import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { formatSummary, parseMode, recordUsage, statusText } from "../extensions/security-review/command.ts";
import type { RunResult } from "../extensions/security-review/pipeline.ts";
import type { Finding } from "../extensions/security-review/schema.ts";
import { emptyUsage } from "../extensions/security-review/agent-runtime.ts";

describe("command arguments", () => {
	test("accepts no argument and full, rejects anything else", () => {
		assert.equal(parseMode(""), "diff");
		assert.equal(parseMode("  "), "diff");
		assert.equal(parseMode("full"), "full");
		assert.equal(parseMode(" full "), "full");
		assert.equal(parseMode("foo"), undefined);
		assert.equal(parseMode("full now"), undefined);
	});
});

describe("status text", () => {
	test("shows the stage and progress counts", () => {
		assert.equal(statusText("scope"), "security-review: scope");
		assert.equal(statusText({ stage: "profile", cached: true }), "security-review: profile (cached)");
		assert.equal(statusText({ stage: "hunt", done: 3, total: 6 }), "security-review: hunt 3/6");
		assert.equal(statusText({ stage: "triage" }), "security-review: triage");
		assert.equal(statusText({ stage: "verify", done: 7, total: 12 }), "security-review: verify 7/12");
		assert.equal(statusText({ stage: "report" }), "security-review: report");
	});
});

function result(findings: Partial<Finding>[], overrides: Partial<RunResult> = {}): RunResult {
	return {
		run: { id: "r1", mode: "diff", started_at: "", finished_at: "", files: 2, complete: true, incomplete_reasons: [], finding_ids: [], refuted: [], unverified: [], errors: [] },
		scope: { mode: "diff", root: "/repo", files: ["a.js", "b.js"], baseRef: "origin/main" },
		profileCached: false,
		hypotheses: [],
		findings: findings as Finding[],
		refuted: [],
		unverified: [],
		counts: { critical: 0, high: findings.length, medium: 0, low: 0 },
		reportPath: "/repo/.security-review/report.md",
		storePath: "/repo/.security-review/findings.json",
		runLogPath: "/repo/.security-review/runs/r1.json",
		agents: [],
		...overrides,
	};
}

describe("session summary", () => {
	test("lists counts by severity, findings, refuted count, and paths", () => {
		const text = formatSummary(
			result([{ id: "SR-001", severity: "high", finding_class: "vulnerability", title: "Search: sql injection leading to data theft", anchors: [{ file: "a.js", line: 3 }], status: "open" }], {
				refuted: [{} as never],
			}),
			"/repo",
			"1,000 tokens across 9 agents",
		);
		assert.match(text, /changes against origin\/main, 2 files/);
		assert.match(text, /1 vulnerability and 0 risks confirmed; 1 refuted, 0 unverified/);
		assert.match(text, /By severity: 0 critical, 1 high, 0 medium, 0 low/);
		assert.match(text, /SR-001 \[high vulnerability\] Search: sql injection leading to data theft - `a\.js:3`/);
		assert.match(text, /Report: `\.security-review\/report\.md` · Findings: `\.security-review\/findings\.json`/);
		assert.match(text, /Usage: 1,000 tokens across 9 agents/);
		assert.doesNotMatch(text, /consequence/);
	});

	test("counts consequences next to a finding", () => {
		const consequence = { vuln_type: "secret-disclosure", description: "d", anchors: [{ file: "a.js", line: 3 }] };
		const base: Partial<Finding> = { id: "SR-001", severity: "high", finding_class: "vulnerability", title: "T", anchors: [{ file: "a.js", line: 3 }] };
		const text = formatSummary(
			result([
				{ ...base, status: "false-positive", consequences: [consequence] },
				{ ...base, id: "SR-002", status: "open", consequences: [consequence, consequence] },
			]),
			"/repo",
			"u",
		);
		assert.match(text, /SR-001 \[high vulnerability\] T - `a\.js:3` \(\+1 consequence\) \(false-positive\)/);
		assert.match(text, /SR-002 .* \(\+2 consequences\)$/m);
	});

	test("says no findings were confirmed and still names the report", () => {
		const text = formatSummary(result([], { refuted: [{} as never, {} as never] }), "/repo", "0 tokens across 7 agents");
		assert.match(text, /No findings were confirmed\. 0 hypotheses raised, 2 refuted, 0 unverified/);
		assert.match(text, /Report: `\.security-review\/report\.md`/);
	});

	test("shows incompleteness and the gitignore hint", () => {
		const text = formatSummary(
			result([], { run: { ...result([]).run, complete: false, incomplete_reasons: ["hunt agent failed (x)"] }, gitignoreHint: "HINT" }),
			"/repo",
			"u",
		);
		assert.match(text, /\*\*Incomplete run:\*\* hunt agent failed \(x\)/);
		assert.doesNotMatch(text, /Stale marking skipped/);
		assert.match(text, /HINT$/);
		const full = result([], { run: { ...result([]).run, mode: "full", complete: false, incomplete_reasons: ["hunt agent failed (x)"] } });
		assert.match(formatSummary(full, "/repo", "u"), /hunt agent failed \(x\)\nStale marking skipped: the run was incomplete\./);
	});
});

describe("usage recording", () => {
	test("appends one usage entry per model to the session", () => {
		const appended: unknown[][] = [];
		const ctx = { sessionManager: { appendUsage: (...args: unknown[]) => appended.push(args) } } as never;
		const usage = { ...emptyUsage(), input: 10, totalTokens: 10 };
		assert.equal(recordUsage(ctx, [{ provider: "p", model: "m", usage }], "note"), true);
		assert.deepEqual(appended, [["security-review", "p", "m", usage, "note"]]);
		assert.equal(recordUsage({ sessionManager: {} } as never, [], "x"), false);
	});
});
