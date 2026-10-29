import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { fingerprint } from "../extensions/security-review/fingerprint.ts";
import { applyHypothesisCap, applyTriageGroups, candidateLabel, huntAssignments, mergeDuplicateHypotheses, subtreePartitions, VULN_CLASSES } from "../extensions/security-review/partition.ts";
import { resolveScope } from "../extensions/security-review/scope.ts";
import { DISCLOSURE, RATE_LIMIT, SQLI, TRAVERSAL } from "./fixtures.ts";
import { makeFixtureRepo } from "./git-fixtures.ts";

describe("hunt partitioning", () => {
	test("default mode partitions by vulnerability class over the whole scope", async () => {
		const scope = await resolveScope(makeFixtureRepo(), "diff");
		const assignments = huntAssignments(scope);
		assert.deepEqual(assignments.map((a) => a.label), VULN_CLASSES.map((c) => c.id));
		assert.deepEqual(assignments.map((a) => a.label), [
			"injection",
			"access-control",
			"secrets-crypto",
			"files-deserialization",
			"network-ssrf",
			"logic-concurrency",
			"feature-abuse",
			"wildcard",
		]);
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

	test("full mode splits through directory levels that have a single child", () => {
		const maven = Array.from({ length: 1900 }, (_, i) => `src/main/java/com/acme/app/mod${i % 30}/File${i}.java`);
		const groups = subtreePartitions([...maven, "pom.xml", "README.md"]);
		assert.ok(groups.length > 1 && groups.length <= 12, `${groups.length} groups`);
		assert.ok(Math.max(...groups.map((g) => g.files.length)) <= 400, groups.map((g) => `${g.label}:${g.files.length}`).join(", "));
		assert.deepEqual(groups.flatMap((g) => g.files).sort(), [...maven, "pom.xml", "README.md"].sort());

		const angular = Array.from({ length: 900 }, (_, i) => `src/app/feature${i % 20}/c${i}.ts`);
		assert.ok(subtreePartitions(angular).length > 1);
		// Files in a single directory cannot be split further.
		const flat = Array.from({ length: 400 }, (_, i) => `a/b/c/f${i}.ts`);
		assert.deepEqual(subtreePartitions(flat).map((g) => g.files.length), [400]);
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
