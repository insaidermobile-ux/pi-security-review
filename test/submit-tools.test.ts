import assert from "node:assert/strict";
import { symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import { checkAnchors, createTriageTool, type TriageCollector } from "../extensions/security-review/submit-tools.ts";
import { runTool } from "./faux.ts";
import { makeRepo } from "./git-fixtures.ts";
import { tempDir } from "./temp.ts";

describe("anchor checks", () => {
	test("refuse a file reached through a symbolic link that leaves the project, without revealing it", () => {
		const repo = makeRepo({ "src/a.ts": "1\n2\n" });
		const outside = tempDir("sr-outside-");
		writeFileSync(join(outside, "secret.txt"), "S\n".repeat(50));
		symlinkSync(outside, join(repo, "vendor"));
		symlinkSync(join(outside, "missing.txt"), join(repo, "src/dangling.txt"));
		for (const file of ["vendor/secret.txt", "vendor/missing.txt", "src/dangling.txt"]) {
			assert.throws(() => checkAnchors(repo, [{ file, line: 999_999 }]), /is outside the project\.$/);
		}
		assert.deepEqual(checkAnchors(repo, [{ file: "./src/a.ts", line: 2 }]), [{ file: "src/a.ts", line: 2 }]);
	});

	test("refuse a file name with control characters", () => {
		const repo = makeRepo({ "src/a.ts": "1\n" });
		const name = "src/a\u001b]8;;evil.example\u0007ok.ts";
		writeFileSync(join(repo, name), "1\n");
		assert.throws(() => checkAnchors(repo, [{ file: name, line: 1 }]), /control characters/);
	});
});

describe("triage tool", () => {
	const labels = ["C-1", "C-2", "C-3"];
	async function submitTriage(groups: unknown): Promise<{ text: string; collector: TriageCollector; terminate?: boolean }> {
		const collector: TriageCollector = {};
		const tool = createTriageTool(labels, collector);
		try {
			const result = await runTool(tool, { groups } as never);
			const content = result.content[0];
			return { text: content?.type === "text" ? content.text : "", collector, terminate: (result as { terminate?: boolean }).terminate };
		} catch (error) {
			return { text: (error as Error).message, collector };
		}
	}

	const cases: [string, unknown, RegExp][] = [
		["unknown label", [{ primary: "C-1", members: ["C-1", "C-9"], reason: "r" }], /unknown candidates: C-9\. Known candidates are C-1, C-2, C-3/],
		["label in two groups", [{ primary: "C-1", members: ["C-1", "C-2"], reason: "r" }, { primary: "C-3", members: ["C-3", "C-2"], reason: "r" }], /C-2 appears in group 1 and group 2/],
		["single member", [{ primary: "C-1", members: ["C-1", "C-1"], reason: "r" }], /fewer than two distinct members/],
		["primary outside its group", [{ primary: "C-3", members: ["C-1", "C-2"], reason: "r" }], /primary C-3 must be one of its members/],
	];
	for (const [name, groups, pattern] of cases) {
		test(`rejects ${name} and records nothing`, async () => {
			const { text, collector } = await submitTriage(groups);
			assert.match(text, pattern);
			assert.match(text, /call submit_triage again/);
			assert.equal(collector.groups, undefined);
		});
	}

	test("accepts a valid grouping and an empty list, and terminates", async () => {
		const valid = await submitTriage([{ primary: "C-2", members: ["C-1", "C-2"], reason: "same query" }]);
		assert.match(valid.text, /Triage recorded \(1 groups\)/);
		assert.equal(valid.terminate, true);
		assert.deepEqual(valid.collector.groups?.[0]?.members, ["C-1", "C-2"]);
		const empty = await submitTriage([]);
		assert.deepEqual(empty.collector.groups, []);
	});
});
