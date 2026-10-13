import assert from "node:assert/strict";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import { fingerprint } from "../extensions/security-review/fingerprint.ts";
import type { Finding, RunRecord, ScopeMode } from "../extensions/security-review/schema.ts";
import {
	emptyStore,
	gitignoreHint,
	loadCachedProfile,
	loadStore,
	mergeRun,
	type NewFinding,
	priorFalsePositive,
	projectFingerprint,
	saveProfile,
	saveStore,
	StoreError,
	storePath,
} from "../extensions/security-review/store.ts";
import { affirm, challenge, hypothesisInput } from "./fixtures.ts";
import { commitAll, makeRepo, write } from "./git-fixtures.ts";
import { tempDir } from "./temp.ts";

function newFinding(overrides: Partial<NewFinding> & { function?: string; line?: number } = {}): NewFinding {
	const { function: fn = "searchUsers", line = 12, ...rest } = overrides;
	const anchors = [{ file: "src/users.ts", line, function: fn }];
	const h = hypothesisInput({ anchors });
	return {
		fingerprint: fingerprint(h),
		title: "User search endpoint: sql injection leading to data exposure",
		finding_class: "vulnerability",
		vuln_type: h.vuln_type,
		severity: "high",
		confidence: "high",
		anchors,
		data_flow: affirm("H-001").attack_path,
		description: affirm("H-001").description,
		verification: { affirmer: affirm("H-001"), challenger: challenge("H-001", "confirmed"), verdict: "confirmed" },
		remediation: affirm("H-001").remediation,
		scope: "diff",
		...rest,
	};
}

function run(mode: ScopeMode, id = "run-1"): Omit<RunRecord, "finding_ids"> {
	return { id, mode, started_at: "t0", finished_at: "t1", files: 3, complete: true, incomplete_reasons: [], refuted: [], unverified: [], errors: [] };
}

function tempRoot(): string {
	return tempDir("sr-store-");
}

describe("store persistence", () => {
	test("missing store loads as empty and saving creates the directory", () => {
		const root = tempRoot();
		assert.deepEqual(loadStore(root), emptyStore());
		saveStore(root, emptyStore());
		assert.ok(existsSync(storePath(root)));
		assert.deepEqual(loadStore(root), emptyStore());
	});

	test("an interrupted write leaves the previous store parseable and no temp files", () => {
		const root = tempRoot();
		const before = mergeRun(emptyStore(), { run: run("diff"), findings: [newFinding()], now: "2026-01-01" }).store;
		saveStore(root, before);
		const after = mergeRun(before, { run: run("diff", "run-2"), findings: [newFinding({ function: "other" })], now: "2026-01-02" }).store;
		assert.throws(
			() =>
				saveStore(root, after, {
					beforeRename: () => {
						throw new Error("simulated crash");
					},
				}),
			/simulated crash/,
		);
		assert.deepEqual(loadStore(root), before);
		assert.deepEqual(readdirSync(join(root, ".security-review")), ["findings.json"]);
	});

	test("refuses to load an invalid store instead of overwriting it", () => {
		const root = tempRoot();
		mkdirSync(join(root, ".security-review"));
		writeFileSync(storePath(root), "{ not json");
		assert.throws(() => loadStore(root), StoreError);
		writeFileSync(storePath(root), JSON.stringify({ version: 1, findings: "nope" }));
		assert.throws(() => loadStore(root), /does not match the findings store schema/);
	});
});

describe("mergeRun", () => {
	test("adds new findings with sequential ids and open status", () => {
		const { store, added, observed } = mergeRun(emptyStore(), {
			run: run("diff"),
			findings: [newFinding(), newFinding({ function: "other" })],
			now: "2026-01-01",
		});
		assert.equal(added, 2);
		assert.deepEqual(store.findings.map((f) => [f.id, f.status, f.first_seen]), [
			["SR-001", "open", "2026-01-01"],
			["SR-002", "open", "2026-01-01"],
		]);
		assert.deepEqual(store.runs[0]!.finding_ids, ["SR-001", "SR-002"]);
		assert.equal(observed.length, 2);
	});

	test("re-observed finding keeps id and first_seen and refreshes anchors, verification, last_seen", () => {
		const first = mergeRun(emptyStore(), { run: run("diff"), findings: [newFinding()], now: "2026-01-01" }).store;
		const moved = newFinding({ line: 60, confidence: "medium" });
		const { store, added, updated } = mergeRun(first, { run: run("diff", "run-2"), findings: [moved], now: "2026-02-01" });
		assert.equal(added, 0);
		assert.equal(updated, 1);
		assert.equal(store.findings.length, 1);
		const finding = store.findings[0]!;
		assert.equal(finding.id, "SR-001");
		assert.equal(finding.first_seen, "2026-01-01");
		assert.equal(finding.last_seen, "2026-02-01");
		assert.equal(finding.anchors[0]!.line, 60);
		assert.equal(finding.confidence, "medium");
	});

	for (const status of ["false-positive", "accepted-risk", "fixed"] as const) {
		test(`user status ${status} survives re-observation`, () => {
			const first = mergeRun(emptyStore(), { run: run("diff"), findings: [newFinding()], now: "t1" }).store;
			first.findings[0]!.status = status;
			const { store } = mergeRun(first, { run: run("full", "run-2"), findings: [newFinding()], now: "t2" });
			assert.equal(store.findings[0]!.status, status);
		});
	}

	test("full mode marks open findings that were not re-observed as stale", () => {
		const first = mergeRun(emptyStore(), { run: run("diff"), findings: [newFinding(), newFinding({ function: "gone" })], now: "t1" }).store;
		first.findings[1]!.status = "accepted-risk";
		const second = mergeRun(first, { run: run("full", "run-2"), findings: [], now: "t2" });
		assert.equal(second.markedStale, 1);
		assert.deepEqual(second.store.findings.map((f) => f.status), ["stale", "accepted-risk"]);
		const third = mergeRun(second.store, { run: run("full", "run-3"), findings: [newFinding()], now: "t3" });
		assert.equal(third.store.findings[0]!.status, "open");
	});

	test("default mode leaves findings outside the run untouched", () => {
		const first = mergeRun(emptyStore(), { run: run("diff"), findings: [newFinding()], now: "t1" }).store;
		const { store, markedStale } = mergeRun(first, { run: run("diff", "run-2"), findings: [], now: "t2" });
		assert.equal(markedStale, 0);
		assert.deepEqual(store.findings, first.findings);
	});

	test("records refuted hypotheses per run and caps stored runs", () => {
		let store = emptyStore();
		const h = { ...hypothesisInput(), id: "H-001", source_partition: "injection", fingerprint: "abc" };
		for (let i = 0; i < 25; i++) {
			store = mergeRun(store, {
				run: { ...run("diff", `run-${i}`), refuted: [{ hypothesis: h, affirmer: affirm("H-001"), challenger: challenge("H-001", "refuted") }] },
				findings: [],
				now: `t${i}`,
			}).store;
		}
		assert.equal(store.runs.length, 20);
		assert.equal(store.runs.at(-1)!.id, "run-24");
		assert.equal(store.runs.at(-1)!.refuted[0]!.challenger.reasoning, "A defense blocks the path.");
	});

	test("stored findings validate against the store schema after merge", () => {
		const root = tempRoot();
		const { store } = mergeRun(emptyStore(), { run: run("diff"), findings: [newFinding({ introduced_in: "abc123" })], now: "t1" });
		saveStore(root, store);
		assert.equal(loadStore(root).findings[0]!.introduced_in, "abc123");
	});

	test("priorFalsePositive finds only false-positive findings by fingerprint", () => {
		const { store } = mergeRun(emptyStore(), { run: run("diff"), findings: [newFinding()], now: "t1" });
		const fp = store.findings[0]!.fingerprint;
		assert.equal(priorFalsePositive(store, fp), undefined);
		(store.findings[0] as Finding).status = "false-positive";
		assert.equal(priorFalsePositive(store, fp)?.id, "SR-001");
	});
});

describe("profile cache", () => {
	const profile = {
		summary: "API",
		stack: ["typescript"],
		entry_points: [],
		trust_boundaries: [],
		auth_model: "none",
		external_inputs: [],
	};

	test("hits on an unchanged project fingerprint and misses after a manifest change", async () => {
		const root = makeRepo({ "package.json": '{"name":"a"}', "src/a.ts": "1\n" });
		const fp = await projectFingerprint(root);
		saveProfile(root, fp, profile, "t1");
		assert.deepEqual(loadCachedProfile(root, await projectFingerprint(root)), profile);

		write(root, "src/b.ts", "2\n");
		assert.equal(await projectFingerprint(root), fp, "files inside an existing top-level directory do not change the fingerprint");

		write(root, "package.json", '{"name":"a","dependencies":{"x":"1"}}');
		const changed = await projectFingerprint(root);
		assert.notEqual(changed, fp);
		assert.equal(loadCachedProfile(root, changed), undefined);
	});

	test("misses after a new top-level directory appears", async () => {
		const root = makeRepo({ "src/a.ts": "1\n" });
		const fp = await projectFingerprint(root);
		write(root, "server/index.ts", "1\n");
		commitAll(root, "server");
		assert.notEqual(await projectFingerprint(root), fp);
	});
});

describe("gitignore hint", () => {
	test("recommends ignoring once when the directory is not ignored", async () => {
		const root = makeRepo();
		const first = await gitignoreHint(root, emptyStore());
		assert.match(first.hint!, /\.security-review\/.*\.gitignore/);
		assert.equal(first.store.gitignore_hint_shown, true);
		const second = await gitignoreHint(root, first.store);
		assert.equal(second.hint, undefined);
	});

	test("shows nothing when the directory is ignored", async () => {
		for (const pattern of [".security-review/", ".security-review", "/.security-review/*"]) {
			const root = makeRepo({ ".gitignore": `${pattern}\n` });
			const { hint, store } = await gitignoreHint(root, emptyStore());
			assert.equal(hint, undefined, pattern);
			assert.equal(store.gitignore_hint_shown, false);
		}
	});

	test("the store directory is never staged", async () => {
		const root = makeRepo();
		saveStore(root, emptyStore());
		assert.ok(existsSync(storePath(root)));
		assert.equal(readFileSync(join(root, ".git", "index")).includes(Buffer.from(".security-review")), false);
	});
});
