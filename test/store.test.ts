import assert from "node:assert/strict";
import { existsSync, mkdirSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import { fingerprint } from "../extensions/security-review/fingerprint.ts";
import type { Finding, RunRecord, ScopeMode } from "../extensions/security-review/schema.ts";
import {
	assertStoreTrusted,
	emptyStore,
	gitignoreHint,
	isStoreIgnored,
	loadCachedProfile,
	loadStore,
	mergeRun,
	type NewFinding,
	matchKey,
	matchStored,
	priorFalsePositives,
	projectFingerprint,
	saveProfile,
	saveStore,
	StoreError,
	storePath,
	writeRunLog,
} from "../extensions/security-review/store.ts";
import { affirm, challenge, hypothesisInput } from "./fixtures.ts";
import { commitAll, makeRepo, sh, write } from "./git-fixtures.ts";
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

	test("an incomplete full-mode run marks nothing stale and reports the skip", () => {
		const first = mergeRun(emptyStore(), { run: run("diff"), findings: [newFinding(), newFinding({ function: "gone" })], now: "t1" }).store;
		const incomplete = { ...run("full", "run-2"), complete: false, incomplete_reasons: ["hunt agent failed (timed out)"] };
		const second = mergeRun(first, { run: incomplete, findings: [newFinding()], now: "t2" });
		assert.equal(second.markedStale, 0);
		assert.equal(second.staleSkipped, true);
		assert.deepEqual(second.store.findings.map((f) => f.status), ["open", "open"]);
		assert.equal(mergeRun(first, { run: run("full", "run-3"), findings: [], now: "t3" }).staleSkipped, false);
	});

	test("default mode leaves findings outside the run untouched", () => {
		const first = mergeRun(emptyStore(), { run: run("diff"), findings: [newFinding()], now: "t1" }).store;
		const incomplete = mergeRun(first, { run: { ...run("diff", "run-1b"), complete: false }, findings: [], now: "t2" });
		assert.equal(incomplete.staleSkipped, false);
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

	test("priorFalsePositives returns only false-positive matches, including fallback matches", () => {
		const { store } = mergeRun(emptyStore(), { run: run("diff"), findings: [newFinding(), authz({ line: 10, fn: "route registration" })], now: "t1" });
		const exact = { ...hypothesisInput(), id: "H-001", fingerprint: store.findings[0]!.fingerprint };
		const reworded = { ...hypothesisInput({ vuln_type: "missing-authz", anchors: [{ file: "src/server.js", line: 13 }] }), id: "H-002", fingerprint: "other" };
		assert.equal(priorFalsePositives(store, [exact, reworded]).size, 0);
		for (const finding of store.findings) (finding as Finding).status = "false-positive";
		const priors = priorFalsePositives(store, [exact, reworded]);
		assert.equal(priors.get("H-001")?.id, "SR-001");
		assert.equal(priors.get("H-002")?.id, "SR-002");
	});
});

function authz(options: { line: number; fn?: string; sink?: string; file?: string }): NewFinding {
	const anchors = [{ file: options.file ?? "src/server.js", line: options.line, ...(options.fn ? { function: options.fn } : {}) }];
	const h = hypothesisInput({ vuln_type: "missing-authz", anchors, suspected_sink: options.sink ?? "res.json(rows) returning user rows" });
	return { ...newFinding(), fingerprint: fingerprint(h), vuln_type: "missing-authz", anchors };
}

function storedFindings(...findings: NewFinding[]): Finding[] {
	return mergeRun(emptyStore(), { run: run("diff"), findings, now: "t1" }).store.findings;
}

describe("matchStored", () => {
	test("matches by exact fingerprint", () => {
		const stored = storedFindings(newFinding(), authz({ line: 10 }));
		const matches = matchStored(stored, [matchKey(newFinding({ line: 99 }))]);
		assert.equal(matches.get(0)?.id, "SR-001");
	});

	test("falls back to an unambiguous type and primary file when line, function, and sink differ", () => {
		const stored = storedFindings(newFinding(), authz({ line: 10, fn: "app.get route registration" }));
		const moved = authz({ line: 13, sink: "users.searchUsers query returning user PII" });
		assert.notEqual(moved.fingerprint, stored[1]!.fingerprint);
		assert.equal(matchStored(stored, [matchKey(moved)]).get(0)?.id, "SR-002");
	});

	test("normalizes type synonyms and paths in the fallback", () => {
		const stored = storedFindings(authz({ line: 10, file: "src/server.js" }));
		const key = { fingerprint: "x", vuln_type: "Missing Authorization", file: "./src/server.js" };
		assert.equal(matchStored(stored, [key]).get(0)?.id, "SR-001");
	});

	test("does not fall back when two stored findings share the type and file", () => {
		const stored = storedFindings(authz({ line: 10, fn: "listUsers" }), authz({ line: 30, fn: "deleteUser" }));
		assert.equal(matchStored(stored, [matchKey(authz({ line: 50, fn: "exportUsers" }))]).size, 0);
	});

	test("does not fall back when two different observations share the type and file", () => {
		const stored = storedFindings(authz({ line: 10, fn: "listUsers" }));
		const matches = matchStored(stored, [matchKey(authz({ line: 30, fn: "deleteUser" })), matchKey(authz({ line: 50, fn: "exportUsers" }))]);
		assert.equal(matches.size, 0);
	});

	test("a stored finding taken by an exact match is not a fallback candidate", () => {
		const stored = storedFindings(authz({ line: 10, fn: "listUsers" }));
		const exact = authz({ line: 12, fn: "listUsers" });
		const other = authz({ line: 40, fn: "deleteUser" });
		const matches = matchStored(stored, [matchKey(exact), matchKey(other)]);
		assert.equal(matches.get(0)?.id, "SR-001");
		assert.equal(matches.has(1), false);
	});
});

describe("mergeRun fallback matching", () => {
	test("a re-observation described differently keeps id, first_seen, and status, and takes the new fingerprint", () => {
		const first = mergeRun(emptyStore(), { run: run("diff"), findings: [authz({ line: 10, fn: "app.get route registration" })], now: "t1" }).store;
		first.findings[0]!.status = "false-positive";
		const moved = authz({ line: 13, fn: "searchUsers", sink: "db.query in searchUsers" });
		const { store, added, updated } = mergeRun(first, { run: run("diff", "run-2"), findings: [moved], now: "t2" });
		assert.deepEqual([added, updated, store.findings.length], [0, 1, 1]);
		const finding = store.findings[0]!;
		assert.deepEqual([finding.id, finding.status, finding.first_seen, finding.last_seen], ["SR-001", "false-positive", "t1", "t2"]);
		assert.equal(finding.anchors[0]!.line, 13);
		assert.equal(finding.fingerprint, moved.fingerprint);
	});

	test("a stale finding matched by the fallback is reopened", () => {
		const first = mergeRun(emptyStore(), { run: run("diff"), findings: [authz({ line: 10 })], now: "t1" }).store;
		first.findings[0]!.status = "stale";
		const { store } = mergeRun(first, { run: run("full", "run-2"), findings: [authz({ line: 11, fn: "searchUsers" })], now: "t2" });
		assert.deepEqual(store.findings.map((f) => [f.id, f.status]), [["SR-001", "open"]]);
	});

	test("re-observation replaces consequences, and clears them when the new observation has none", () => {
		const consequence = { vuln_type: "secret-disclosure", description: "d", anchors: [{ file: "src/users.ts", line: 12 }] };
		const first = mergeRun(emptyStore(), { run: run("diff"), findings: [newFinding({ consequences: [consequence] })], now: "t1" }).store;
		const replaced = mergeRun(first, { run: run("diff", "run-2"), findings: [newFinding({ consequences: [{ ...consequence, vuln_type: "idor" }] })], now: "t2" }).store;
		assert.deepEqual(replaced.findings[0]!.consequences!.map((c) => c.vuln_type), ["idor"]);
		const cleared = mergeRun(replaced, { run: run("diff", "run-3"), findings: [newFinding()], now: "t3" }).store;
		assert.equal("consequences" in cleared.findings[0]!, false);
	});

	test("re-observation without CWE or CVSS clears the old values but keeps introduced_in and user fields", () => {
		const first = mergeRun(emptyStore(), {
			run: run("diff"),
			findings: [newFinding({ cwe: "CWE-89", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", cvss_score: 7.5, introduced_in: "abc123" })],
			now: "t1",
		}).store;
		(first.findings[0] as Finding & { note?: string }).note = "tracked in JIRA-1";
		const incoming = newFinding();
		delete incoming.cwe;
		delete incoming.cvss_vector;
		delete incoming.cvss_score;
		delete incoming.introduced_in;
		const second = mergeRun(first, { run: run("diff", "run-2"), findings: [incoming], now: "t2" }).store.findings[0]!;
		for (const field of ["cwe", "cvss_vector", "cvss_score"]) assert.equal(field in second, false, field);
		assert.equal(second.introduced_in, "abc123");
		assert.equal((second as Finding & { note?: string }).note, "tracked in JIRA-1");
		const third = mergeRun({ ...emptyStore(), findings: [second] }, { run: run("diff", "run-3"), findings: [newFinding({ cwe: "CWE-200", cvss_score: 5.3 })], now: "t3" }).store.findings[0]!;
		assert.equal(third.cwe, "CWE-200");
		assert.equal(third.cvss_score, 5.3);
	});

	test("an ambiguous observation becomes a new finding", () => {
		const first = mergeRun(emptyStore(), { run: run("diff"), findings: [authz({ line: 10, fn: "listUsers" }), authz({ line: 30, fn: "deleteUser" })], now: "t1" }).store;
		const { store, added } = mergeRun(first, { run: run("diff", "run-2"), findings: [authz({ line: 50, fn: "exportUsers" })], now: "t2" });
		assert.equal(added, 1);
		assert.deepEqual(store.findings.map((f) => f.id), ["SR-001", "SR-002", "SR-003"]);
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

describe("store trust", () => {
	const FINDINGS = ".security-review/findings.json";
	const mergeBase = (root: string) => sh(root, "merge-base", "main", "HEAD").trim();

	test("an untracked store is trusted", async () => {
		const root = makeRepo();
		sh(root, "checkout", "-q", "-b", "feature");
		saveStore(root, emptyStore());
		await assertStoreTrusted({ root, mergeBase: mergeBase(root) });
	});

	test("a tracked store changed by commits on the branch is refused in both modes", async () => {
		const root = makeRepo();
		sh(root, "checkout", "-q", "-b", "feature");
		saveStore(root, emptyStore());
		saveProfile(root, "fp", { summary: "s", stack: ["js"], entry_points: [], trust_boundaries: [], auth_model: "none", external_inputs: [] }, "now");
		sh(root, "add", "-f", ".security-review");
		commitAll(root, "add a store");
		for (const scope of [{ root, mergeBase: mergeBase(root) }, { root }]) {
			await assert.rejects(assertStoreTrusted(scope), (error: unknown) => {
				assert.ok(error instanceof StoreError);
				assert.match(error.message, /findings\.json and \.security-review\/profile\.json are tracked by git and changed by commits on this branch/);
				return true;
			});
		}
	});

	test("a tracked store from the default branch stays trusted, including local edits", async () => {
		const root = makeRepo();
		saveStore(root, emptyStore());
		sh(root, "add", "-f", FINDINGS);
		commitAll(root, "track the store");
		sh(root, "checkout", "-q", "-b", "feature");
		write(root, "src/a.ts", "1\n");
		commitAll(root, "feature work");
		// The extension's own uncommitted update of the store.
		saveStore(root, { ...emptyStore(), gitignore_hint_shown: true });
		await assertStoreTrusted({ root, mergeBase: mergeBase(root) });
		await assertStoreTrusted({ root });
	});

	test("a store directory that is a symbolic link is refused before it is read or written", async () => {
		const root = makeRepo();
		const target = tempDir("sr-target-");
		writeFileSync(join(target, "findings.json"), JSON.stringify(emptyStore()));
		symlinkSync(target, join(root, ".security-review"));
		sh(root, "add", ".security-review");
		commitAll(root, "store as a link");
		const refused = (error: unknown) => error instanceof StoreError && /\.security-review is a symbolic link/.test(error.message);
		await assert.rejects(assertStoreTrusted({ root }), refused);
		assert.throws(() => loadStore(root), refused);
		assert.throws(() => loadCachedProfile(root, "fp"), refused);
		assert.throws(() => saveStore(root, emptyStore()), refused);
		assert.deepEqual(readdirSync(target), ["findings.json"]);
	});

	test("store files and the runs directory that are symbolic links are refused", async () => {
		const root = makeRepo({ "docs/fixtures/findings.json": JSON.stringify(emptyStore()) });
		mkdirSync(join(root, ".security-review"));
		symlinkSync("../docs/fixtures/findings.json", join(root, FINDINGS));
		await assert.rejects(assertStoreTrusted({ root }), /findings\.json is a symbolic link/);
		assert.throws(() => loadStore(root), /findings\.json is a symbolic link/);

		const other = makeRepo();
		const target = tempDir("sr-target-");
		mkdirSync(join(other, ".security-review"));
		symlinkSync(target, join(other, ".security-review", "runs"));
		assert.throws(() => writeRunLog(other, { ...run("diff"), finding_ids: [] }), /runs is a symbolic link/);
		assert.deepEqual(readdirSync(target), []);
	});

	test("a tracked store is trusted when there is no default branch to compare with", async () => {
		const root = makeRepo();
		sh(root, "branch", "-m", "main", "trunk");
		saveStore(root, emptyStore());
		sh(root, "add", "-f", FINDINGS);
		commitAll(root, "track the store");
		await assertStoreTrusted({ root });
	});
});

describe("gitignore hint", () => {
	test("recommends ignoring once when the directory is not ignored", async () => {
		const root = makeRepo();
		const first = gitignoreHint(emptyStore(), await isStoreIgnored(root));
		assert.match(first.hint!, /\.security-review\/.*\.gitignore/);
		assert.equal(first.store.gitignore_hint_shown, true);
		const second = gitignoreHint(first.store, await isStoreIgnored(root));
		assert.equal(second.hint, undefined);
	});

	test("shows nothing when the directory is ignored", async () => {
		for (const pattern of [".security-review/", ".security-review", "/.security-review/*"]) {
			const root = makeRepo({ ".gitignore": `${pattern}\n` });
			const { hint, store } = gitignoreHint(emptyStore(), await isStoreIgnored(root));
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
