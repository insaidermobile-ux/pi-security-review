import assert from "node:assert/strict";
import { join } from "node:path";
import { describe, test } from "node:test";
import { introducedIn, isExcluded, resolveBaseRef, resolveScope, ScopeError } from "../extensions/security-review/scope.ts";
import { cloneWithOrigin, commitAll, makeRepo, sh, write } from "./git-fixtures.ts";
import { tempDir } from "./temp.ts";

async function rejectsWith(promise: Promise<unknown>, code: string, pattern: RegExp) {
	await assert.rejects(promise, (error: unknown) => {
		assert.ok(error instanceof ScopeError);
		assert.equal(error.code, code);
		assert.match(error.message, pattern);
		return true;
	});
}

describe("base reference resolution", () => {
	test("uses the branch origin/HEAD points to", async () => {
		const clone = cloneWithOrigin(makeRepo());
		assert.equal(await resolveBaseRef(clone), "origin/main");
	});

	test("falls back to local main without a remote", async () => {
		assert.equal(await resolveBaseRef(makeRepo()), "main");
	});

	test("falls back to local master", async () => {
		const root = makeRepo();
		sh(root, "branch", "-m", "main", "master");
		assert.equal(await resolveBaseRef(root), "master");
	});

	test("reports every reference tried when no candidate exists", async () => {
		const root = makeRepo();
		sh(root, "branch", "-m", "main", "trunk");
		await rejectsWith(resolveBaseRef(root), "no-base", /origin\/HEAD, origin\/main, origin\/master, main, master.*\/security-review full/s);
	});
});

describe("default (diff) scope", () => {
	test("includes committed, unstaged, and untracked files and skips ignored ones", async () => {
		const root = makeRepo({ "README.md": "x\n", ".gitignore": "secret.env\n", "src/old.ts": "export const a = 1;\n" });
		sh(root, "checkout", "-q", "-b", "feature");
		write(root, "src/committed.ts", "export const b = 2;\n");
		commitAll(root, "feature work");
		write(root, "src/old.ts", "export const a = 3;\n");
		write(root, "src/new.ts", "export const c = 4;\n");
		write(root, "secret.env", "TOKEN=1\n");
		const scope = await resolveScope(root, "diff");
		assert.equal(scope.baseRef, "main");
		assert.deepEqual(scope.files, ["src/committed.ts", "src/new.ts", "src/old.ts"]);
		assert.deepEqual(scope.untracked, ["src/new.ts"]);
		assert.match(scope.diff!, /src\/committed\.ts/);
		assert.match(scope.diff!, /export const a = 3/);
	});

	test("skips files deleted on the branch", async () => {
		const root = makeRepo({ "a.ts": "1\n", "b.ts": "2\n" });
		sh(root, "checkout", "-q", "-b", "feature");
		sh(root, "rm", "-q", "a.ts");
		write(root, "b.ts", "3\n");
		commitAll(root, "delete a");
		assert.deepEqual((await resolveScope(root, "diff")).files, ["b.ts"]);
	});

	test("applies exclude patterns", async () => {
		const root = makeRepo();
		sh(root, "checkout", "-q", "-b", "feature");
		write(root, "vendor/lib/x.js", "1\n");
		write(root, "src/app.ts", "1\n");
		commitAll(root, "add");
		assert.deepEqual((await resolveScope(root, "diff", { exclude: ["vendor"] })).files, ["src/app.ts"]);
	});

	test("stops with a full-mode suggestion on a clean default branch", async () => {
		await rejectsWith(resolveScope(makeRepo(), "diff"), "empty", /no unmerged changes.*\/security-review full/s);
	});

	test("works from a subdirectory and against origin", async () => {
		const clone = cloneWithOrigin(makeRepo({ "src/a.ts": "1\n" }));
		write(clone, "src/a.ts", "2\n");
		const scope = await resolveScope(join(clone, "src"), "diff");
		assert.equal(scope.baseRef, "origin/main");
		assert.deepEqual(scope.files, ["src/a.ts"]);
	});

	test("reports the commit that introduced a file", async () => {
		const root = makeRepo();
		sh(root, "checkout", "-q", "-b", "feature");
		write(root, "src/a.ts", "1\n");
		commitAll(root, "add a");
		const sha = sh(root, "rev-parse", "HEAD").trim();
		write(root, "src/b.ts", "1\n");
		const scope = await resolveScope(root, "diff");
		assert.equal(await introducedIn(scope, "src/a.ts"), sha);
		assert.equal(await introducedIn(scope, "src/b.ts"), "uncommitted");
	});
});

describe("full scope", () => {
	test("lists tracked and untracked non-ignored files minus excludes", async () => {
		const root = makeRepo({ "README.md": "x\n", ".gitignore": "dist/\n", "src/a.ts": "1\n", "vendor/v.js": "1\n" });
		write(root, "src/untracked.ts", "1\n");
		write(root, "dist/out.js", "1\n");
		const scope = await resolveScope(root, "full", { exclude: ["vendor/**", "*.md"] });
		assert.deepEqual(scope.files, [".gitignore", "src/a.ts", "src/untracked.ts"]);
		assert.equal(scope.diff, undefined);
	});
});

describe("preconditions", () => {
	test("fails outside a git work tree with an explanation", async () => {
		const dir = tempDir("sr-nogit-");
		await rejectsWith(resolveScope(dir, "diff"), "not-a-repo", /needs a git repository/);
		await rejectsWith(resolveScope(dir, "full"), "not-a-repo", /needs a git repository/);
	});
});

describe("isExcluded", () => {
	test("supports globs, directory names, and basename patterns", () => {
		assert.ok(isExcluded("vendor/a/b.js", ["vendor/**"]));
		assert.ok(isExcluded("vendor/a/b.js", ["vendor/"]));
		assert.ok(isExcluded("pkg/node_modules/x/index.js", ["node_modules"]));
		assert.ok(isExcluded("web/app.min.js", ["*.min.js"]));
		assert.ok(!isExcluded("src/vendors.ts", ["vendor"]));
	});
});

describe("store directory", () => {
	test("is never part of the audited scope", async () => {
		const root = makeRepo();
		sh(root, "checkout", "-q", "-b", "feature");
		write(root, ".security-review/findings.json", "{}");
		write(root, "src/a.ts", "1\n");
		assert.deepEqual((await resolveScope(root, "diff")).files, ["src/a.ts"]);
		assert.deepEqual((await resolveScope(root, "full")).files, ["README.md", "src/a.ts"]);
	});
});
