import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tempDir } from "./temp.ts";

const GIT_ENV = {
	...process.env,
	GIT_AUTHOR_NAME: "Test",
	GIT_AUTHOR_EMAIL: "test@example.com",
	GIT_COMMITTER_NAME: "Test",
	GIT_COMMITTER_EMAIL: "test@example.com",
	GIT_CONFIG_GLOBAL: "/dev/null",
	GIT_CONFIG_NOSYSTEM: "1",
};

export function sh(cwd: string, ...args: string[]): string {
	return execFileSync("git", args, { cwd, env: GIT_ENV, encoding: "utf8" });
}

export function write(root: string, file: string, content: string): void {
	mkdirSync(dirname(join(root, file)), { recursive: true });
	writeFileSync(join(root, file), content);
}

/** A repository on `main` with one commit containing `files`. */
export function makeRepo(files: Record<string, string> = { "README.md": "# fixture\n" }): string {
	const root = tempDir("sr-repo-");
	sh(root, "init", "-q", "-b", "main");
	for (const [file, content] of Object.entries(files)) write(root, file, content);
	sh(root, "add", "-A");
	sh(root, "commit", "-q", "-m", "initial");
	return root;
}

export function commitAll(root: string, message: string): void {
	sh(root, "add", "-A");
	sh(root, "commit", "-q", "-m", message);
}

/** A bare clone acting as `origin`, with origin/HEAD set. Returns the clone's path. */
export function cloneWithOrigin(source: string): string {
	const bare = tempDir("sr-origin-");
	sh(bare, "clone", "-q", "--bare", source, bare);
	const clone = tempDir("sr-clone-");
	sh(clone, "clone", "-q", bare, clone);
	return clone;
}

const FIXTURE_DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "vulnerable-app");

function copyTree(from: string, to: string): void {
	cpSync(from, to, { recursive: true });
}

/**
 * The vulnerable-app fixture as a git repository: `base/` committed on `main`, then a `feature`
 * branch (checked out) that adds the seeded SQL injection.
 */
export function makeFixtureRepo(): string {
	const root = tempDir("sr-app-");
	sh(root, "init", "-q", "-b", "main");
	copyTree(join(FIXTURE_DIR, "base"), root);
	commitAll(root, "base app");
	sh(root, "checkout", "-q", "-b", "feature");
	copyTree(join(FIXTURE_DIR, "feature"), root);
	commitAll(root, "add user search");
	return root;
}
