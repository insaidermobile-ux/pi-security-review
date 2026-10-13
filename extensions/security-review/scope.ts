import { execFile } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { join, posix } from "node:path";
import type { ScopeMode } from "./schema.ts";

/** The extension's own output directory; never part of the audited scope. */
export const STORE_DIR = ".security-review";

export const BASE_CANDIDATES = ["origin/HEAD", "origin/main", "origin/master", "main", "master"] as const;

/** Diff text handed to agents is capped; agents read files directly for anything beyond it. */
export const MAX_DIFF_BYTES = 200_000;

export type ScopeErrorCode = "not-a-repo" | "no-base" | "git-failed" | "empty";

export class ScopeError extends Error {
	readonly code: ScopeErrorCode;
	constructor(code: ScopeErrorCode, message: string) {
		super(message);
		this.name = "ScopeError";
		this.code = code;
	}
}

export interface Scope {
	mode: ScopeMode;
	/** Absolute path of the git work tree root; all file paths are relative to it. */
	root: string;
	files: string[];
	/** Diff mode only. */
	baseRef?: string;
	mergeBase?: string;
	diff?: string;
	diffTruncated?: boolean;
	untracked?: string[];
}

interface GitResult {
	code: number;
	stdout: string;
	stderr: string;
}

export function git(cwd: string, args: string[]): Promise<GitResult> {
	return new Promise((resolve) => {
		execFile(
			"git",
			["-c", "core.quotepath=off", ...args],
			{ cwd, maxBuffer: 256 * 1024 * 1024, env: { ...process.env, GIT_OPTIONAL_LOCKS: "0", GIT_TERMINAL_PROMPT: "0" } },
			(error, stdout, stderr) => {
				const code = error ? (typeof error.code === "number" ? error.code : 1) : 0;
				resolve({ code, stdout: stdout.toString(), stderr: stderr.toString() });
			},
		);
	});
}

async function gitOk(cwd: string, args: string[], what: string): Promise<string> {
	const result = await git(cwd, args);
	if (result.code !== 0) {
		throw new ScopeError("git-failed", `${what} failed: git ${args.join(" ")}\n${result.stderr.trim()}`);
	}
	return result.stdout;
}

function splitZ(output: string): string[] {
	return output.split("\0").filter((entry) => entry.length > 0);
}

export async function findRepoRoot(cwd: string): Promise<string> {
	const result = await git(cwd, ["rev-parse", "--show-toplevel"]);
	if (result.code !== 0 || !result.stdout.trim()) {
		throw new ScopeError(
			"not-a-repo",
			`/security-review needs a git repository, but ${cwd} is not inside a git work tree. Run it from your repository, or run \`git init\` first.`,
		);
	}
	return result.stdout.trim();
}

/** First existing base candidate, in order. `origin/HEAD` is reported as the branch it points to. */
export async function resolveBaseRef(root: string): Promise<string> {
	for (const candidate of BASE_CANDIDATES) {
		const ref = candidate.includes("/") ? `refs/remotes/${candidate}` : `refs/heads/${candidate}`;
		const exists = await git(root, ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`]);
		if (exists.code !== 0) continue;
		if (candidate === "origin/HEAD") {
			const target = await git(root, ["symbolic-ref", "--short", "refs/remotes/origin/HEAD"]);
			if (target.code === 0 && target.stdout.trim()) return target.stdout.trim();
		}
		return candidate;
	}
	throw new ScopeError(
		"no-base",
		`Could not find a base branch to compare against. Tried: ${BASE_CANDIDATES.join(", ")}. ` +
			"If you have a remote, run `git remote set-head origin --auto`. To audit the whole project instead, run /security-review full.",
	);
}

/**
 * Whether `file` matches an exclude pattern. A pattern without a slash also matches by basename at any
 * depth, and a pattern naming a directory matches everything below it.
 */
export function isExcluded(file: string, patterns: readonly string[]): boolean {
	for (const raw of patterns) {
		const pattern = raw.replace(/^\.\//, "").replace(/\/+$/, "");
		if (posix.matchesGlob(file, pattern) || posix.matchesGlob(file, `${pattern}/**`)) return true;
		if (!pattern.includes("/") && (posix.matchesGlob(file, `**/${pattern}`) || posix.matchesGlob(file, `**/${pattern}/**`))) return true;
	}
	return false;
}

function isAuditableFile(root: string, file: string): boolean {
	const full = join(root, file);
	if (!existsSync(full)) return false;
	try {
		return statSync(full).isFile();
	} catch {
		return false;
	}
}

function finalize(root: string, files: Iterable<string>, exclude: readonly string[]): string[] {
	const excluded = [...exclude, `${STORE_DIR}/**`];
	return [...new Set(files)].filter((file) => !isExcluded(file, excluded) && isAuditableFile(root, file)).sort();
}

export interface ResolveScopeOptions {
	exclude?: readonly string[];
}

export async function resolveScope(cwd: string, mode: ScopeMode, options: ResolveScopeOptions = {}): Promise<Scope> {
	const exclude = options.exclude ?? [];
	const root = await findRepoRoot(cwd);

	if (mode === "full") {
		const listed = splitZ(await gitOk(root, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], "Listing project files"));
		const files = finalize(root, listed, exclude);
		if (files.length === 0) throw new ScopeError("empty", "There are no files to audit in this project after applying excludes.");
		return { mode, root, files };
	}

	const baseRef = await resolveBaseRef(root);
	const mergeBaseResult = await git(root, ["merge-base", baseRef, "HEAD"]);
	if (mergeBaseResult.code !== 0) {
		const hasHead = (await git(root, ["rev-parse", "--verify", "--quiet", "HEAD"])).code === 0;
		throw new ScopeError(
			"git-failed",
			hasHead
				? `Could not compute the merge-base of HEAD and ${baseRef}. In a shallow clone, run \`git fetch --unshallow\`. To audit the whole project instead, run /security-review full.`
				: `The repository has no commits yet, so there is nothing to compare with ${baseRef}. Run /security-review full.`,
		);
	}
	const mergeBase = mergeBaseResult.stdout.trim();
	const changed = splitZ(await gitOk(root, ["diff", "-z", "--name-only", "--no-renames", "--diff-filter=d", mergeBase], "Listing changed files"));
	const untrackedListed = splitZ(await gitOk(root, ["ls-files", "-z", "--others", "--exclude-standard"], "Listing untracked files"));
	const files = finalize(root, [...changed, ...untrackedListed], exclude);
	if (files.length === 0) {
		throw new ScopeError(
			"empty",
			`There are no unmerged changes against ${baseRef}: no commits, uncommitted edits, or untracked files to audit. Run /security-review full to audit the whole project.`,
		);
	}
	const untracked = untrackedListed.filter((file) => files.includes(file));
	const trackedInScope = files.filter((file) => !untracked.includes(file));
	let diff = "";
	if (trackedInScope.length > 0) {
		// Very long pathspecs can exceed argument limits; the unfiltered diff is an acceptable fallback.
		const pathspec = trackedInScope.length <= 500 ? ["--", ...trackedInScope] : [];
		diff = await gitOk(root, ["diff", "--no-ext-diff", "--no-textconv", "--no-color", mergeBase, ...pathspec], "Reading the diff");
	}
	const diffTruncated = Buffer.byteLength(diff) > MAX_DIFF_BYTES;
	if (diffTruncated) diff = Buffer.from(diff).subarray(0, MAX_DIFF_BYTES).toString();
	return { mode, root, files, baseRef, mergeBase, diff, diffTruncated, untracked };
}

/**
 * Commit that last touched `file` between the merge-base and HEAD, "uncommitted" when the file only
 * changed in the working tree, or undefined when unknown.
 */
export async function introducedIn(scope: Scope, file: string): Promise<string | undefined> {
	if (scope.mode !== "diff" || !scope.mergeBase) return undefined;
	if (scope.untracked?.includes(file)) return "uncommitted";
	const log = await git(scope.root, ["log", "-n", "1", "--format=%H", `${scope.mergeBase}..HEAD`, "--", file]);
	const sha = log.stdout.trim();
	if (log.code === 0 && sha) return sha;
	return scope.files.includes(file) ? "uncommitted" : undefined;
}
