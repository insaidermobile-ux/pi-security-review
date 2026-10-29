import { execFile } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { join } from "node:path";
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

export interface FullScope {
	mode: "full";
	/** Absolute path of the git work tree root; all file paths are relative to it. */
	root: string;
	files: string[];
}

export interface DiffScope {
	mode: "diff";
	/** Absolute path of the git work tree root; all file paths are relative to it. */
	root: string;
	files: string[];
	baseRef: string;
	mergeBase: string;
	diff: string;
	diffTruncated: boolean;
	untracked: string[];
}

export type Scope = FullScope | DiffScope;

interface GitResult {
	code: number;
	stdout: string;
	stderr: string;
}

/**
 * Environment for every git process. A read never fetches: a partial clone would otherwise fetch a
 * missing object through a transport the repository's config chooses, and the empty protocol
 * allowlist overrides any `protocol.*.allow` in that config.
 */
export const GIT_ENV: Readonly<Record<string, string>> = {
	GIT_OPTIONAL_LOCKS: "0",
	GIT_TERMINAL_PROMPT: "0",
	GIT_NO_LAZY_FETCH: "1",
	GIT_ALLOW_PROTOCOL: "",
};

/** Overrides for configured programs that are not named per driver. */
const STATIC_OVERRIDES = [
	"core.fsmonitor=false",
	"log.showSignature=false",
	"gpg.program=false",
	"gpg.openpgp.program=false",
	"gpg.x509.program=false",
	"gpg.ssh.program=false",
	// A submodule's own config is not read below, so status and diff do not descend into submodules.
	"diff.ignoreSubmodules=all",
];

const FILTER_KEY = /^filter\.(.+)\.(?:clean|smudge|process|required)$/;

function run(cwd: string, args: string[]): Promise<GitResult> {
	return new Promise((resolve) => {
		execFile("git", args, { cwd, maxBuffer: 256 * 1024 * 1024, env: { ...process.env, ...GIT_ENV } }, (error, stdout, stderr) => {
			const code = error ? (typeof error.code === "number" ? error.code : 1) : 0;
			resolve({ code, stdout: stdout.toString(), stderr: stderr.toString() });
		});
	});
}

/**
 * `-c` options that switch off the programs git takes from configuration while it reads. The audited
 * project can come with its own `.git/config`, so its config is as untrusted as its files: `status`,
 * `blame`, and a diff against the work tree run filter drivers, `cat-file --filters` runs smudge, and
 * signature checks run gpg. Filter drivers have arbitrary names, so the configured ones are listed
 * and each is emptied. Diff drivers and textconv are disabled per command with --no-ext-diff and
 * --no-textconv.
 */
export async function safeGitConfig(cwd: string): Promise<string[]> {
	const listed = await run(cwd, ["config", "-z", "--list"]);
	const drivers = new Set<string>();
	for (const entry of listed.stdout.split("\0")) {
		const match = FILTER_KEY.exec(entry.split("\n", 1)[0]!);
		if (match) drivers.add(match[1]!);
	}
	const filters = [...drivers].flatMap((name) => ["clean=", "smudge=", "process=", "required=false"].map((setting) => `filter.${name}.${setting}`));
	return [...STATIC_OVERRIDES, ...filters].flatMap((setting) => ["-c", setting]);
}

export async function git(cwd: string, args: string[]): Promise<GitResult> {
	return run(cwd, ["-c", "core.quotepath=off", ...(await safeGitConfig(cwd)), ...args]);
}

async function gitOk(cwd: string, args: string[], what: string): Promise<string> {
	const result = await git(cwd, args);
	if (result.code !== 0) {
		throw new ScopeError("git-failed", `${what} failed: git ${args.join(" ")}\n${result.stderr.trim()}`);
	}
	return result.stdout;
}

/** Before a subcommand that takes file names: `pages/[id].tsx` is a file, not a glob that also matches `pages/i.tsx`. */
const LITERAL_PATHS = "--literal-pathspecs";

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

function escapeRegExp(text: string): string {
	return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Regular expression source for a glob. Unlike a shell glob, `*`, `?`, and `**` also match names that
 * start with a dot, so an excluded directory does not leak its dotfiles into the audited scope.
 */
function globSource(glob: string): string {
	let source = "";
	for (let i = 0; i < glob.length; i++) {
		const char = glob[i]!;
		const close = char === "[" ? glob.indexOf("]", i + 2) : char === "{" ? glob.indexOf("}", i) : -1;
		if (char === "*" && glob[i + 1] === "*") {
			// "**/" spans any number of directories, including none.
			const spansDirectories = glob[i + 2] === "/";
			source += spansDirectories ? "(?:.*/)?" : ".*";
			i += spansDirectories ? 2 : 1;
		} else if (char === "*") source += "[^/]*";
		else if (char === "?") source += "[^/]";
		else if (char === "[" && close > 0) {
			const body = glob.slice(i + 1, close);
			source += `[${body.startsWith("!") ? `^${body.slice(1)}` : body}]`.replace(/\\/g, "\\\\");
			i = close;
		} else if (char === "{" && close > 0) {
			source += `(?:${glob.slice(i + 1, close).split(",").map(globSource).join("|")})`;
			i = close;
		} else source += escapeRegExp(char);
	}
	return source;
}

/**
 * A predicate for the exclude patterns. A pattern without a slash also matches by name at any depth,
 * and a pattern naming a directory matches everything below it.
 */
export function excludeMatcher(patterns: readonly string[]): (file: string) => boolean {
	const matchers = patterns.map((raw) => {
		const pattern = raw.replace(/^\.\//, "").replace(/\/+$/, "");
		const anyDepth = pattern.includes("/") ? "" : "(?:.*/)?";
		try {
			return new RegExp(`^${anyDepth}${globSource(pattern)}(?:/.*)?$`);
		} catch {
			// Not a valid glob, for example an unordered character range: match the text as written.
			return new RegExp(`^${anyDepth}${escapeRegExp(pattern)}(?:/.*)?$`);
		}
	});
	return (file) => matchers.some((matcher) => matcher.test(file));
}

export function isExcluded(file: string, patterns: readonly string[]): boolean {
	return excludeMatcher(patterns)(file);
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
	const excluded = excludeMatcher([...exclude, `${STORE_DIR}/**`]);
	return [...new Set(files)].filter((file) => !excluded(file) && isAuditableFile(root, file)).sort();
}

export interface ResolveScopeOptions {
	exclude?: readonly string[];
}

export async function resolveScope(cwd: string, mode: "full", options?: ResolveScopeOptions): Promise<FullScope>;
export async function resolveScope(cwd: string, mode: "diff", options?: ResolveScopeOptions): Promise<DiffScope>;
export async function resolveScope(cwd: string, mode: ScopeMode, options?: ResolveScopeOptions): Promise<Scope>;
export async function resolveScope(cwd: string, mode: ScopeMode, options: ResolveScopeOptions = {}): Promise<Scope> {
	const exclude = options.exclude ?? [];
	const root = await findRepoRoot(cwd);

	if (mode === "full") {
		const listed = splitZ(await gitOk(root, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], "Listing project files"));
		const files = finalize(root, listed, exclude);
		if (files.length === 0) throw new ScopeError("empty", "There are no files to audit in this project after applying excludes.");
		return { mode: "full", root, files };
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
	const inScope = new Set(files);
	const untracked = untrackedListed.filter((file) => inScope.has(file));
	const untrackedInScope = new Set(untracked);
	const trackedInScope = files.filter((file) => !untrackedInScope.has(file));
	let diff = "";
	if (trackedInScope.length > 0) {
		// Very long pathspecs can exceed argument limits; the unfiltered diff is an acceptable fallback.
		const pathspec = trackedInScope.length <= 500 ? ["--", ...trackedInScope] : [];
		diff = await gitOk(root, [LITERAL_PATHS, "diff", "--no-ext-diff", "--no-textconv", "--no-color", mergeBase, ...pathspec], "Reading the diff");
	}
	const diffTruncated = Buffer.byteLength(diff) > MAX_DIFF_BYTES;
	if (diffTruncated) diff = Buffer.from(diff).subarray(0, MAX_DIFF_BYTES).toString();
	return { mode: "diff", root, files, baseRef, mergeBase, diff, diffTruncated, untracked };
}

/**
 * Commit that last touched `file` between the merge-base and HEAD, "uncommitted" when the file only
 * changed in the working tree, or undefined when unknown.
 */
export async function introducedIn(scope: Scope, file: string): Promise<string | undefined> {
	if (scope.mode !== "diff") return undefined;
	if (scope.untracked.includes(file)) return "uncommitted";
	const log = await git(scope.root, [LITERAL_PATHS, "log", "-n", "1", "--format=%H", `${scope.mergeBase}..HEAD`, "--", file]);
	const sha = log.stdout.trim();
	if (log.code === 0 && sha) return sha;
	return scope.files.includes(file) ? "uncommitted" : undefined;
}
