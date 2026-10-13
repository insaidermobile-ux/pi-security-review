import { createHash, randomBytes } from "node:crypto";
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";
import { git, STORE_DIR } from "./scope.ts";
import { type Finding, type Profile, ProfileInput, type RunRecord, type StoreFile, StoreFile as StoreFileSchema, validate } from "./schema.ts";

export { STORE_DIR };
export const FINDINGS_FILE = "findings.json";
export const REPORT_FILE = "report.md";
export const PROFILE_FILE = "profile.json";
export const RUNS_DIR = "runs";
/** Run records kept inline in findings.json; full logs stay in runs/. */
export const MAX_STORED_RUNS = 20;

/** Statuses set by the user that the extension never overwrites. */
export const USER_STATUSES: ReadonlySet<Finding["status"]> = new Set(["accepted-risk", "fixed", "false-positive"]);

export function storePath(root: string, file: string = FINDINGS_FILE): string {
	return join(root, STORE_DIR, file);
}

export function emptyStore(): StoreFile {
	return { version: 1, gitignore_hint_shown: false, findings: [], runs: [] };
}

export class StoreError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "StoreError";
	}
}

/** Load the store. A missing file yields an empty store; an unreadable or invalid one throws so it is never overwritten. */
export function loadStore(root: string): StoreFile {
	const path = storePath(root);
	if (!existsSync(path)) return emptyStore();
	let data: unknown;
	try {
		data = JSON.parse(readFileSync(path, "utf8"));
	} catch (error) {
		throw new StoreError(`${path} is not valid JSON (${(error as Error).message}). Fix or remove it and run again.`);
	}
	const errors = validate(StoreFileSchema, data);
	if (errors.length > 0) {
		throw new StoreError(`${path} does not match the findings store schema:\n${errors.slice(0, 10).join("\n")}\nFix or remove it and run again.`);
	}
	return data as StoreFile;
}

export interface AtomicWriteHooks {
	/** Test hook: runs after the temporary file is written, before it replaces the target. */
	beforeRename?: (tempPath: string) => void;
}

/** Write via a synced temporary file and rename, so readers see either the old or the new content. */
export function writeFileAtomic(path: string, content: string, hooks: AtomicWriteHooks = {}): void {
	mkdirSync(dirname(path), { recursive: true });
	const temp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
	try {
		const fd = openSync(temp, "w", 0o644);
		try {
			writeSync(fd, content);
			fsyncSync(fd);
		} finally {
			closeSync(fd);
		}
		hooks.beforeRename?.(temp);
		renameSync(temp, path);
	} catch (error) {
		rmSync(temp, { force: true });
		throw error;
	}
}

export function saveStore(root: string, store: StoreFile, hooks?: AtomicWriteHooks): void {
	writeFileAtomic(storePath(root), `${JSON.stringify(store, null, 2)}\n`, hooks);
}

export function writeRunLog(root: string, run: RunRecord & Record<string, unknown>): string {
	const path = join(root, STORE_DIR, RUNS_DIR, `${run.id}.json`);
	writeFileAtomic(path, `${JSON.stringify(run, null, 2)}\n`);
	return path;
}

/** A finding produced by a run, before the store assigns identity and lifecycle fields. */
export type NewFinding = Omit<Finding, "id" | "status" | "first_seen" | "last_seen">;

export interface MergeInput {
	run: Omit<RunRecord, "finding_ids">;
	findings: NewFinding[];
	now: string;
}

export interface MergeResult {
	store: StoreFile;
	run: RunRecord;
	/** Findings observed in this run, as stored (with id and preserved status). */
	observed: Finding[];
	added: number;
	updated: number;
	markedStale: number;
}

function nextId(findings: readonly Finding[]): () => string {
	let max = 0;
	for (const finding of findings) max = Math.max(max, Number.parseInt(finding.id.slice(3), 10) || 0);
	return () => `SR-${String(++max).padStart(3, "0")}`;
}

/**
 * Merge a run's findings into the store: deduplicate by fingerprint, keep ids and user-set statuses,
 * refresh evidence, and in full mode mark open findings that were not observed again as stale.
 */
export function mergeRun(previous: StoreFile, input: MergeInput): MergeResult {
	const findings = previous.findings.map((finding) => ({ ...finding }));
	const byFingerprint = new Map(findings.map((finding) => [finding.fingerprint, finding]));
	const allocate = nextId(findings);
	const observed = new Map<string, Finding>();
	let added = 0;
	let updated = 0;

	for (const incoming of input.findings) {
		const existing = byFingerprint.get(incoming.fingerprint);
		if (existing) {
			const status = USER_STATUSES.has(existing.status) ? existing.status : "open";
			Object.assign(existing, incoming, {
				id: existing.id,
				status,
				first_seen: existing.first_seen,
				last_seen: input.now,
				introduced_in: existing.introduced_in ?? incoming.introduced_in,
			});
			if (existing.introduced_in === undefined) delete existing.introduced_in;
			if (!observed.has(existing.id)) updated++;
			observed.set(existing.id, existing);
		} else {
			const finding: Finding = { ...incoming, id: allocate(), status: "open", first_seen: input.now, last_seen: input.now };
			findings.push(finding);
			byFingerprint.set(finding.fingerprint, finding);
			observed.set(finding.id, finding);
			added++;
		}
	}

	let markedStale = 0;
	if (input.run.mode === "full") {
		for (const finding of findings) {
			if (finding.status === "open" && !observed.has(finding.id)) {
				finding.status = "stale";
				markedStale++;
			}
		}
	}

	const run: RunRecord = { ...input.run, finding_ids: [...observed.keys()] };
	const runs = [...previous.runs, run].slice(-MAX_STORED_RUNS);
	return { store: { ...previous, findings, runs }, run, observed: [...observed.values()], added, updated, markedStale };
}

/** A stored finding the user marked as a false positive with the same fingerprint, if any. */
export function priorFalsePositive(store: StoreFile, fingerprint: string): Finding | undefined {
	return store.findings.find((finding) => finding.fingerprint === fingerprint && finding.status === "false-positive");
}

// Profile cache

const MANIFEST_PATTERN =
	/^(package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|go\.mod|go\.sum|Cargo\.toml|Cargo\.lock|pyproject\.toml|poetry\.lock|uv\.lock|Pipfile(\.lock)?|requirements[^/]*\.txt|setup\.py|Gemfile(\.lock)?|composer\.(json|lock)|pom\.xml|build\.gradle(\.kts)?|settings\.gradle(\.kts)?|[^/]+\.csproj|mix\.(exs|lock)|Package\.swift|pubspec\.(yaml|lock))$/;

/** Fingerprint of the project's shape: top-level entries plus the content of root manifests and lockfiles. */
export async function projectFingerprint(root: string): Promise<string> {
	const listed = await git(root, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"]);
	const files = listed.stdout.split("\0").filter((file) => file && !file.startsWith(`${STORE_DIR}/`));
	const topLevel = [...new Set(files.map((file) => file.split("/")[0]!))].sort();
	const manifests = files.filter((file) => !file.includes("/") && MANIFEST_PATTERN.test(file)).sort();
	const hash = createHash("sha256");
	hash.update(topLevel.join("\n"));
	for (const manifest of manifests) {
		hash.update(`\0${manifest}\0`);
		const path = join(root, manifest);
		if (existsSync(path)) hash.update(readFileSync(path));
	}
	return hash.digest("hex").slice(0, 16);
}

interface ProfileCache {
	fingerprint: string;
	created_at: string;
	profile: Profile;
}

export function loadCachedProfile(root: string, fingerprint: string): Profile | undefined {
	const path = storePath(root, PROFILE_FILE);
	if (!existsSync(path)) return undefined;
	try {
		const cache = JSON.parse(readFileSync(path, "utf8")) as ProfileCache;
		if (cache.fingerprint !== fingerprint) return undefined;
		return validate(ProfileInput, cache.profile).length === 0 ? cache.profile : undefined;
	} catch {
		return undefined;
	}
}

export function saveProfile(root: string, fingerprint: string, profile: Profile, now: string): void {
	const cache: ProfileCache = { fingerprint, created_at: now, profile };
	writeFileAtomic(storePath(root, PROFILE_FILE), `${JSON.stringify(cache, null, 2)}\n`);
}

// .gitignore recommendation

export async function isStoreIgnored(root: string): Promise<boolean> {
	const result = await git(root, ["check-ignore", "-q", "--no-index", `${STORE_DIR}/${FINDINGS_FILE}`]);
	return result.code === 0;
}

/**
 * The once-per-project recommendation to ignore `.security-review/`, or undefined when it is already
 * ignored or was shown before. Marks the hint as shown in the returned store.
 */
export async function gitignoreHint(root: string, store: StoreFile): Promise<{ hint?: string; store: StoreFile }> {
	if (await isStoreIgnored(root)) return { store };
	if (store.gitignore_hint_shown) return { store };
	return {
		hint: `\`${STORE_DIR}/\` is not ignored by git. Add it to .gitignore to keep findings out of commits: echo '${STORE_DIR}/' >> .gitignore`,
		store: { ...store, gitignore_hint_shown: true },
	};
}
