import { normalizeVulnType } from "./fingerprint.ts";
import { type HuntAssignment, VULN_CLASSES } from "./prompts.ts";
import { type Anchor, type Consequence, type HypothesisInput, type Severity, severityRank } from "./schema.ts";
import type { Scope } from "./scope.ts";

/** Upper bound of hunt agents in full mode; concurrency is limited separately. */
export const MAX_SUBTREE_AGENTS = 12;
/** Preferred maximum number of files owned by one full-mode hunt agent. */
export const TARGET_FILES_PER_AGENT = 150;
/** How many times a subtree is split into its subdirectories before it is left as one group. */
const MAX_SPLIT_LEVELS = 6;

export function huntAssignments(scope: Scope): HuntAssignment[] {
	if (scope.mode === "diff") {
		return VULN_CLASSES.map((vulnClass) => ({ label: vulnClass.id, kind: "class", title: vulnClass.title, focus: vulnClass.focus, files: scope.files }));
	}
	return subtreePartitions(scope.files).map((group) => ({ label: group.label, kind: "subtree", title: `Subtree ${group.label}`, files: group.files }));
}

interface Group {
	label: string;
	files: string[];
}

function groupByPrefix(files: readonly string[], depth: number): Group[] {
	const groups = new Map<string, string[]>();
	for (const file of files) {
		const segments = file.split("/");
		const key = segments.length > depth ? segments.slice(0, depth).join("/") : depth === 1 ? "(root files)" : segments.slice(0, -1).join("/") || "(root files)";
		let list = groups.get(key);
		if (!list) groups.set(key, (list = []));
		list.push(file);
	}
	return [...groups].map(([label, groupFiles]) => ({ label, files: groupFiles }));
}

/**
 * The subdirectories of a group whose files share their first `depth` path segments. Levels with a
 * single subdirectory are passed through, as in `src/main/java/com/acme`, so they neither stop the
 * split nor count as one. Undefined when all the files are in one directory.
 */
function splitGroup(files: readonly string[], depth: number): { children: Group[]; depth: number } | undefined {
	let deepest = 0;
	for (const file of files) deepest = Math.max(deepest, file.split("/").length);
	for (let next = depth + 1; next <= deepest; next++) {
		const children = groupByPrefix(files, next);
		if (children.length > 1) return { children, depth: next };
	}
	return undefined;
}

/**
 * Split the project into subtrees: top-level directories, recursively split while they hold more than
 * the target number of files, then small groups merged until at most MAX_SUBTREE_AGENTS remain.
 */
export function subtreePartitions(files: readonly string[]): Group[] {
	let groups: Group[] = [];
	const queue: Array<{ group: Group; depth: number; level: number }> = groupByPrefix(files, 1).map((group) => ({ group, depth: 1, level: 1 }));
	while (queue.length > 0) {
		const { group, depth, level } = queue.shift()!;
		const split = group.files.length > TARGET_FILES_PER_AGENT && level < MAX_SPLIT_LEVELS ? splitGroup(group.files, depth) : undefined;
		if (split) queue.push(...split.children.map((child) => ({ group: child, depth: split.depth, level: level + 1 })));
		else groups.push(group);
	}
	// Merge the two smallest groups while there are too many, or while both are small enough to share an agent.
	groups.sort((a, b) => a.files.length - b.files.length);
	while (groups.length > 1) {
		const [a, b] = groups as [Group, Group, ...Group[]];
		const tooMany = groups.length > MAX_SUBTREE_AGENTS;
		if (!tooMany && a.files.length + b.files.length > TARGET_FILES_PER_AGENT) break;
		groups = [{ label: `${a.label} + ${b.label}`, files: [...a.files, ...b.files] }, ...groups.slice(2)];
		groups.sort((x, y) => x.files.length - y.files.length);
	}
	for (const group of groups) group.files.sort();
	return groups.sort((a, b) => a.label.localeCompare(b.label));
}

export interface TaggedHypothesis extends HypothesisInput {
	source_partition: string;
	consequences?: Consequence[];
}

function anchorsOverlap(a: readonly Anchor[], b: readonly Anchor[]): boolean {
	return a.some((x) =>
		b.some((y) => x.file === y.file && ((x.function && y.function ? x.function === y.function : false) || Math.abs(x.line - y.line) <= 5)),
	);
}

/** Merge hypotheses with the same vulnerability type and overlapping anchors, keeping the more severe claim. */
export function mergeDuplicateHypotheses(hypotheses: readonly TaggedHypothesis[]): TaggedHypothesis[] {
	const merged: TaggedHypothesis[] = [];
	for (const hypothesis of hypotheses) {
		const type = normalizeVulnType(hypothesis.vuln_type);
		const match = merged.find((existing) => normalizeVulnType(existing.vuln_type) === type && anchorsOverlap(existing.anchors, hypothesis.anchors));
		if (!match) {
			merged.push({ ...hypothesis, anchors: [...hypothesis.anchors] });
			continue;
		}
		const keepIncoming = severityRank(hypothesis.severity_estimate) < severityRank(match.severity_estimate);
		const anchors = [...(keepIncoming ? hypothesis.anchors : match.anchors), ...(keepIncoming ? match.anchors : hypothesis.anchors)];
		const unique = anchors.filter((anchor, i) => anchors.findIndex((other) => other.file === anchor.file && other.line === anchor.line) === i);
		const partitions = new Set([...match.source_partition.split(", "), hypothesis.source_partition]);
		Object.assign(match, keepIncoming ? { ...hypothesis } : {}, { anchors: unique, source_partition: [...partitions].join(", ") });
	}
	return merged;
}

/** Label of the candidate at `index` as shown to the triage agent. */
export function candidateLabel(index: number): string {
	return `C-${index + 1}`;
}

/** A triage group in candidate labels, already validated against the candidate list. */
export interface CandidateGroup {
	primary: string;
	members: string[];
}

/**
 * Fold each triage group into its primary candidate: the primary keeps its own fields (so its
 * fingerprint is unchanged), takes the most severe estimate and the union of source partitions, and
 * carries the other members as consequences. A group takes the position of its first member.
 */
export function applyTriageGroups(candidates: readonly TaggedHypothesis[], groups: readonly CandidateGroup[]): TaggedHypothesis[] {
	const indexOf = (label: string) => Number.parseInt(label.slice(2), 10) - 1;
	const groupAt = new Map<number, number[]>();
	const grouped = new Set<number>();
	for (const group of groups) {
		const members = [...new Set(group.members.map(indexOf))].sort((a, b) => a - b);
		const primary = indexOf(group.primary);
		groupAt.set(members[0]!, [primary, ...members.filter((m) => m !== primary)]);
		for (const member of members) grouped.add(member);
	}
	const result: TaggedHypothesis[] = [];
	candidates.forEach((candidate, index) => {
		const group = groupAt.get(index);
		if (group) {
			const [primary, ...others] = group.map((i) => candidates[i]!);
			const members = [primary!, ...others];
			const severity = members.map((m) => m.severity_estimate).sort((a, b) => severityRank(a) - severityRank(b))[0]!;
			const partitions = new Set(members.flatMap((m) => m.source_partition.split(", ")));
			const consequences: Consequence[] = [
				...(primary!.consequences ?? []),
				...others.flatMap((o) => [{ vuln_type: o.vuln_type, description: o.claim, anchors: o.anchors }, ...(o.consequences ?? [])]),
			];
			result.push({ ...primary!, severity_estimate: severity, source_partition: [...partitions].join(", "), consequences });
		} else if (!grouped.has(index)) {
			result.push(candidate);
		}
	});
	return result;
}

/** Order by severity estimate (stable) and split at the cap. */
export function applyHypothesisCap<T extends { severity_estimate: Severity }>(hypotheses: readonly T[], cap: number): { verify: T[]; overflow: T[] } {
	const ordered = hypotheses
		.map((hypothesis, index) => ({ hypothesis, index }))
		.sort((a, b) => severityRank(a.hypothesis.severity_estimate) - severityRank(b.hypothesis.severity_estimate) || a.index - b.index)
		.map((entry) => entry.hypothesis);
	return { verify: ordered.slice(0, cap), overflow: ordered.slice(cap) };
}
