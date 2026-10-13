import { normalizeVulnType } from "./fingerprint.ts";
import { type HuntAssignment, VULN_CLASSES } from "./prompts.ts";
import type { Anchor, HypothesisInput } from "./schema.ts";
import type { Scope } from "./scope.ts";

/** Upper bound of hunt agents in full mode; concurrency is limited separately. */
export const MAX_SUBTREE_AGENTS = 12;
/** Preferred maximum number of files owned by one full-mode hunt agent. */
export const TARGET_FILES_PER_AGENT = 150;

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
 * Split the project into subtrees: top-level directories, recursively split while they hold more than
 * the target number of files, then small groups merged until at most MAX_SUBTREE_AGENTS remain.
 */
export function subtreePartitions(files: readonly string[]): Group[] {
	let groups: Group[] = [];
	const queue: Array<{ group: Group; depth: number }> = groupByPrefix(files, 1).map((group) => ({ group, depth: 1 }));
	while (queue.length > 0) {
		const { group, depth } = queue.shift()!;
		if (group.files.length > TARGET_FILES_PER_AGENT && depth < 6) {
			const children = groupByPrefix(group.files, depth + 1);
			if (children.length > 1) {
				queue.push(...children.map((child) => ({ group: child, depth: depth + 1 })));
				continue;
			}
		}
		groups.push(group);
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
}

function anchorsOverlap(a: readonly Anchor[], b: readonly Anchor[]): boolean {
	return a.some((x) =>
		b.some((y) => x.file === y.file && ((x.function && y.function ? x.function === y.function : false) || Math.abs(x.line - y.line) <= 5)),
	);
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

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
		const keepIncoming = SEVERITY_ORDER.indexOf(hypothesis.severity_estimate) < SEVERITY_ORDER.indexOf(match.severity_estimate);
		const anchors = [...(keepIncoming ? hypothesis.anchors : match.anchors), ...(keepIncoming ? match.anchors : hypothesis.anchors)];
		const unique = anchors.filter((anchor, i) => anchors.findIndex((other) => other.file === anchor.file && other.line === anchor.line) === i);
		const partitions = new Set([...match.source_partition.split(", "), hypothesis.source_partition]);
		Object.assign(match, keepIncoming ? { ...hypothesis } : {}, { anchors: unique, source_partition: [...partitions].join(", ") });
	}
	return merged;
}

/** Order by severity estimate (stable) and split at the cap. */
export function applyHypothesisCap<T extends { severity_estimate: string }>(hypotheses: readonly T[], cap: number): { verify: T[]; overflow: T[] } {
	const ordered = hypotheses
		.map((hypothesis, index) => ({ hypothesis, index }))
		.sort((a, b) => SEVERITY_ORDER.indexOf(a.hypothesis.severity_estimate) - SEVERITY_ORDER.indexOf(b.hypothesis.severity_estimate) || a.index - b.index)
		.map((entry) => entry.hypothesis);
	return { verify: ordered.slice(0, cap), overflow: ordered.slice(cap) };
}
