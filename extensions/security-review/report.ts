import type { Finding, RefutedHypothesis, RunRecord, Severity } from "./schema.ts";
import { SEVERITIES } from "./schema.ts";
import type { Scope } from "./scope.ts";
import { staleMarkingSkipped } from "./store.ts";

export const STALE_SKIPPED_NOTE = "Stale marking skipped: the run was incomplete.";

/** C0 and C1 control characters other than tab and newline: a terminal reads them as escape sequences. */
const CONTROL_CHARS = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;

export function hasControlChars(text: string): boolean {
	return text.search(CONTROL_CHARS) >= 0;
}

/**
 * Text that agents wrote or quoted from the audited repository, with control characters made visible.
 * Shown in a terminal (or a report printed in one), an escape sequence could write the clipboard, plant
 * a hidden link, or overwrite other parts of the output.
 */
export function stripControl(text: string): string {
	return text.replace(/\r\n/g, "\n").replace(CONTROL_CHARS, "\uFFFD");
}

export interface ReportInput {
	run: RunRecord;
	scope: Pick<Scope, "mode" | "baseRef" | "mergeBase">;
	findings: Finding[];
	refuted: RefutedHypothesis[];
	unverified: RunRecord["unverified"];
	summary?: string;
}

export type SeverityCounts = Record<Severity, number>;

export function countBySeverity(findings: readonly Finding[]): SeverityCounts {
	const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
	for (const finding of findings) counts[finding.severity]++;
	return counts;
}

function anchorText(anchor: Finding["anchors"][number]): string {
	return `\`${anchor.file}:${anchor.line}\`${anchor.function ? ` (${anchor.function})` : ""}`;
}

function consequenceLines(consequences: Finding["consequences"]): string[] {
	return (consequences ?? []).map((c) => `- ${c.vuln_type} at ${c.anchors.map(anchorText).join(", ")}: ${c.description}`);
}

/** A code fence longer than any backtick run in `text`, so no line of the text can close it. */
export function fence(text: string, language = ""): string {
	const longest = Math.max(2, ...[...text.matchAll(/`+/g)].map((match) => match[0].length));
	const ticks = "`".repeat(longest + 1);
	return `${ticks}${language}\n${text.trimEnd()}\n${ticks}`;
}

function renderFinding(finding: Finding): string {
	const { affirmer, challenger, verdict } = finding.verification;
	const meta = [
		`**${finding.finding_class === "vulnerability" ? "Vulnerability" : "Risk"}**`,
		`severity ${finding.severity}`,
		`confidence ${finding.confidence}`,
		`status ${finding.status}`,
		finding.cwe,
		finding.cvss_score !== undefined ? `CVSS ${finding.cvss_score}${finding.cvss_vector ? ` (${finding.cvss_vector})` : ""}` : undefined,
		finding.introduced_in ? `introduced in ${finding.introduced_in === "uncommitted" ? "uncommitted changes" : `\`${finding.introduced_in.slice(0, 12)}\``}` : undefined,
	].filter(Boolean);
	const lines = [
		`#### ${finding.id}: ${finding.title}`,
		"",
		meta.join(" · "),
		"",
		`**Location:** ${finding.anchors.map(anchorText).join(", ")}`,
		"",
		"**Background.** " + finding.description.background,
		"",
		"**Detail.** " + finding.description.detail,
		"",
		"**Attack scenario.** " + finding.description.attack_scenario,
		"",
		"**Data flow**",
		"",
		...finding.data_flow.map((step, i) => `${i + 1}. \`${step.location}\`: ${step.description}`),
		"",
		...(finding.consequences?.length ? ["**Consequences** (removed by the same fix)", "", ...consequenceLines(finding.consequences), ""] : []),
		"<details><summary>Verification</summary>",
		"",
		"**Affirmer**",
		"",
		`- Missing defenses: ${affirmer.missing_defenses.length ? affirmer.missing_defenses.map((d) => `${d.defense} (${d.location})`).join("; ") : "none listed"}`,
		`- Preconditions: ${affirmer.preconditions.length ? affirmer.preconditions.join("; ") : "none"}`,
		"",
		"**Challenger**",
		"",
		`- Attribution: attacker is trusted role: ${challenger.attribution.attacker_is_trusted_role ? "yes" : "no"}; harmful step outside component: ${challenger.attribution.harmful_step_outside_component ? "yes" : "no"}. ${challenger.attribution.reasoning}`,
		`- Defenses examined: ${challenger.defenses_found.length ? challenger.defenses_found.map((d) => `${d.defense} at ${d.location} (${d.effect})`).join("; ") : "none"}`,
		`- Threat model: ${challenger.threat_model_notes}`,
		`- Reasoning: ${challenger.reasoning}`,
		"",
		`**Verdict:** ${verdict} (confidence ${challenger.confidence})`,
		"",
		"</details>",
		"",
		"**Remediation.** " + finding.remediation.summary,
	];
	if (finding.remediation.patch) lines.push("", fence(finding.remediation.patch, "diff"));
	return lines.join("\n");
}

export function plural(count: number, one: string, many = `${one}s`): string {
	return `${count} ${count === 1 ? one : many}`;
}

/** Render the Markdown report for one run. */
export function renderReport(input: ReportInput): string {
	const { run, scope, findings } = input;
	const counts = countBySeverity(findings);
	const vulnerabilities = findings.filter((f) => f.finding_class === "vulnerability").length;
	const lines = [
		"# Security review report",
		"",
		`- Run: \`${run.id}\` (${run.started_at} to ${run.finished_at})`,
		`- Scope: ${scope.mode === "diff" ? `changes against \`${scope.baseRef}\` (merge-base \`${scope.mergeBase?.slice(0, 12)}\`)` : "full project"}, ${run.files} files`,
		`- Result: ${plural(vulnerabilities, "vulnerability", "vulnerabilities")}, ${plural(findings.length - vulnerabilities, "risk")}, ${input.refuted.length} refuted, ${input.unverified.length} unverified`,
		`- By severity: ${SEVERITIES.map((s) => `${counts[s]} ${s}`).join(", ")}`,
	];
	if (!run.complete) lines.push(`- **Incomplete run:** ${run.incomplete_reasons.join("; ")}`);
	if (staleMarkingSkipped(run)) lines.push(`- ${STALE_SKIPPED_NOTE}`);
	lines.push("");
	if (input.summary) lines.push("## Summary", "", input.summary.trim(), "");

	lines.push("## Findings", "");
	if (findings.length === 0) lines.push("No vulnerabilities or risks were confirmed in this run.", "");
	for (const severity of SEVERITIES) {
		const group = findings
			.filter((f) => f.severity === severity)
			.sort((a, b) => (a.finding_class === b.finding_class ? a.id.localeCompare(b.id) : a.finding_class === "vulnerability" ? -1 : 1));
		if (group.length === 0) continue;
		lines.push(`### ${severity[0]!.toUpperCase()}${severity.slice(1)}`, "");
		for (const finding of group) lines.push(renderFinding(finding), "");
	}

	lines.push("## Refuted hypotheses", "");
	if (input.refuted.length === 0) lines.push("None.", "");
	for (const entry of input.refuted) {
		const h = entry.hypothesis;
		lines.push(
			`### ${h.id}: ${h.vuln_type} at ${h.anchors.map(anchorText).join(", ")}`,
			"",
			`**Claim.** ${h.claim}`,
			"",
			`**Why it was refuted** (confidence ${entry.challenger.confidence}): ${entry.challenger.reasoning}`,
			"",
		);
		if (h.consequences?.length) lines.push("**Consequences, refuted with it:**", "", ...consequenceLines(h.consequences), "");
		const blocking = entry.challenger.defenses_found.filter((d) => d.effect !== "none");
		if (blocking.length) lines.push(...blocking.map((d) => `- ${d.defense} at \`${d.location}\` (${d.effect})`), "");
	}

	if (input.unverified.length > 0) {
		lines.push("## Unverified hypotheses", "", "These were raised but not verified in this run (cap reached or an agent failed).", "");
		for (const h of input.unverified) {
			const extra = h.consequences?.length ? ` (consequences: ${h.consequences.map((c) => c.vuln_type).join(", ")})` : "";
			lines.push(`- ${h.id} [${h.severity_estimate}] ${h.vuln_type} at ${h.anchors.map(anchorText).join(", ")}: ${h.claim}${extra}`);
		}
		lines.push("");
	}
	if (run.errors.length > 0) lines.push("## Errors", "", ...run.errors.map((e) => `- ${e}`), "");
	return `${stripControl(lines.join("\n")).trimEnd()}\n`;
}
