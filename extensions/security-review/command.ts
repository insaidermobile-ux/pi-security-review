import { relative } from "node:path";
import type { Api, Model } from "@earendil-works/pi-ai";
import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { createSdkAgentRunner, resolveModelRuntime, UsageLedger, type UsageRecord } from "./agent-runtime.ts";
import { type Progress, type RunResult, runPipeline } from "./pipeline.ts";
import { type ScopeMode, SEVERITIES } from "./schema.ts";
import { resolveScope, ScopeError } from "./scope.ts";
import { resolveRoleModels, resolveSettings } from "./settings.ts";
import { readSettingsLayers } from "./settings-source.ts";
import { StoreError } from "./store.ts";

export const COMMAND_NAME = "security-review";
export const STATUS_KEY = "security-review";
export const MESSAGE_TYPE = "security-review";
export const USAGE = "Usage: /security-review [full]. Without arguments, audits changes not yet merged into the default branch; `full` audits the whole project.";

const MAX_LISTED_FINDINGS = 10;

export function parseMode(args: string): ScopeMode | undefined {
	const trimmed = args.trim();
	if (trimmed === "") return "diff";
	if (trimmed === "full") return "full";
	return undefined;
}

export function statusText(progress: Progress | "scope"): string {
	if (progress === "scope") return "security-review: scope";
	switch (progress.stage) {
		case "profile":
			return `security-review: profile${progress.cached ? " (cached)" : ""}`;
		case "hunt":
			return `security-review: hunt ${progress.done}/${progress.total}`;
		case "verify":
			return `security-review: verify ${progress.done}/${progress.total}`;
		case "report":
			return "security-review: report";
	}
}

function plural(count: number, one: string, many = `${one}s`): string {
	return `${count} ${count === 1 ? one : many}`;
}

function formatUsage(ledger: UsageLedger, agents: number): string {
	const total = ledger.total();
	const cost = total.cost.total > 0 ? `, $${total.cost.total.toFixed(4)}` : "";
	return `${total.totalTokens.toLocaleString("en-US")} tokens${cost} across ${plural(agents, "agent")}`;
}

/** Markdown summary posted into the session after a run. */
export function formatSummary(result: RunResult, cwd: string, usage: string): string {
	const rel = (path: string) => relative(cwd, path) || path;
	const vulnerabilities = result.findings.filter((f) => f.finding_class === "vulnerability").length;
	const risks = result.findings.length - vulnerabilities;
	const scope =
		result.scope.mode === "diff"
			? `changes against ${result.scope.baseRef}, ${plural(result.scope.files.length, "file")}`
			: `full project, ${plural(result.scope.files.length, "file")}`;
	const lines = [`**Security review** (${scope})`, ""];
	if (result.findings.length === 0) {
		lines.push(
			`No findings were confirmed. ${plural(result.hypotheses.length, "hypothesis", "hypotheses")} raised, ${result.refuted.length} refuted, ${result.unverified.length} unverified.`,
		);
	} else {
		lines.push(
			`${plural(vulnerabilities, "vulnerability", "vulnerabilities")} and ${plural(risks, "risk")} confirmed; ${result.refuted.length} refuted, ${result.unverified.length} unverified.`,
			`By severity: ${SEVERITIES.map((s) => `${result.counts[s]} ${s}`).join(", ")}.`,
			"",
		);
		const ordered = [...result.findings].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.id.localeCompare(b.id));
		for (const finding of ordered.slice(0, MAX_LISTED_FINDINGS)) {
			const anchor = finding.anchors[0]!;
			const triaged = finding.status !== "open" ? ` (${finding.status})` : "";
			lines.push(`- ${finding.id} [${finding.severity} ${finding.finding_class}] ${finding.title} - \`${anchor.file}:${anchor.line}\`${triaged}`);
		}
		if (ordered.length > MAX_LISTED_FINDINGS) lines.push(`- ... and ${ordered.length - MAX_LISTED_FINDINGS} more in the report`);
	}
	if (result.summary) lines.push("", result.summary.trim());
	if (!result.run.complete) lines.push("", `**Incomplete run:** ${result.run.incomplete_reasons.join("; ")}`);
	lines.push("", `Report: \`${rel(result.reportPath)}\` · Findings: \`${rel(result.storePath)}\``, `Usage: ${usage}.`);
	if (result.gitignoreHint) lines.push("", result.gitignoreHint);
	return lines.join("\n");
}

/** Add audit agents' usage to the session's usage totals (as `/session` reports them). */
export function recordUsage(ctx: ExtensionCommandContext, records: UsageRecord[], note: string): boolean {
	const manager = ctx.sessionManager as unknown as { appendUsage?: (kind: string, provider: string, model: string, usage: UsageRecord["usage"], note?: string) => unknown };
	if (typeof manager.appendUsage !== "function") return false;
	for (const record of records) manager.appendUsage(COMMAND_NAME, record.provider, record.model, record.usage, note);
	return true;
}

let running = false;

export async function runSecurityReview(pi: ExtensionAPI, args: string, ctx: ExtensionCommandContext): Promise<void> {
	const mode = parseMode(args);
	if (!mode) {
		ctx.ui.notify(`Unknown argument "${args.trim()}". ${USAGE}`, "error");
		return;
	}
	if (running) {
		ctx.ui.notify("A security review is already running in this session.", "warning");
		return;
	}

	const { settings, errors: settingsErrors } = resolveSettings(...readSettingsLayers(ctx.cwd, ctx.isProjectTrusted()));
	if (settingsErrors.length > 0) {
		ctx.ui.notify(`Invalid security-review settings:\n${settingsErrors.join("\n")}`, "error");
		return;
	}
	const { models, errors: modelErrors } = resolveRoleModels<Model<Api>>(settings, ctx.model, (provider, id) => ctx.modelRegistry.find(provider, id));
	if (!models) {
		ctx.ui.notify(`Cannot select models for the security review:\n${modelErrors.join("\n")}`, "error");
		return;
	}

	running = true;
	ctx.ui.setStatus(STATUS_KEY, statusText("scope"));
	try {
		const scope = await resolveScope(ctx.cwd, mode, { exclude: settings.exclude });
		const ledger = new UsageLedger();
		const runner = createSdkAgentRunner({
			root: scope.root,
			modelRuntime: await resolveModelRuntime(ctx.modelRegistry),
			thinkingLevel: ctx.thinkingLevel,
			timeoutMs: settings.agentTimeoutSeconds * 1000,
			ledger,
		});
		let result: RunResult;
		try {
			result = await runPipeline(scope, { runner, models, settings, onProgress: (progress) => ctx.ui.setStatus(STATUS_KEY, statusText(progress)) });
		} finally {
			// Usage is recorded even when the pipeline fails partway, so session totals stay accurate.
			recordUsage(ctx, ledger.entries(), `security-review ${mode}`);
		}
		const usage = formatUsage(ledger, result.agents.length);
		pi.sendMessage({
			customType: MESSAGE_TYPE,
			content: formatSummary(result, ctx.cwd, usage),
			display: true,
			details: {
				runId: result.run.id,
				mode,
				counts: result.counts,
				complete: result.run.complete,
				reportPath: result.reportPath,
				storePath: result.storePath,
				usage: ledger.total(),
			},
		});
	} catch (error) {
		if (error instanceof ScopeError) ctx.ui.notify(error.message, error.code === "empty" ? "info" : "error");
		else if (error instanceof StoreError) ctx.ui.notify(error.message, "error");
		else ctx.ui.notify(`Security review failed: ${(error as Error).message}`, "error");
	} finally {
		running = false;
		ctx.ui.setStatus(STATUS_KEY, undefined);
	}
}

export function registerSecurityReview(pi: ExtensionAPI): void {
	pi.registerCommand(COMMAND_NAME, {
		description: "Audit unmerged changes for security vulnerabilities (`full` audits the whole project)",
		getArgumentCompletions: (prefix) =>
			"full".startsWith(prefix.trim()) ? [{ value: "full", label: "full", description: "Audit the whole project instead of unmerged changes" }] : null,
		handler: (args, ctx) => runSecurityReview(pi, args, ctx),
	});
}
