import { existsSync, readFileSync, statSync } from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";
import { defineTool, type ToolDefinition } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { normalizePath } from "./fingerprint.ts";
import {
	type AffirmArgument,
	AffirmArgument as AffirmArgumentSchema,
	type Anchor,
	type ChallengeArgument,
	ChallengeArgument as ChallengeArgumentSchema,
	type HypothesisInput,
	HypothesisInput as HypothesisInputSchema,
	type Profile,
	ProfileInput,
	SummaryInput,
} from "./schema.ts";

const Receipt = Type.Object({ recorded: Type.Boolean(), message: Type.String() });

function receipt(message: string, terminate = false) {
	return {
		content: [{ type: "text" as const, text: message }],
		structuredContent: { recorded: true, message },
		details: undefined,
		terminate,
	};
}

/** Anchors must point at existing lines of files inside the project; paths are normalized to project-relative. */
export function checkAnchors(root: string, anchors: Anchor[]): Anchor[] {
	return anchors.map((anchor) => {
		const absolute = resolve(root, anchor.file);
		const rel = normalizePath(relative(root, absolute));
		if (rel.startsWith("../") || isAbsolute(rel)) throw new Error(`Anchor file ${anchor.file} is outside the project.`);
		if (!existsSync(absolute) || !statSync(absolute).isFile()) throw new Error(`Anchor file ${anchor.file} does not exist. Use a path relative to the project root.`);
		const lines = readFileSync(join(root, rel), "utf8").split("\n").length;
		if (anchor.line > lines) throw new Error(`Anchor ${rel}:${anchor.line} is past the end of the file (${lines} lines).`);
		return { ...anchor, file: rel };
	});
}

export interface ProfileCollector {
	profile?: Profile;
}

export function createProfileTool(collector: ProfileCollector): ToolDefinition {
	return defineTool({
		name: "submit_profile",
		label: "Submit project profile",
		description: "Submit the project profile. Call exactly once when your investigation is complete.",
		parameters: ProfileInput,
		outputSchema: Receipt,
		async execute(_id, params) {
			collector.profile = params;
			return receipt("Profile recorded. You are done.", true);
		},
	}) as unknown as ToolDefinition;
}

export interface HypothesisCollector {
	hypotheses: HypothesisInput[];
}

export function createHypothesisTool(root: string, collector: HypothesisCollector): ToolDefinition {
	return defineTool({
		name: "submit_hypothesis",
		label: "Submit hypothesis",
		description:
			"Submit one candidate vulnerability for independent verification. Call once per distinct issue. Anchors must be existing file:line locations relative to the project root.",
		parameters: HypothesisInputSchema,
		outputSchema: Receipt,
		executionMode: "sequential",
		async execute(_id, params) {
			const anchors = checkAnchors(root, params.anchors);
			collector.hypotheses.push({ ...params, anchors });
			return receipt(`Hypothesis #${collector.hypotheses.length} recorded. Continue hunting, or stop when you have nothing more to report.`);
		},
	}) as unknown as ToolDefinition;
}

export interface ArgumentCollector<T> {
	argument?: T;
}

function checkHypothesisId(expected: string, actual: string): void {
	if (actual !== expected) throw new Error(`hypothesis_id must be "${expected}", got "${actual}".`);
}

export function createAffirmTool(hypothesisId: string, collector: ArgumentCollector<AffirmArgument>): ToolDefinition {
	return defineTool({
		name: "submit_argument",
		label: "Submit affirmer argument",
		description: `Submit your argument that hypothesis ${hypothesisId} is exploitable. Call exactly once.`,
		parameters: AffirmArgumentSchema,
		outputSchema: Receipt,
		async execute(_id, params) {
			checkHypothesisId(hypothesisId, params.hypothesis_id);
			collector.argument = params;
			return receipt("Argument recorded. You are done.", true);
		},
	}) as unknown as ToolDefinition;
}

export function createChallengeTool(hypothesisId: string, collector: ArgumentCollector<ChallengeArgument>): ToolDefinition {
	return defineTool({
		name: "submit_argument",
		label: "Submit challenger argument",
		description: `Submit your challenge and verdict for hypothesis ${hypothesisId}. Call exactly once.`,
		parameters: ChallengeArgumentSchema,
		outputSchema: Receipt,
		async execute(_id, params) {
			checkHypothesisId(hypothesisId, params.hypothesis_id);
			collector.argument = params;
			return receipt("Verdict recorded. You are done.", true);
		},
	}) as unknown as ToolDefinition;
}

export function createSummaryTool(collector: { summary?: string }): ToolDefinition {
	return defineTool({
		name: "submit_summary",
		label: "Submit summary",
		description: "Submit the executive summary. Call exactly once.",
		parameters: SummaryInput,
		outputSchema: Receipt,
		async execute(_id, params) {
			collector.summary = params.summary;
			return receipt("Summary recorded. You are done.", true);
		},
	}) as unknown as ToolDefinition;
}
