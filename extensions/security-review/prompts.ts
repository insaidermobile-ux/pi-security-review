import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AffirmArgument, Finding, Hypothesis, Profile } from "./schema.ts";
import type { Scope } from "./scope.ts";
import type { Role } from "./settings.ts";

const ROLES_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "roles");
/** File lists in prompts are capped; agents use find/ls for the rest. */
const MAX_LISTED_FILES = 400;

const cache = new Map<string, string>();

function readRole(name: string): string {
	let text = cache.get(name);
	if (text === undefined) {
		text = readFileSync(join(ROLES_DIR, `${name}.md`), "utf8").trim();
		cache.set(name, text);
	}
	return text;
}

export function systemPrompt(role: Role): string {
	return readRole(role).replace("{{common}}", readRole("common"));
}

export interface VulnClass {
	id: string;
	title: string;
	focus: string;
}

/** Vulnerability class clusters used to partition hunting in diff mode. */
export const VULN_CLASSES: readonly VulnClass[] = [
	{
		id: "injection",
		title: "Injection",
		focus: "SQL/NoSQL/LDAP/XPath injection, OS command injection, code evaluation (eval, Function, template engines, expression languages), server-side template injection, cross-site scripting, header and log injection.",
	},
	{
		id: "access-control",
		title: "Authentication and authorization",
		focus: "Missing or inconsistent authorization checks, insecure direct object references, privilege escalation, authentication bypass, session fixation, broken JWT or token validation, CSRF on state-changing endpoints, open redirects used in auth flows.",
	},
	{
		id: "secrets-crypto",
		title: "Secrets and cryptography",
		focus: "Hardcoded credentials and keys, secrets written to logs or responses, weak or misused cryptography (ECB, static IVs, MD5/SHA1 for passwords), non-constant-time secret comparison, predictable random values used for tokens, disabled TLS certificate verification.",
	},
	{
		id: "files-deserialization",
		title: "Files and deserialization",
		focus: "Path traversal, arbitrary file read or write, unsafe archive extraction (zip slip), unrestricted uploads, insecure deserialization (pickle, YAML, Java serialization, unsafe JSON revivers), XML external entities, prototype pollution.",
	},
	{
		id: "network-ssrf",
		title: "Network and SSRF",
		focus: "Server-side request forgery, URL validation bypasses, DNS rebinding exposure, unsafe proxying, overly permissive CORS, exposure of internal services, webhook and callback handling.",
	},
	{
		id: "logic-concurrency",
		title: "Business logic and concurrency",
		focus: "Race conditions and TOCTOU in security-relevant operations, double spending, broken state machines, missing rate limits on credential or payment operations, trust in client-supplied prices, roles, or identifiers.",
	},
];

export interface HuntAssignment {
	/** Stable partition label, e.g. "injection" or "src/api". */
	label: string;
	kind: "class" | "subtree";
	title: string;
	/** Vulnerability focus for class partitions. */
	focus?: string;
	/** Files owned by the assignment. */
	files: string[];
}

function header(label: string): string {
	return `Agent: ${label}`;
}

function json(value: unknown): string {
	return `\`\`\`json\n${JSON.stringify(value, null, 2)}\n\`\`\``;
}

function fileList(files: readonly string[]): string {
	const shown = files.slice(0, MAX_LISTED_FILES).map((file) => `- ${file}`);
	if (files.length > MAX_LISTED_FILES) shown.push(`- ... and ${files.length - MAX_LISTED_FILES} more (use find or ls to see them)`);
	return shown.join("\n");
}

function profileSection(profile: Profile | undefined): string {
	return profile ? `## Project profile\n\n${json(profile)}` : "## Project profile\n\nNo profile is available; orient yourself from the manifests and layout first.";
}

export function profilePrompt(scope: Scope): string {
	return [
		header("profile"),
		"Profile this project for a security review.",
		`The review mode is \`${scope.mode}\`. ${scope.mode === "diff" ? "Only some files changed, but profile the whole project: later agents need the full context." : "The whole project will be audited."}`,
		`## Files in review scope (${scope.files.length})\n\n${fileList(scope.files)}`,
	].join("\n\n");
}

export function huntPrompt(profile: Profile | undefined, scope: Scope, assignment: HuntAssignment): string {
	const parts = [header(`hunt:${assignment.label}`), profileSection(profile)];
	if (assignment.kind === "class") {
		parts.push(
			`## Assignment: ${assignment.title}\n\nHunt only for this class of issues in the changed code:\n\n${assignment.focus}\n\nOther agents cover the other classes. You may read any file in the project to trace data flow, but only report issues whose flaw is in, or is introduced or exposed by, the changes below.`,
		);
		parts.push(`## Changed files (${scope.files.length})\n\n${fileList(scope.files)}`);
		if (scope.untracked?.length) parts.push(`New untracked files (not in the diff; read them directly):\n\n${fileList(scope.untracked)}`);
		parts.push(
			`## Diff against ${scope.baseRef} (merge-base ${scope.mergeBase?.slice(0, 12)})\n\n${scope.diffTruncated ? "The diff was truncated; read the changed files directly for the rest.\n\n" : ""}\`\`\`diff\n${scope.diff ?? ""}\n\`\`\``,
		);
	} else {
		parts.push(
			`## Assignment: ${assignment.title}\n\nAudit the files below for vulnerabilities of every class. Other agents own the rest of the project. You may read any file to trace data flow, but only report issues whose flaw is located in your files.\n\nClasses to consider:\n\n${VULN_CLASSES.map((c) => `- **${c.title}**: ${c.focus}`).join("\n")}`,
		);
		parts.push(`## Your files (${assignment.files.length})\n\n${fileList(assignment.files)}`);
	}
	return parts.join("\n\n");
}

function hypothesisSection(hypothesis: Hypothesis): string {
	const { fingerprint: _fingerprint, source_partition: _partition, ...visible } = hypothesis;
	return `## Hypothesis ${hypothesis.id}\n\n${json(visible)}`;
}

export function affirmerPrompt(profile: Profile | undefined, hypothesis: Hypothesis, scope: Scope): string {
	return [
		header(`affirmer:${hypothesis.id}`),
		profileSection(profile),
		hypothesisSection(hypothesis),
		scope.mode === "diff" ? `This hypothesis was raised while reviewing changes against ${scope.baseRef}.` : "This hypothesis was raised during a full-project review.",
		`Build the case and submit it with \`submit_argument\` using \`hypothesis_id: "${hypothesis.id}"\`.`,
	].join("\n\n");
}

export function challengerPrompt(profile: Profile | undefined, hypothesis: Hypothesis, argument: AffirmArgument, prior?: Finding): string {
	const parts = [header(`challenger:${hypothesis.id}`), profileSection(profile), hypothesisSection(hypothesis), `## Affirmer's argument\n\n${json(argument)}`];
	if (prior) {
		parts.push(
			`## Previous verdict: false positive\n\nThe project's developers marked an earlier finding for the same issue (${prior.id}, "${prior.title}") as a false positive. The challenger reasoning recorded then was:\n\n${json(prior.verification.challenger)}\n\nConfirm this hypothesis again only if you have new evidence that the earlier reasoning is wrong, and state that evidence in your reasoning.`,
		);
	}
	parts.push(`Challenge the argument and submit your verdict with \`submit_argument\` using \`hypothesis_id: "${hypothesis.id}"\`.`);
	return parts.join("\n\n");
}

export interface ReportStats {
	mode: Scope["mode"];
	files: number;
	hypotheses: number;
	vulnerabilities: number;
	risks: number;
	refuted: number;
	unverified: number;
	complete: boolean;
	incompleteReasons: string[];
}

export function reportPrompt(stats: ReportStats, findings: Finding[]): string {
	const compact = findings.map((f) => ({
		id: f.id,
		title: f.title,
		class: f.finding_class,
		severity: f.severity,
		confidence: f.confidence,
		anchors: f.anchors,
		status: f.status,
		detail: f.description.detail,
	}));
	return [header("report"), `## Run statistics\n\n${json(stats)}`, `## Findings from this run\n\n${json(compact)}`, "Write the executive summary and submit it with `submit_summary`."].join(
		"\n\n",
	);
}
