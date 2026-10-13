import { createHash } from "node:crypto";
import type { Anchor } from "./schema.ts";

const VULN_TYPE_ALIASES: Record<string, string> = {
	sqli: "sql-injection",
	"sql-injection-attack": "sql-injection",
	"os-command-injection": "command-injection",
	"shell-injection": "command-injection",
	"directory-traversal": "path-traversal",
	"cross-site-scripting": "xss",
	"server-side-request-forgery": "ssrf",
	"broken-access-control": "missing-authz",
	"missing-authorization": "missing-authz",
	"insecure-direct-object-reference": "idor",
};

/** Canonical vulnerability type: lowercase words joined by dashes, with common synonyms folded. */
export function normalizeVulnType(vulnType: string): string {
	const canonical = vulnType
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "");
	return VULN_TYPE_ALIASES[canonical] ?? canonical;
}

const IDENTIFIER = /[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*/g;

/**
 * Canonical code identifier from a free-text description: the first dotted name or call (`db.query`,
 * `exec(`), else the first identifier. Models describe the same sink with different prose around it;
 * the API name is the stable part.
 */
export function leadingIdentifier(text: string): string {
	const matches = [...text.matchAll(IDENTIFIER)];
	const called = matches.find((m) => m[0].includes(".") || text[m.index! + m[0].length] === "(");
	return (called ?? matches[0])?.[0].toLowerCase() ?? "";
}

/** Canonical sink: the API or function name it starts with. */
export function normalizeSink(sink: string): string {
	return leadingIdentifier(sink);
}

export function normalizePath(file: string): string {
	return file.replace(/\\/g, "/").replace(/^\.\//, "");
}

/**
 * Stable identity of a finding across runs: vulnerability type, primary anchor file and enclosing
 * function, and the sink. Line numbers are deliberately excluded so code movement does not matter.
 */
export function fingerprint(input: { vuln_type: string; anchors: Anchor[]; suspected_sink: string }): string {
	const primary = input.anchors[0];
	const parts = [
		normalizeVulnType(input.vuln_type),
		primary ? normalizePath(primary.file) : "",
		primary?.function ? leadingIdentifier(primary.function) : "",
		normalizeSink(input.suspected_sink),
	];
	return createHash("sha256").update(parts.join("\u0000")).digest("hex").slice(0, 16);
}

/** "<component>: <vulnerability type> leading to <consequence>" */
export function formatTitle(component: string, vulnType: string, consequence: string): string {
	const type = normalizeVulnType(vulnType).replace(/-/g, " ");
	return `${component.trim()}: ${type} leading to ${consequence.trim().replace(/\.$/, "")}`;
}
