import { constants, realpathSync } from "node:fs";
import { access, readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import {
	createFindToolDefinition,
	createGrepToolDefinition,
	createLsToolDefinition,
	createReadToolDefinition,
	detectSupportedImageMimeTypeFromFile,
	type ToolDefinition,
} from "@earendil-works/pi-coding-agent";

function escapes(from: string, to: string): boolean {
	const rel = relative(from, to);
	return rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel);
}

/**
 * Whether `path` (absolute, or relative to `root`) stays inside the project, both as written and after
 * symbolic links are resolved: a repository can contain a link that points at a file outside it.
 */
export function isInsideProject(root: string, path: string): boolean {
	const resolved = resolve(root, path);
	if (escapes(root, resolved)) return false;
	try {
		return !escapes(realpathSync(root), realpathSync(resolved));
	} catch {
		// Nothing exists at the path, so nothing can be read through it.
		return true;
	}
}

export function outsideProjectMessage(path: string): string {
	return `Path ${path} is outside the project. Audit agents read only files inside the audited project.`;
}

const UNICODE_SPACES = /[  -   　]/g;

/**
 * The path pi's grep, find, and ls resolve for a `path` argument: they fold Unicode spaces and drop a
 * leading "@" before resolving. Undefined for a home-directory or file-URL path, which pi would expand.
 */
function asPiResolves(path: string): string | undefined {
	const normalized = path.replace(UNICODE_SPACES, " ").replace(/^@/, "");
	return normalized.startsWith("~") || /^file:/i.test(normalized) ? undefined : normalized;
}

function confined(root: string, tool: ToolDefinition): ToolDefinition {
	return {
		...tool,
		async execute(toolCallId, params, signal, onUpdate, ctx) {
			const path = (params as { path?: string }).path;
			if (path !== undefined) {
				const resolved = asPiResolves(path);
				if (resolved === undefined || !isInsideProject(root, resolved)) throw new Error(outsideProjectMessage(path));
			}
			return tool.execute(toolCallId, params, signal, onUpdate, ctx);
		},
	};
}

/**
 * pi's read, grep, find, and ls, confined to the project; `write`, `edit`, and `bash` are never given
 * to audit agents. The built-ins resolve absolute and home-relative paths, which would let an agent
 * steered by the audited code read the user's files and copy them into the report.
 */
export function createReadOnlyTools(root: string): ToolDefinition[] {
	const guard = (path: string) => {
		if (!isInsideProject(root, path)) throw new Error(outsideProjectMessage(path));
	};
	// read tries alternative spellings of a missing file name, so its guard sees the final path.
	const read = createReadToolDefinition(root, {
		operations: {
			access: async (path) => {
				guard(path);
				await access(path, constants.R_OK);
			},
			readFile: async (path) => {
				guard(path);
				return readFile(path);
			},
			detectImageMimeType: detectSupportedImageMimeTypeFromFile,
		},
	});
	const searching = [createGrepToolDefinition(root), createFindToolDefinition(root), createLsToolDefinition(root)];
	return [read as unknown as ToolDefinition, ...searching.map((tool) => confined(root, tool as unknown as ToolDefinition))];
}
