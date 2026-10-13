import { constants, lstatSync, realpathSync } from "node:fs";
import { access, readFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
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
 * The real path of `path` or, when nothing exists there, of its nearest existing ancestor. Undefined at
 * a symbolic link that does not resolve: where it leads is unknown.
 */
function realLocation(path: string): string | undefined {
	for (let current = path; ; current = dirname(current)) {
		try {
			return realpathSync(current);
		} catch {
			try {
				lstatSync(current);
				return undefined;
			} catch {}
			if (dirname(current) === current) return current;
		}
	}
}

/**
 * Whether `path` (absolute, or relative to `root`) stays inside the project, both as written and after
 * symbolic links are resolved: a repository can contain a link that points at a file outside it. A path
 * that does not exist is judged by its nearest existing ancestor, and a link that does not resolve is
 * refused, so a missing file behind a link is refused like an existing one: the answer does not reveal
 * whether a file outside the project exists.
 */
export function isInsideProject(root: string, path: string): boolean {
	const resolved = resolve(root, path);
	if (escapes(root, resolved)) return false;
	const realRoot = realLocation(root);
	const real = realLocation(resolved);
	return realRoot !== undefined && real !== undefined && !escapes(realRoot, real);
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
