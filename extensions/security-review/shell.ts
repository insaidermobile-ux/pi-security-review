import { execFile } from "node:child_process";
import { isAbsolute, relative, resolve } from "node:path";
import { defineTool } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

export const SHELL_TOOL_NAME = "shell";
const MAX_OUTPUT_BYTES = 50_000;
const COMMAND_TIMEOUT_MS = 30_000;

/** Git subcommands that only read repository state. */
const GIT_SUBCOMMANDS = new Set(["log", "show", "blame", "diff", "grep", "ls-files", "ls-tree", "rev-parse", "status", "cat-file"]);
/** Subcommands that render diffs, where external diff drivers and textconv filters are disabled. */
const GIT_DIFF_RENDERING = new Set(["log", "show", "diff"]);

/** Options that write files or run other programs, per command. A trailing "=" also matches "--opt=value". */
const DENIED_OPTIONS: Record<string, readonly string[]> = {
	git: ["--output", "--ext-diff", "--textconv", "-O", "--open-files-in-pager", "--exec", "--upload-pack"],
	rg: ["--pre", "--pre-glob", "-z", "--search-zip", "--hostname-bin"],
	tail: ["-f", "-F", "--follow", "--retry"],
	cat: [],
	head: [],
	ls: [],
	wc: [],
};

export const ALLOWED_COMMANDS = Object.keys(DENIED_OPTIONS);

export class ShellRejection extends Error {
	constructor(message: string) {
		super(message);
		this.name = "ShellRejection";
	}
}

/**
 * Split a command line into argv like a POSIX shell would for plain words and quotes, without any
 * expansion. Unquoted shell operators are rejected because no shell interprets them.
 */
export function tokenize(command: string): string[] {
	const argv: string[] = [];
	let current = "";
	let inWord = false;
	let quote: "'" | '"' | undefined;
	for (let i = 0; i < command.length; i++) {
		const char = command[i]!;
		if (quote) {
			if (char === quote) quote = undefined;
			else if (char === "\\" && quote === '"' && i + 1 < command.length && '"\\'.includes(command[i + 1]!)) current += command[++i];
			else current += char;
			continue;
		}
		if (char === "'" || char === '"') {
			quote = char;
			inWord = true;
		} else if (char === "\\" && i + 1 < command.length) {
			current += command[++i];
			inWord = true;
		} else if (char === " " || char === "\t") {
			if (inWord) argv.push(current);
			current = "";
			inWord = false;
		} else if ("|&;<>()$`\n\r".includes(char)) {
			throw new ShellRejection(
				`Shell operator ${JSON.stringify(char)} is not supported: commands run without a shell, one at a time, with no pipes, redirection, chaining, or substitution.`,
			);
		} else {
			current += char;
			inWord = true;
		}
	}
	if (quote) throw new ShellRejection("Unterminated quote in command.");
	if (inWord) argv.push(current);
	return argv;
}

function isDenied(arg: string, denied: readonly string[]): boolean {
	return denied.some((option) => {
		if (arg === option || arg.startsWith(`${option}=`)) return true;
		// Combined short flags such as `-zl` or attached values such as `-Ocat`.
		return /^-[A-Za-z]$/.test(option) && /^-[A-Za-z]/.test(arg) && !arg.startsWith("--") && arg.slice(1).includes(option[1]!);
	});
}

function looksLikePath(value: string): boolean {
	return isAbsolute(value) || value.startsWith("~") || value === ".." || value.startsWith("../") || value.includes("/../") || value.endsWith("/..");
}

function assertInsideRoot(root: string, value: string): void {
	if (!looksLikePath(value)) return;
	if (value.startsWith("~")) throw new ShellRejection(`Path ${value} is outside the project.`);
	const rel = relative(root, resolve(root, value));
	if (rel === ".." || rel.startsWith("../") || isAbsolute(rel)) throw new ShellRejection(`Path ${value} is outside the project.`);
}

/** Validate a command against the allowlist and return the argv to execute. Throws ShellRejection otherwise. */
export function checkCommand(command: string, root: string): string[] {
	const argv = tokenize(command.trim());
	const program = argv[0];
	if (!program) throw new ShellRejection("Empty command.");
	if (!(program in DENIED_OPTIONS)) {
		throw new ShellRejection(`Command "${program}" is not allowed. Allowed commands: ${ALLOWED_COMMANDS.join(", ")}. Use the read, grep, find, and ls tools for other inspection.`);
	}
	const args = argv.slice(1);
	if (program === "git") {
		const sub = args[0];
		if (!sub || !GIT_SUBCOMMANDS.has(sub)) {
			throw new ShellRejection(`"git ${sub ?? ""}" is not allowed. The subcommand must come first and be one of: ${[...GIT_SUBCOMMANDS].join(", ")}.`);
		}
	}
	for (const arg of args) {
		if (isDenied(arg, DENIED_OPTIONS[program]!)) throw new ShellRejection(`Option ${arg} is not allowed for ${program}.`);
		const value = arg.startsWith("-") && arg.includes("=") ? arg.slice(arg.indexOf("=") + 1) : arg;
		assertInsideRoot(root, value);
	}
	if (program === "git") {
		const [sub, ...rest] = args;
		const hardening = GIT_DIFF_RENDERING.has(sub!) ? ["--no-ext-diff", "--no-textconv"] : [];
		return ["git", "-c", "core.fsmonitor=false", "-c", "core.pager=cat", "--no-pager", sub!, ...hardening, ...rest];
	}
	return argv;
}

interface ShellResult {
	exitCode: number;
	output: string;
	truncated: boolean;
}

export function runChecked(argv: string[], root: string, signal?: AbortSignal): Promise<ShellResult> {
	return new Promise((resolvePromise) => {
		execFile(
			argv[0]!,
			argv.slice(1),
			{
				cwd: root,
				timeout: COMMAND_TIMEOUT_MS,
				maxBuffer: 8 * 1024 * 1024,
				signal,
				env: { ...process.env, GIT_OPTIONAL_LOCKS: "0", GIT_TERMINAL_PROMPT: "0", PAGER: "cat", GIT_PAGER: "cat" },
			},
			(error, stdout, stderr) => {
				let output = `${stdout}${stderr ? `\n[stderr]\n${stderr}` : ""}`;
				const truncated = Buffer.byteLength(output) > MAX_OUTPUT_BYTES;
				if (truncated) {
					output = `${Buffer.from(output).subarray(0, MAX_OUTPUT_BYTES).toString()}\n[output truncated at ${MAX_OUTPUT_BYTES} bytes; narrow the command]`;
				}
				const exitCode = error ? (typeof error.code === "number" ? error.code : 1) : 0;
				if (error && typeof error.code !== "number") output += `\n[${error.message}]`;
				resolvePromise({ exitCode, output, truncated });
			},
		);
	});
}

/** Read-only shell tool: an allowlist of inspection commands executed without a shell inside `root`. */
export function createShellTool(root: string) {
	return defineTool({
		name: SHELL_TOOL_NAME,
		label: "Read-only shell",
		description:
			`Run one read-only inspection command in the project root. Allowed: git (${[...GIT_SUBCOMMANDS].join(", ")}), rg, cat, head, tail, ls, wc. ` +
			"No shell: pipes, redirection, chaining, globs, and variable expansion are not supported. Paths must stay inside the project.",
		promptSnippet: "shell: read-only git/rg/cat/head/tail/ls/wc commands without pipes",
		parameters: Type.Object({ command: Type.String({ minLength: 1, description: 'e.g. "git log -n 5 -- src/auth.ts" or "rg -n createUser src"' }) }),
		annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
		async execute(_toolCallId, params, signal) {
			const argv = checkCommand(params.command, root);
			const result = await runChecked(argv, root, signal);
			return {
				content: [{ type: "text", text: `exit ${result.exitCode}\n${result.output || "(no output)"}` }],
				details: { exitCode: result.exitCode, truncated: result.truncated },
			};
		},
	});
}
