import { spawn } from "node:child_process";
import { defineTool } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { isInsideProject } from "./read-tools.ts";
import { GIT_ENV, safeGitConfig } from "./scope.ts";

export const SHELL_TOOL_NAME = "shell";
const MAX_OUTPUT_BYTES = 50_000;
const COMMAND_TIMEOUT_MS = 30_000;

/** Git subcommands that only read repository state. */
const GIT_SUBCOMMANDS = new Set(["log", "show", "blame", "diff", "grep", "ls-files", "ls-tree", "rev-parse", "status", "cat-file"]);
/** Hardening options per subcommand: external diff drivers and textconv run programs from the repository's config. */
const GIT_HARDENING = new Map<string, string[]>([
	["log", ["--no-ext-diff", "--no-textconv"]],
	["show", ["--no-ext-diff", "--no-textconv"]],
	["diff", ["--no-ext-diff", "--no-textconv"]],
	["blame", ["--no-textconv"]],
]);

/** Options of one command that write files, run other programs, or read outside the project. */
interface OptionRules {
	/** Long options. Every prefix of one is refused too, because git accepts unambiguous abbreviations. */
	long: readonly string[];
	/** Long options that are a prefix of a denied one but are safe themselves. */
	exact: readonly string[];
	/** Short flags, also refused inside a combined argument such as `-zl`. */
	short: string;
	/** Short options that take a value: the rest of a combined argument is that value, not more flags. */
	shortWithValue: string;
}

const NO_RULES: OptionRules = { long: [], exact: [], short: "", shortWithValue: "" };
const GIT_RULES: OptionRules = {
	// Submodules have their own config, whose filter drivers safeGitConfig does not see.
	long: ["--output", "--ext-diff", "--textconv", "--open-files-in-pager", "--exec", "--upload-pack", "--ignore-submodules", "--submodule", "--recurse-submodules"],
	exact: ["--text"],
	short: "",
	shortWithValue: "",
};
/** `git grep -O<pager>` runs the pager; elsewhere `-O` only names an order file. */
const GIT_GREP_RULES: OptionRules = { ...GIT_RULES, short: "O", shortWithValue: "efABCm" };

const OPTION_RULES = new Map<string, OptionRules>([
	["git", GIT_RULES],
	["rg", { long: ["--pre", "--pre-glob", "--search-zip", "--hostname-bin", "--follow"], exact: [], short: "zL", shortWithValue: "efgtTABCmMjdEr" }],
	["tail", { long: ["--follow", "--retry"], exact: [], short: "fF", shortWithValue: "ncb" }],
	["cat", NO_RULES],
	["head", NO_RULES],
	// Following a symlink inside a listed directory (-L, -H) reaches files outside the project that no argument names.
	["ls", { long: ["--dereference", "--dereference-command-line", "--dereference-command-line-symlink-to-dir"], exact: [], short: "LH", shortWithValue: "" }],
	// GNU wc --files0-from opens every path listed in a file, which the per-argument path check never sees.
	["wc", { long: ["--files0-from"], exact: [], short: "", shortWithValue: "" }],
]);

export const ALLOWED_COMMANDS = [...OPTION_RULES.keys()];

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

/** Check one option against the rules and return the values embedded in it, which are checked as paths. */
function optionValues(program: string, arg: string, rules: OptionRules): string[] {
	const refuse = () => new ShellRejection(`Option ${arg} is not allowed for ${program}.`);
	const equals = arg.indexOf("=");
	const afterEquals = equals < 0 ? [] : [arg.slice(equals + 1)];
	if (arg.startsWith("--")) {
		const name = equals < 0 ? arg : arg.slice(0, equals);
		if (!rules.exact.includes(name) && rules.long.some((option) => option.startsWith(name))) throw refuse();
		return afterEquals;
	}
	for (let i = 1; i < arg.length; i++) {
		if (rules.short.includes(arg[i]!)) throw refuse();
		if (rules.shortWithValue.includes(arg[i]!)) return [arg.slice(i + 1).replace(/^=/, "")];
	}
	return afterEquals;
}

function assertInsideRoot(root: string, value: string): void {
	if (value.startsWith("~") || !isInsideProject(root, value)) {
		throw new ShellRejection(
			`Path ${value} is outside the project. Arguments that look like a path outside it are refused even when meant as a search pattern; rewrite such a pattern, for example as [/]etc.`,
		);
	}
}

/** Validate a command against the allowlist and return the argv to execute. Throws ShellRejection otherwise. */
export function checkCommand(command: string, root: string): string[] {
	const argv = tokenize(command.trim());
	const program = argv[0];
	if (!program) throw new ShellRejection("Empty command.");
	let rules = OPTION_RULES.get(program);
	if (!rules) {
		throw new ShellRejection(`Command "${program}" is not allowed. Allowed commands: ${ALLOWED_COMMANDS.join(", ")}. Use the read, grep, find, and ls tools for other inspection.`);
	}
	const args = argv.slice(1);
	if (program === "git") {
		const sub = args[0];
		if (!sub || !GIT_SUBCOMMANDS.has(sub)) {
			throw new ShellRejection(`"git ${sub ?? ""}" is not allowed. The subcommand must come first and be one of: ${[...GIT_SUBCOMMANDS].join(", ")}.`);
		}
		if (sub === "grep") rules = GIT_GREP_RULES;
	}
	let options = true;
	for (const arg of args) {
		if (options && arg === "--") options = false;
		else if (options && arg.startsWith("-") && arg.length > 1) for (const value of optionValues(program, arg, rules)) assertInsideRoot(root, value);
		else assertInsideRoot(root, arg);
	}
	if (program === "git") {
		const [sub, ...rest] = args;
		return ["git", "-c", "core.pager=cat", "--no-pager", sub!, ...(GIT_HARDENING.get(sub!) ?? []), ...rest];
	}
	return argv;
}

interface ShellResult {
	exitCode: number;
	output: string;
	truncated: boolean;
}

/** Collects a stream's output up to the cap and counts the rest, so a huge output cannot exhaust memory. */
function capture(stream: NodeJS.ReadableStream): { text: () => string; overflowed: () => boolean } {
	const chunks: Buffer[] = [];
	let kept = 0;
	let dropped = false;
	stream.on("data", (chunk: Buffer) => {
		if (kept < MAX_OUTPUT_BYTES) chunks.push(chunk.subarray(0, MAX_OUTPUT_BYTES - kept));
		if (kept + chunk.length > MAX_OUTPUT_BYTES) dropped = true;
		kept = Math.min(MAX_OUTPUT_BYTES, kept + chunk.length);
	});
	return { text: () => Buffer.concat(chunks).toString(), overflowed: () => dropped };
}

export async function runChecked(argv: string[], root: string, signal?: AbortSignal): Promise<ShellResult> {
	const command = argv[0] === "git" ? ["git", ...(await safeGitConfig(root)), ...argv.slice(1)] : argv;
	return new Promise((resolvePromise) => {
		// stdin is closed: with an open pipe, rg and cat without a path argument would wait for input.
		const child = spawn(command[0]!, command.slice(1), {
			cwd: root,
			signal,
			stdio: ["ignore", "pipe", "pipe"],
			env: { ...process.env, ...GIT_ENV, PAGER: "cat", GIT_PAGER: "cat" },
		});
		const stdout = capture(child.stdout);
		const stderr = capture(child.stderr);
		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			child.kill();
		}, COMMAND_TIMEOUT_MS);
		let settled = false;
		const finish = (exitCode: number, note?: string) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			const errors = stderr.text();
			let output = `${stdout.text()}${errors ? `\n[stderr]\n${errors}` : ""}`;
			const truncated = stdout.overflowed() || stderr.overflowed() || Buffer.byteLength(output) > MAX_OUTPUT_BYTES;
			if (truncated) {
				output = `${Buffer.from(output).subarray(0, MAX_OUTPUT_BYTES).toString()}\n[output truncated at ${MAX_OUTPUT_BYTES} bytes; narrow the command]`;
			}
			if (note) output += `\n[${note}]`;
			resolvePromise({ exitCode, output, truncated });
		};
		child.on("error", (error) => finish(1, error.message));
		child.on("close", (code, killSignal) => {
			if (timedOut) finish(1, `timed out after ${COMMAND_TIMEOUT_MS / 1000} s; narrow the command`);
			else finish(code ?? 1, code === null ? `terminated by ${killSignal}` : undefined);
		});
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
