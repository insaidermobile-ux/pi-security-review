/**
 * Drive pi in RPC mode with this package loaded, send one prompt (for example a slash command), and
 * print the extension UI events, custom messages, and session stats it produces.
 *
 *   node scripts/rpc-run.ts --cwd <dir> [--approve] [--installed] [--model provider/id] [--timeout 1800] -- "/security-review"
 *
 * --installed uses the packages installed in the active pi profile instead of loading this checkout
 * with discovery disabled.
 */
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const argv = process.argv.slice(2);
const sep = argv.indexOf("--");
const opts = sep >= 0 ? argv.slice(0, sep) : argv;
const message = sep >= 0 ? argv.slice(sep + 1).join(" ") : "/security-review";
const opt = (name: string) => {
	const i = opts.indexOf(`--${name}`);
	return i >= 0 ? opts[i + 1] : undefined;
};
const cwd = opt("cwd") ?? process.cwd();
const timeoutMs = Number(opt("timeout") ?? 1800) * 1000;
const packageDir = join(dirname(fileURLToPath(import.meta.url)), "..");

const piArgs = opts.includes("--installed") ? ["--mode", "rpc", "--no-session"] : ["--mode", "rpc", "-ne", "-ns", "-np", "-e", packageDir, "--no-session"];
if (opts.includes("--approve")) piArgs.push("--approve");
const model = opt("model");
if (model) piArgs.push("--model", model);

const child = spawn("pi", piArgs, { cwd, stdio: ["pipe", "pipe", "inherit"] });
const send = (command: object) => child.stdin.write(`${JSON.stringify(command)}\n`);
const started = Date.now();
const elapsed = () => `${((Date.now() - started) / 1000).toFixed(1)}s`;
const timer = setTimeout(() => {
	console.log(`[${elapsed()}] timeout`);
	child.kill();
	process.exit(2);
}, timeoutMs);

createInterface({ input: child.stdout }).on("line", (line) => {
	let event: Record<string, any>;
	try {
		event = JSON.parse(line);
	} catch {
		console.log(`[raw] ${line}`);
		return;
	}
	if (event.type === "extension_ui_request") {
		const detail = event.method === "setStatus" ? `${event.statusKey}=${JSON.stringify(event.statusText ?? null)}` : `${event.notifyType ?? ""} ${event.message ?? ""}`;
		console.log(`[${elapsed()}] ui.${event.method} ${detail}`);
	} else if (event.type === "message_end" && event.message?.role === "custom") {
		console.log(`[${elapsed()}] custom message (${event.message.customType}):\n${typeof event.message.content === "string" ? event.message.content : JSON.stringify(event.message.content)}`);
	} else if (event.type === "extension_error") {
		console.log(`[${elapsed()}] EXTENSION ERROR ${JSON.stringify(event)}`);
	} else if (event.type === "response" && event.id === "p1") {
		console.log(`[${elapsed()}] prompt handled: ${JSON.stringify({ success: event.success, error: event.error })}`);
		send({ id: "s1", type: "get_session_stats" });
	} else if (event.type === "response" && event.id === "s1") {
		console.log(`[${elapsed()}] session stats: ${JSON.stringify(event.data?.tokens)} cost=${event.data?.cost}`);
		clearTimeout(timer);
		child.kill();
	}
});

send({ id: "p1", type: "prompt", message });
