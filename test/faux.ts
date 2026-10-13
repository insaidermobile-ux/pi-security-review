import { join } from "node:path";
import { type AssistantMessage, fauxAssistantMessage, fauxProvider, type FauxResponseFactory, type Message } from "@earendil-works/pi-ai";
import { ModelRuntime } from "@earendil-works/pi-coding-agent";
import { tempDir } from "./temp.ts";

export { fauxAssistantMessage, fauxText, fauxToolCall } from "@earendil-works/pi-ai";

export type ScriptStep = AssistantMessage | FauxResponseFactory;

function textOf(message: Message): string {
	if (typeof message.content === "string") return message.content;
	return message.content.map((part) => ("text" in part ? part.text : "")).join("");
}

/**
 * A model runtime with a faux provider whose responses are routed per agent: the first script key
 * found in an agent's first user message selects its script, and the number of assistant turns so far
 * selects the step. Agents can therefore run in parallel deterministically.
 */
export async function scriptedRuntime(scripts: Record<string, ScriptStep[]>) {
	const dir = tempDir("sr-faux-");
	const runtime = await ModelRuntime.create({ authPath: join(dir, "auth.json"), modelsPath: null, refreshOnCreate: false });
	const cost = { input: 1, output: 2, cacheRead: 0, cacheWrite: 0 };
	const faux = fauxProvider({ provider: "faux", models: [{ id: "auditor", cost }, { id: "other-auditor", cost }] });
	runtime.registerNativeProvider(faux.provider);
	const calls: string[] = [];
	/** First user message of each scripted agent, by script key. */
	const prompts = new Map<string, string>();
	const router: FauxResponseFactory = async (context, options, state, model) => {
		const firstUser = context.messages.find((m) => m.role === "user");
		const text = firstUser ? textOf(firstUser) : "";
		const key = Object.keys(scripts).find((candidate) => text.includes(candidate));
		if (!key) return fauxAssistantMessage(`no script for agent: ${text.slice(0, 80)}`);
		const turn = context.messages.filter((m) => m.role === "assistant").length;
		calls.push(`${key}#${turn}`);
		if (turn === 0) prompts.set(key, text);
		const step = scripts[key]![turn];
		if (!step) return fauxAssistantMessage("nothing more to do");
		return typeof step === "function" ? step(context, options, state, model) : step;
	};
	faux.setResponses(Array.from({ length: 2000 }, () => router));
	const model = runtime.getModel("faux", "auditor")!;
	/** A second model on the same provider, for per-role overrides. */
	const otherModel = runtime.getModel("faux", "other-auditor")!;
	return { runtime, faux, model, otherModel, calls, prompts, root: dir };
}

/** A provider error response, for example a rate limit. */
export function providerError(errorMessage: string): AssistantMessage {
	return fauxAssistantMessage("", { stopReason: "error", errorMessage });
}

export const RATE_LIMITED = '429: {"code":"1302","message":"Rate limit reached for requests"}';

/**
 * A step that answers with a provider error for its first `times` calls, then delegates to `then`.
 * pi drops failed attempts from the conversation it replays, so retries and re-runs hit the same step.
 */
export function failTimes(times: number, errorMessage: string, then: ScriptStep): FauxResponseFactory {
	let calls = 0;
	return (context, options, state, model) => {
		if (calls++ < times) return providerError(errorMessage);
		return typeof then === "function" ? then(context, options, state, model) : then;
	};
}

/** A step that answers with `steps` in turn on successive calls, repeating the last one. */
export function inTurn(...steps: ScriptStep[]): FauxResponseFactory {
	let calls = 0;
	return (context, options, state, model) => {
		const step = steps[Math.min(calls++, steps.length - 1)]!;
		return typeof step === "function" ? step(context, options, state, model) : step;
	};
}

/** A step that never answers until the request is aborted. */
export const hang: FauxResponseFactory = (_context, options) =>
	new Promise((resolve) => {
		const done = () => resolve(fauxAssistantMessage("", { stopReason: "aborted" }));
		if (options?.signal?.aborted) done();
		options?.signal?.addEventListener("abort", done, { once: true });
	});
