import assert from "node:assert/strict";
import { afterEach, describe, test } from "node:test";
import type { FauxResponseFactory } from "@earendil-works/pi-ai";
import { createSdkAgentRunner, UsageLedger } from "../extensions/security-review/agent-runtime.ts";
import { BRIDGE_PROVIDER, recordBridgePrompt } from "../extensions/security-review/bridge.ts";
import { createHypothesisTool, type HypothesisCollector } from "../extensions/security-review/submit-tools.ts";
import { fauxAssistantMessage, fauxToolCall, providerError, scriptedRuntime } from "./faux.ts";
import { hypothesisInput } from "./fixtures.ts";
import { makeFixtureRepo } from "./git-fixtures.ts";

const REGISTRY_KEY = Symbol.for("claude-bridge:promptCaptures");
const globals = globalThis as Record<symbol, unknown>;

type Recorded = { systemPrompt: string; input: { custom?: string; contextFiles: unknown[]; skills: unknown[] }; source?: string };

/** A stand-in for the bridge's process-wide prompt registry. */
function fakeRegistry(): Recorded[] {
	const recorded: Recorded[] = [];
	globals[REGISTRY_KEY] = { record: (systemPrompt: string, input: Recorded["input"], source?: string) => recorded.push({ systemPrompt, input, source }) };
	return recorded;
}

/** Like the bridge: refuse any request whose system prompt was not recorded. */
function bridgeGate(recorded: Recorded[], then: FauxResponseFactory | ReturnType<typeof fauxAssistantMessage>): FauxResponseFactory {
	return (context, options, state, model) => {
		// The rendered prompt: the leading system message's content followed by its sections.
		const system = context.messages.find((m) => m.role === "system");
		const content = typeof system?.content === "string" ? system.content : (system?.content ?? []).map((part) => part.text).join("");
		const prompt = [content, ...Object.values(system?.sections ?? {})].filter(Boolean).join("\n\n");
		if (!recorded.some((r) => r.systemPrompt === prompt)) return providerError("prompt-capture: no capture for this system prompt");
		return typeof then === "function" ? then(context, options, state, model) : then;
	};
}

afterEach(() => {
	delete globals[REGISTRY_KEY];
});

describe("bridge prompt registry", () => {
	test("records the rendered prompt with only the role instructions", () => {
		const recorded = fakeRegistry();
		assert.equal(recordBridgePrompt("RENDERED", "ROLE"), true);
		assert.deepEqual(recorded, [{ systemPrompt: "RENDERED", input: { custom: "ROLE", contextFiles: [], skills: [] }, source: "pi-security-review" }]);
	});

	test("does nothing without a usable registry", () => {
		assert.equal(recordBridgePrompt("RENDERED", "ROLE"), false);
		globals[REGISTRY_KEY] = { record: "not a function" };
		assert.equal(recordBridgePrompt("RENDERED", "ROLE"), false);
	});
});

describe("audit agents on a bridge model", () => {
	const SYSTEM = "You are a test auditor.";

	test("register their prompt for every request, including later turns and the nudge", async () => {
		const recorded = fakeRegistry();
		const root = makeFixtureRepo();
		const { runtime, model, calls } = await scriptedRuntime(
			{
				"BRIDGED-AGENT": [
					bridgeGate(recorded, fauxAssistantMessage("looked around, nothing submitted yet")),
					bridgeGate(recorded, fauxAssistantMessage(fauxToolCall("submit_hypothesis", hypothesisInput({ anchors: [{ file: "src/users.js", line: 6 }] })))),
					bridgeGate(recorded, fauxAssistantMessage("submitted")),
				],
			},
			{ provider: BRIDGE_PROVIDER },
		);
		assert.equal(model.provider, BRIDGE_PROVIDER);
		const collector: HypothesisCollector = { hypotheses: [] };
		const runner = createSdkAgentRunner({ root, modelRuntime: runtime, timeoutMs: 10_000, ledger: new UsageLedger() });
		const outcome = await runner.run({
			label: "hunt:injection",
			role: "hunt",
			model,
			systemPrompt: SYSTEM,
			prompt: "BRIDGED-AGENT go",
			tools: [createHypothesisTool(root, collector)],
			done: () => collector.hypotheses.length > 0,
			nudge: "Submit now.",
		});
		assert.equal(outcome.ok, true, outcome.error);
		assert.equal(collector.hypotheses.length, 1);
		assert.deepEqual(calls, ["BRIDGED-AGENT#0", "BRIDGED-AGENT#1", "BRIDGED-AGENT#2"]);
		assert.ok(recorded.length >= 3, "recorded before the prompt, before the nudge, and on each turn");
		assert.ok(recorded.every((r) => r.input.custom === SYSTEM && r.systemPrompt.startsWith(SYSTEM)));
	});

	test("without registration the bridge refuses the request", async () => {
		const recorded = fakeRegistry();
		const root = makeFixtureRepo();
		// Same gate, but the agent runs on another provider, so nothing is recorded and nothing is gated by provider.
		const { runtime, model } = await scriptedRuntime({ "PLAIN-AGENT": [bridgeGate(recorded, fauxAssistantMessage("ok"))] });
		const runner = createSdkAgentRunner({ root, modelRuntime: runtime, timeoutMs: 10_000, ledger: new UsageLedger() });
		const outcome = await runner.run({ label: "profile", role: "profile", model, systemPrompt: SYSTEM, prompt: "PLAIN-AGENT go", tools: [], done: () => true });
		assert.deepEqual(recorded, [], "other providers record nothing");
		assert.equal(outcome.ok, false);
		assert.equal(outcome.rejected, true);
	});
});
