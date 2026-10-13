import { type Api, type AssistantMessage, isContextOverflow, isRetryableAssistantError, type Model, type Usage } from "@earendil-works/pi-ai";
import {
	type AgentSession,
	createAgentSession,
	createExtensionRuntime,
	getAgentDir,
	ModelRuntime,
	type ResourceLoader,
	SessionManager,
	SettingsManager,
	type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { BRIDGE_PROVIDER, recordBridgePrompt } from "./bridge.ts";
import { createReadOnlyTools } from "./read-tools.ts";
import type { Role } from "./settings.ts";
import { createShellTool } from "./shell.ts";

type ThinkingLevel = NonNullable<Parameters<typeof createAgentSession>[0]>["thinkingLevel"];

export function emptyUsage(): Usage {
	return { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } };
}

export function addUsage(target: Usage, usage: Usage): void {
	target.input += usage.input;
	target.output += usage.output;
	target.cacheRead += usage.cacheRead;
	target.cacheWrite += usage.cacheWrite;
	target.totalTokens += usage.totalTokens;
	target.cost.input += usage.cost.input;
	target.cost.output += usage.cost.output;
	target.cost.cacheRead += usage.cost.cacheRead;
	target.cost.cacheWrite += usage.cost.cacheWrite;
	target.cost.total += usage.cost.total;
}

export interface UsageRecord {
	provider: string;
	model: string;
	usage: Usage;
}

/** Usage of all audit agents, grouped by provider and model. */
export class UsageLedger {
	private readonly byModel = new Map<string, UsageRecord>();

	add(provider: string, model: string, usage: Usage): void {
		const key = `${provider}/${model}`;
		let record = this.byModel.get(key);
		if (!record) {
			record = { provider, model, usage: emptyUsage() };
			this.byModel.set(key, record);
		}
		addUsage(record.usage, usage);
	}

	entries(): UsageRecord[] {
		return [...this.byModel.values()];
	}

	total(): Usage {
		const total = emptyUsage();
		for (const record of this.byModel.values()) addUsage(total, record.usage);
		return total;
	}
}

export interface AgentSpec {
	/** Unique label for progress and logs, e.g. "hunt:injection" or "challenger:H-003". */
	label: string;
	role: Role;
	model: Model<Api>;
	systemPrompt: string;
	prompt: string;
	/** Submission tools for this role. */
	tools: ToolDefinition[];
	/** Whether the agent has submitted what it owes. */
	done: () => boolean;
	/** Sent once when the agent stops without submitting. */
	nudge?: string;
}

export interface AgentOutcome {
	label: string;
	ok: boolean;
	timedOut: boolean;
	error?: string;
	/** The agent failed on a transient provider error (rate limit, overload, server or network) after its retries. */
	transient?: true;
	/**
	 * The provider rejected the request with an error retrying cannot fix (authentication, billing, a refusal).
	 * Context overflow is excluded: it depends on the prompt, not on the model alone.
	 */
	rejected?: true;
	usage: Usage;
}

/** The error of an agent stopped by the run's abort signal. */
export const CANCELLED = "cancelled";

export interface AgentRunner {
	run(spec: AgentSpec, signal?: AbortSignal): Promise<AgentOutcome>;
}

export interface SdkRunnerOptions {
	/** Audited project root; agent tools resolve paths against it. */
	root: string;
	modelRuntime: ModelRuntime;
	thinkingLevel?: ThinkingLevel;
	timeoutMs: number;
	ledger: UsageLedger;
	/** Retry policy for transient model request failures; tests shorten the delays. */
	retry?: RetryPolicy;
}

export interface RetryPolicy {
	maxRetries: number;
	baseDelayMs: number;
	maxAgentDelayMs: number;
}

/**
 * Waits of 5, 10, 20, 40, 60, and 60 s (about 3 minutes) before an agent gives up on a transient error.
 * Provider rate limits often last longer than pi's interactive default of 2 + 4 + 8 s, and the total
 * still fits inside the default agent timeout.
 */
export const AGENT_RETRY: RetryPolicy = { maxRetries: 6, baseDelayMs: 5000, maxAgentDelayMs: 60_000 };

function isolatedResources(systemPrompt: string): ResourceLoader {
	return {
		getExtensions: () => ({ extensions: [], errors: [], runtime: createExtensionRuntime() }),
		getSkills: () => ({ skills: [], diagnostics: [] }),
		getPrompts: () => ({ prompts: [], diagnostics: [] }),
		getThemes: () => ({ themes: [], diagnostics: [] }),
		getAgentsFiles: () => ({ agentsFiles: [] }),
		getSystemPrompt: () => systemPrompt,
		getSystemPromptSource: () => undefined,
		getAppendSystemPrompt: () => [],
		getAppendSystemPromptSources: () => [],
		extendResources: () => {},
		reload: async () => {},
	};
}

/**
 * Create an isolated, read-only, in-memory session for one audit agent: no extensions, skills,
 * context files, or user settings; only read-only tools confined to the project, the restricted
 * shell, and the role's submission tools.
 */
export async function createAuditSession(options: SdkRunnerOptions, spec: Pick<AgentSpec, "model" | "systemPrompt" | "tools">): Promise<AgentSession> {
	// The confined read tools replace pi's built-ins of the same names.
	const customTools = [...createReadOnlyTools(options.root), createShellTool(options.root) as unknown as ToolDefinition, ...spec.tools];
	const { session } = await createAgentSession({
		cwd: options.root,
		agentDir: getAgentDir(),
		model: spec.model,
		thinkingLevel: options.thinkingLevel,
		modelRuntime: options.modelRuntime,
		resourceLoader: isolatedResources(spec.systemPrompt),
		tools: customTools.map((tool) => tool.name),
		customTools,
		sessionManager: SessionManager.inMemory(options.root),
		settingsManager: SettingsManager.inMemory({ retry: { enabled: true, ...(options.retry ?? AGENT_RETRY) } }),
	});
	return session;
}

function lastAssistantError(session: AgentSession): { error: string; transient: boolean; rejected: boolean } | undefined {
	for (let i = session.messages.length - 1; i >= 0; i--) {
		const message = session.messages[i] as AssistantMessage;
		if (message?.role !== "assistant") continue;
		if (message.stopReason !== "error") return undefined;
		// pi's own classifier, so "transient" means exactly what pi already retried.
		const transient = isRetryableAssistantError(message);
		return { error: message.errorMessage || "model request failed", transient, rejected: !transient && !isContextOverflow(message) };
	}
	return undefined;
}

export function createSdkAgentRunner(options: SdkRunnerOptions): AgentRunner {
	return {
		async run(spec, signal) {
			const usage = emptyUsage();
			let timedOut = false;
			let session: AgentSession | undefined;
			let timer: NodeJS.Timeout | undefined;
			const onAbort = () => void session?.abort();
			try {
				if (signal?.aborted) return { label: spec.label, ok: false, timedOut: false, error: CANCELLED, usage };
				session = await createAuditSession(options, spec);
				const audit = session;
				const bridged = spec.model.provider === BRIDGE_PROVIDER;
				// Re-recorded on every turn, as the bridge does itself, in case pi re-renders the prompt.
				const register = () => bridged && recordBridgePrompt(audit.systemPrompt, spec.systemPrompt);
				session.subscribe((event) => {
					if (event.type === "turn_start") register();
					if (event.type !== "message_end" || event.message.role !== "assistant") return;
					const message = event.message as AssistantMessage;
					if (!message.usage) return;
					addUsage(usage, message.usage);
					options.ledger.add(message.provider ?? spec.model.provider, message.model ?? spec.model.id, message.usage);
				});
				signal?.addEventListener("abort", onAbort, { once: true });
				timer = setTimeout(() => {
					timedOut = true;
					void session?.abort();
				}, options.timeoutMs);

				register();
				await session.prompt(spec.prompt);
				// A model error already used up pi's retries; a nudge would only repeat the failing request.
				if (!spec.done() && !timedOut && !signal?.aborted && spec.nudge && !lastAssistantError(session)) {
					register();
					await session.prompt(spec.nudge);
				}

				if (timedOut) return { label: spec.label, ok: false, timedOut, error: `timed out after ${Math.round(options.timeoutMs / 1000)}s`, usage };
				if (signal?.aborted) return { label: spec.label, ok: false, timedOut, error: CANCELLED, usage };
				const failure = lastAssistantError(session);
				if (failure) {
					const kind = failure.transient ? { transient: true as const } : failure.rejected ? { rejected: true as const } : {};
					return { label: spec.label, ok: false, timedOut, error: failure.error, ...kind, usage };
				}
				if (!spec.done()) return { label: spec.label, ok: false, timedOut, error: "finished without submitting a result", usage };
				return { label: spec.label, ok: true, timedOut, usage };
			} catch (error) {
				return { label: spec.label, ok: false, timedOut, error: (error as Error).message, usage };
			} finally {
				if (timer) clearTimeout(timer);
				signal?.removeEventListener("abort", onAbort);
				session?.dispose();
			}
		},
	};
}

/**
 * The model runtime of the parent pi session, so audit agents share its credentials and any providers
 * registered by other extensions. Falls back to a runtime built from the standard auth and model files.
 */
export async function resolveModelRuntime(modelRegistry: unknown): Promise<ModelRuntime> {
	const candidate = (modelRegistry as { runtime?: unknown } | undefined)?.runtime as Partial<ModelRuntime> | undefined;
	if (candidate && typeof candidate.getModel === "function" && typeof candidate.streamSimple === "function" && typeof candidate.getAuth === "function") {
		return candidate as ModelRuntime;
	}
	return ModelRuntime.create();
}
