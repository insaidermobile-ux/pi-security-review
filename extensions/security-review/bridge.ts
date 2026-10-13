/**
 * Support for models served by pi-claude-bridge.
 *
 * The bridge sends a request only for a system prompt it has recorded, which it does from its own
 * agent hooks. Audit sessions load no extensions, so they record their prompts themselves in the
 * bridge's process-wide registry. The registry is internal to the bridge; when it is missing or has
 * changed shape, nothing is recorded and the bridge refuses the request as it would anyway.
 */

export const BRIDGE_PROVIDER = "claude-bridge";
const REGISTRY_KEY = Symbol.for("claude-bridge:promptCaptures");

interface PromptRegistry {
	record(systemPrompt: string, input: { custom?: string; contextFiles: unknown[]; skills: unknown[] }, source?: string): void;
}

/**
 * Record an audit agent's rendered system prompt so the bridge accepts requests that carry it.
 * Only the role instructions are forwarded to Claude Code; project context files and skills are not.
 */
export function recordBridgePrompt(systemPrompt: string, rolePrompt: string): boolean {
	const registry = (globalThis as Record<symbol, unknown>)[REGISTRY_KEY] as Partial<PromptRegistry> | undefined;
	if (typeof registry?.record !== "function") return false;
	registry.record(systemPrompt, { custom: rolePrompt, contextFiles: [], skills: [] }, "pi-security-review");
	return true;
}
