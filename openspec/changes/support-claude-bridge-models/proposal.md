# Proposal

## Why

`pi-claude-bridge` serves Claude models through Claude Code, and it is a common way to run pi on a Claude subscription. With a bridge model as the session model, every audit agent's request is refused, so `/security-review` cannot run at all (since the previous change, it stops after the profile agent).

The bridge sends a request only for a system prompt it has seen before. It records each prompt when pi starts an agent, through its own `before_agent_start`, `agent_start`, and `turn_start` handlers. Audit agents run in isolated sessions without extensions, so the bridge never sees their prompts and refuses them.

## What Changes

- Before each request of an audit agent whose model is served by the `claude-bridge` provider, the extension records the agent's system prompt in the bridge's process-wide prompt registry. The recorded prompt carries only the agent's role instructions, with no project context files, skills, or appended instructions.
- Nothing changes for other providers, or when the bridge is not installed.
- The README describes bridge support and replaces the advice to choose another model.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `security-review-configuration`: new requirement that roles can use models served by `pi-claude-bridge`.

## Impact

- **Code:** a small module in `extensions/security-review/` that writes to the bridge's registry, and `agent-runtime.ts` calling it before each prompt.
- **Coupling:** the registry is internal to `pi-claude-bridge` (`Symbol.for("claude-bridge:promptCaptures")`, method `record`), not a published API. If a bridge release changes it, bridge requests are refused as before, and the run stops after the profile agent with the bridge's error.
- **Usage:** audit agents on a bridge model use the user's Claude subscription quota. A full run starts many agents.
- **No new dependencies.**
