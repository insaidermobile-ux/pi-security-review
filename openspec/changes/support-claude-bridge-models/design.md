# Design

## Context

- `pi-claude-bridge` keeps `PromptCaptures` in a process-wide registry at `globalThis[Symbol.for("claude-bridge:promptCaptures")]`, so that isolated agents, which load their own copy of the bridge module, share one instance. Its `record(systemPrompt, { custom, append, contextFiles, skills, sections }, source)` stores what pi assembled for an agent, keyed by the final system prompt.
- For each request, the bridge looks up `context.systemPrompt` in the registry. On a match, it starts Claude Code with its own preset prompt and appends the portable parts of the capture: custom prompt, appended text, context files, skills, and custom sections. With no match, it throws `prompt-capture: no capture for this …-char system prompt`.
- On this provider path the bridge starts Claude Code with `tools: []`. The model can only call pi's tools, which the bridge exposes over MCP. For audit agents those are the read-only tools and the role's submission tool.
- Audit sessions get their system prompt from `isolatedResources(spec.systemPrompt)`, which pi renders with the tool list and working directory.

## Goals / Non-Goals

**Goals:** audit agents work on bridge models; the read-only guarantee holds; nothing changes for other providers.

**Non-Goals:**

- Loading extensions into audit sessions. That would break isolation and run the bridge's session hooks for every agent.
- A generic mechanism for other providers that need prompt registration. None is known.

## Decisions

### D1. Record before each prompt and on every turn

In `createSdkAgentRunner`, when `spec.model.provider === "claude-bridge"`, record `session.systemPrompt` with `{ custom: spec.systemPrompt, contextFiles: [], skills: [] }` and source `pi-security-review`:

- before `session.prompt(spec.prompt)` and before the nudge;
- on each `turn_start` event of the session.

Recording again on each turn covers pi re-rendering the prompt between turns, the same reason the bridge itself records on `turn_start`. A recording with an unchanged key is a no-op update.

`custom` is the role prompt, not the rendered prompt. That way Claude Code receives the role instructions after its own preset, and none of pi's rendering: pi's tool list and working-directory lines duplicate what Claude Code already knows.

### D2. Feature detection, not a dependency

A helper `recordBridgePrompt(systemPrompt, rolePrompt)` reads the registry from `globalThis`, checks that it has a `record` function, and returns `false` if it does not. A missing registry is not an error. The bridge's own refusal surfaces as a rejected profile request, which already stops the run with a readable reason.

## Risks / Trade-offs

- **Coupling to bridge internals.** → Feature detection keeps the failure mode the same as today, a refused request with the bridge's error message. The README names the bridge version this was verified with.
- **Claude Code session files.** The bridge writes a Claude Code session file per agent under `~/.claude/projects/`. These are Claude Code's files, not pi sessions, so "not persisted to the user's session list" still holds for pi. → The README mentions it.
- **The registry holds at most 256 keys.** Audit roles render 6 distinct prompts at most, so they cannot push out the user's own capture.
