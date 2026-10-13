# Tasks

## 1. Bridge registration

- [ ] 1.1 Add `recordBridgePrompt(systemPrompt, rolePrompt)` that records into `globalThis[Symbol.for("claude-bridge:promptCaptures")]` when it has a `record` function and returns whether it did; verify with unit tests for a present registry (key, custom, empty context files and skills, source) and a missing or malformed one
- [ ] 1.2 Call it from the runner for `claude-bridge` models before the prompt, before the nudge, and on each `turn_start`; verify with an agent-runtime test using a fake registry and a faux provider named `claude-bridge` whose responses fail unless the request's system prompt was recorded, and a test that a faux model on another provider records nothing

## 2. Docs and checks

- [ ] 2.1 Describe bridge support in the README: what is sent to Claude Code, subscription usage, Claude Code session files, and the internal-registry caveat; replace the advice to choose another model
- [ ] 2.2 `npm run check`, `./scripts/check-load.sh`, and one real diff run of the fixture with the installed packages and a `claude-bridge` model through `scripts/rpc-run.ts` that completes
