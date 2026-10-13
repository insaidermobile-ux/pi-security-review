# Tasks

## 1. Agent runtime

- [ ] 1.1 Set `rejected: true` on an `AgentOutcome` when the last assistant error is neither accepted by `isRetryableAssistantError` nor detected by `isContextOverflow`; verify with agent-runtime tests: a provider refusal is rejected, a rate limit after retries, a context overflow, a timeout, and a missing submission are not

## 2. Pipeline

- [ ] 2.1 Add `failureReasons(stage, outcomes)` grouping failures by error, with labels shortened to 60 characters, errors to 300, and at most three labels per group; use it for profile, hunt, and verification failures, carrying the failed outcome on unverified results; verify with unit tests for one failure, six identical failures, mixed errors, and long labels and errors
- [ ] 2.2 Skip the hunt and verify stages when the profile outcome is `rejected` and the hunt model equals the profile model, with the reason `hunting skipped: <provider>/<id> rejected the profile agent's request`; verify with pipeline tests: a refused profile request runs only the profile agent and writes an incomplete report, a different hunt model still hunts, and a timed-out profile agent still hunts

## 3. Docs and checks

- [ ] 3.1 Describe the early stop in the README limitations section
- [ ] 3.2 `npm run check`, `./scripts/check-load.sh`, and one real run on a fixture with a model whose requests are refused, through `scripts/rpc-run.ts`, that stops after the profile agent with a short summary
