# Tasks

## 1. Agent runtime

- [x] 1.1 Set the audit session retry budget to 6 retries, 5 s base delay, 60 s cap (`AGENT_RETRY`), with an optional `retry` override in `SdkRunnerOptions`; verify with an agent-runtime test where a faux provider answers 429 twice and then succeeds, and the agent finishes ok
- [x] 1.2 Set `transient: true` on an `AgentOutcome` only when the last assistant error is accepted by `isRetryableAssistantError`; verify with agent-runtime tests: exhausted 429 is transient, a non-retryable provider error, a timeout, and a missing submission are not

## 2. Hunt re-run

- [x] 2.1 Re-run each transiently failed hunt assignment once after the batch, with a fresh collector and the label `hunt:<assignment> (re-run)`; on success replace its hypotheses and add an `errors` note, on failure keep both attempts' hypotheses and record the failure; grow the progress total by the re-runs; verify with pipeline tests for a successful re-run (run complete, both attempts in `agents`, re-run hypothesis verified), a failed re-run (incomplete, partial hypotheses kept), and a timed-out hunter (no re-run)

## 3. Docs and checks

- [x] 3.1 Describe the retry budget and the hunt re-run in the README security model and limitations section
- [x] 3.2 `npm run check`, `./scripts/check-load.sh`, and one real-model diff run of the fixture through `scripts/rpc-run.ts` that completes
