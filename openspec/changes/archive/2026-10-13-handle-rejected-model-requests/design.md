# Design

## Context

- `AgentOutcome` already distinguishes timeouts (`timedOut`) and transient provider errors after retries (`transient`). A model request error that is not transient, for example an authentication, billing, or provider-side refusal, is reported only as `error`, the same way as an agent that finished without submitting.
- `runPipeline` turns each failed hunt outcome into its own incomplete reason `hunt agent failed (<label>: <error>)`, and each failed verification into `verification failed (<label>: <error>)`. Full-mode hunt labels list every subtree in the partition.
- The profile agent runs alone before any other agent, so it is the cheapest point to find out that the model cannot be used.

## Goals / Non-Goals

**Goals:** stop spending agents on a model that has just refused a request; make the summary readable when many agents fail the same way.

**Non-Goals:**

- Stopping on failures in later stages. A hunt or verification agent's rejection can be specific to its prompt, and the stage already runs its agents in parallel.
- Stopping when the profile comes from the cache, in default mode. No model request is made then, so there is nothing to classify; grouped reasons keep that case readable.
- Workarounds for specific providers. Support for `pi-claude-bridge` is a separate change.

## Decisions

### D1. `rejected` on the agent outcome

`AgentOutcome` gains `rejected?: true`, set when the agent's last assistant message is a model request error that `isRetryableAssistantError` does not accept and `isContextOverflow` does not detect. It is never set together with `transient`, nor for timeouts, cancellations, or missing submissions. Context overflow is excluded because it depends on the prompt and the conversation, not on the model alone.

### D2. Early stop in `runPipeline`

After the profile stage, if the profile outcome is `rejected` and `models.hunt` has the same provider and id as `models.profile`, `runPipeline` skips the hunt and verify stages. The incomplete reasons are the profile failure and `hunting skipped: <provider>/<id> rejected the profile agent's request`. The report summary agent does not run, because there are no findings. The store is merged as for any incomplete run: nothing is marked stale.

A different hunt model means the user chose it on purpose, so hunting proceeds without a profile, as today.

### D3. Grouped, shortened reasons

A helper `failureReasons(stage, outcomes)` groups failed outcomes by their error text, in first-seen order, and returns one reason per group:

- one agent: `<stage> agent failed (<label>: <error>)`
- several: `<n> <stage> agents failed (<label>, <label>, <label> and <k> more): <error>`

Labels are shortened to 60 characters and errors to 300, with an ellipsis. Verification failures use the stage name `verification`. The unverified result therefore carries its failed outcome instead of a preformatted string. Promise rejections become outcomes labelled with the stage name.

## Risks / Trade-offs

- **A provider error misclassified as non-transient stops a run that could have worked.** → pi's classifier already decides what is worth retrying, so we stop only where pi would also give up. The run is marked incomplete and the reason is visible, so the user can re-run.
- **Shortened errors may cut useful detail.** → The run log keeps every agent's full error, and the report links to the run log.
