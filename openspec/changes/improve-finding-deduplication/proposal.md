# Proposal

## Why

Real-model runs of `/security-review` on the seeded fixture showed three deduplication gaps:

- The same authorization issue got a new id on each of three runs. Its anchor line, function name, and sink wording changed between runs, so the exact fingerprint never matched.
- One root cause showed up as several findings, for example a SQL injection and the secret disclosure it enables.
- A `full` run marks unobserved findings `stale` even when part of the project was never checked.

Together these make the findings store noisy and erode trust in finding ids and `false-positive` markings, which the store exists to preserve.

## What Changes

- **Stale marking only after complete runs.** A `full` run that is incomplete (an agent failed or timed out, the hypothesis cap was hit, or verification failed) does not mark any finding `stale`. The report and the session summary say that stale marking was skipped.
- **Fallback matching across runs.** When no stored finding has the exact fingerprint, a finding matches a stored finding with the same vulnerability type and primary anchor file, but only when the match is unambiguous: exactly one candidate on each side. Ambiguous cases keep today's behavior and create a new finding. The lookup that gives the challenger a prior `false-positive` verdict uses the same rule.
- **New triage stage.** It runs between hunt and verify. When there are at least two hypotheses after same-type merging, one triage agent groups hypotheses that a single code fix would eliminate. Each group is verified as one hypothesis whose primary issue is the root cause, and the other members are carried as consequences. The resulting finding lists its consequences. If triage fails, the hypotheses proceed unmerged and the run log notes the failure. Triage failure does not make the run incomplete, because no code is left unchecked.
- **New `triage` role** in the `models` setting, defaulting to the session model like the other roles.
- **Optional `consequences` field** on finding records. The store format version stays 1. Finding records already accept extra fields, so older versions of the extension read stores written by this version and ignore the field.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `security-audit-pipeline`:
  - Stage order gains triage between hunt and verify.
  - New requirement for root-cause grouping.
  - The prior false-positive lookup uses the fallback match.
- `security-findings-store`:
  - Repeat-run deduplication gains the unambiguous type-and-file fallback.
  - Stale marking requires a complete full-mode run.
  - Findings may carry consequences.
- `security-review-configuration`: the role list gains `triage`, for both the session-model default and per-role overrides.

## Impact

- **Code** in `extensions/security-review/`:
  - `store.ts`: merge matching, stale marking, false-positive lookup.
  - `pipeline.ts`: new triage stage, priors computed with the shared matcher.
  - `partition.ts` or a new `triage.ts`: applying groups.
  - `submit-tools.ts`: new `submit_triage` tool.
  - `prompts.ts` and `roles/triage.md`: new role prompt.
  - `roles/affirmer.md` and `roles/challenger.md`: assess consequences.
  - `schema.ts`: triage input, `consequences` on hypotheses and findings.
  - `settings.ts`: `triage` role.
  - `report.ts` and `command.ts`: consequences, stale-skipped note, triage progress.
- **Cost:** one extra agent per run when there are at least two hypotheses. It is usually offset by fewer affirmer and challenger pairs after merging.
- **Docs:** the README settings table, and the known limitations section, which these fixes partly remove.
- **No new dependencies.**
