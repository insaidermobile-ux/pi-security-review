# Tasks

## 1. Stale marking only after complete runs

- [ ] 1.1 In `mergeRun`, mark stale only when `run.mode === "full" && run.complete`, and return `staleSkipped`; verify with store tests for a complete full run (marks stale), an incomplete full run (no stale, `staleSkipped` true), and a default-mode run (unchanged)
- [ ] 1.2 Print "Stale marking skipped: the run was incomplete." in `renderReport` and `formatSummary` when `staleSkipped` is true; verify with a report test and a command test for an incomplete full run, and that the golden snapshot for complete runs is unchanged

## 2. Shared finding matcher

- [ ] 2.1 Add `matchStored(stored, incoming)` to `store.ts` with an exact pass and an unambiguous type + primary-file fallback (design D1); verify with unit tests: exact match, fallback with differing line/function/sink, two stored candidates (no match), two incoming candidates (no match), a candidate already taken by an exact match, and type synonyms and path normalization
- [ ] 2.2 Use `matchStored` in `mergeRun`, and on a fallback match replace the stored fingerprint; verify with store tests that a fallback re-observation keeps id, `first_seen`, and a `false-positive` status, refreshes anchors, takes the new fingerprint, reopens a `stale` finding, and that an ambiguous case creates a new `SR-` id
- [ ] 2.3 Compute the challenger's prior false-positive in `runPipeline` with `matchStored` over the hypotheses entering verification, replacing `priorFalsePositive`, and tell the challenger in `roles/challenger.md` to disregard a prior about a different code path; verify with a pipeline test where a hypothesis with a different fingerprint receives the stored false-positive through the fallback and the challenger prompt contains it

## 3. Schema and settings

- [ ] 3.1 Add `Consequence` and `TriageInput` schemas and optional `consequences` on `StoredHypothesis` and `Finding` in `schema.ts`; verify with schema tests that findings with and without consequences validate, consequences without anchors are rejected, and a store written without the field still loads
- [ ] 3.2 Add the `triage` role to `ROLES` after `hunt`; verify with settings tests that `models.triage` resolves and defaults to the session model, and with the README test that the settings table lists the role

## 4. Triage stage

- [ ] 4.1 Add the `submit_triage` tool (terminating, `outputSchema` Receipt) that rejects unknown labels, labels in several groups, groups with fewer than two members, and a primary outside its group, and accepts an empty group list; verify with submit-tool tests covering each rejection message and a valid submission
- [ ] 4.2 Add `applyTriageGroups(candidates, groups)` in `partition.ts` (design D3: primary fields kept, most severe estimate, union of partitions, other members as consequences, group placed at its first member's position); verify with unit tests including unchanged primary fingerprint and deterministic order
- [ ] 4.3 Add `roles/triage.md` (grouping criterion: fixing the primary removes every member; separate missing controls stay separate) and `triagePrompt(profile, candidates)` with `C-n` labels; verify with a prompt test that every candidate's label, type, claim, anchors, and sink are present and the system prompt includes the shared ground rules
- [ ] 4.4 Run triage in the pipeline after `mergeDuplicateHypotheses` and before `applyHypothesisCap`, emit `{ stage: "triage" }` progress shown as `security-review: triage`, skip it below two candidates, and on failure proceed ungrouped with the failure in `errors` but not in `incomplete_reasons`; verify with faux-provider pipeline tests: grouping reduces verify agents, a group counts once against the cap, one candidate runs no triage agent, a hung triage agent leaves the run complete with an error, plus a `statusText` test

## 5. Consequences in verification and output

- [ ] 5.1 Add a Consequences section to `affirmerPrompt` and `challengerPrompt` when present, and update `roles/affirmer.md` (fold real consequences into impact and severity) and `roles/challenger.md` (verdict on the primary; consequences fall with it); verify with prompt tests for hypotheses with and without consequences
- [ ] 5.2 Copy consequences onto findings in `buildFinding`, and render them under each finding in `renderReport` and as a count in `formatSummary`; verify with a pipeline test (finding and refuted record keep consequences), an updated report snapshot, and a command test
- [ ] 5.3 Update the README: add `triage` to the cost description and the roles, describe root-cause grouping, replace the deduplication and overlapping-findings limitations with the remaining trade-offs (design Risks), and note that incomplete full runs skip stale marking; verify `npm test` (README test) passes and the README matches the implemented behavior

## 6. Integration checks

- [ ] 6.1 Run `npm run check` and `./scripts/check-load.sh`, and run `scripts/dry-run.ts` with a triage step added against the fixture with the default model; verify the suite is green, the command loads, and the triage dry run returns a valid grouping
- [ ] 6.2 Real-model run via `scripts/rpc-run.ts` on a fresh fixture repo, twice: verify that the status bar shows triage, that a disclosure-through-injection hypothesis (if raised) is a consequence of the SQL injection rather than a separate finding, that a rate-limit hypothesis (if raised) stays separate, and that the missing-authorization finding keeps its id on the second run
- [ ] 6.3 Real-model `/security-review full` run with `maxHypotheses: 1` in project settings on a fixture with stored findings; verify the run is incomplete, no finding is marked stale, and the summary and report say stale marking was skipped
