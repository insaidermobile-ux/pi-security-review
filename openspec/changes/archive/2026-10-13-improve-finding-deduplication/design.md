# Design

## Context

See `proposal.md` (Why) for the problems, and the delta specs for the required behavior. Relevant current state:

- `store.ts` `mergeRun` matches incoming findings to stored ones by exact fingerprint only. It marks unobserved open findings `stale` after every `full` run, whether complete or not.
- `pipeline.ts` computes the challenger's prior false-positive with `priorFalsePositive(store, fingerprint)`, which is also exact-fingerprint only.
- `huntStage` runs in this order: hunt agents → `mergeDuplicateHypotheses`, which merges same-type hypotheses with overlapping anchors → `applyHypothesisCap` → assign `H-NNN` ids and fingerprints.
- The three real-model runs saw the same authorization issue at `src/server.js` lines 10, 11, and 13. Its function was described as "app.get route registration", then `searchUsers`, then nothing, and its sinks were described differently each time. The type and file were the same every time.
- In the `Finding` and `StoredHypothesis` schemas the top-level object is not closed (`additionalProperties` is unset), unlike the agent input schemas.

## Goals / Non-Goals

**Goals:**

- Make deduplication more robust without changing the fingerprint algorithm, so that existing stores keep matching.
- Keep every new decision either deterministic and unit-testable (matching, stale skipping), or validated at the tool boundary with a safe fallback (triage).

**Non-Goals:**

- Semantic matching of findings across runs by a model.
- Merging stored findings that earlier runs already split. The new behavior applies to new observations only; users can mark old duplicates `false-positive` or delete them.
- Changing hunt partitioning, or having hunters skip classes another hunter covers.

## Decisions

### D1. One matcher shared by the store merge and the prior false-positive lookup

A pure function in `store.ts`:

```
matchStored(stored: Finding[], incoming: MatchKey[]) -> Map<incomingIndex, Finding>
MatchKey = { fingerprint, vuln_type, file }   // file = primary anchor, normalized
```

1. **Exact pass:** match each incoming key to a stored finding with an equal fingerprint. Several incoming keys may map to the same stored finding; this is today's behavior.
2. **Fallback pass:** take stored findings no incoming key has matched, and incoming keys still unmatched. Group both sides by `normalizeVulnType(vuln_type) + "\0" + normalizePath(file)`. Match only groups with exactly one member on each side.

Both callers use it:

- `mergeRun` uses it for verified findings. On a fallback match it sets the stored `fingerprint` to the incoming one, then applies the existing update rules (keep id, user status, `first_seen`).
- `runPipeline` uses it for the hypotheses entering verification, keyed by their primary issue. It passes a match to the challenger only when the matched finding's status is `false-positive`.

Candidates include every stored status. A `stale` finding matched again returns to `open` under the existing rules; user statuses are kept.

Alternatives considered:

- Line proximity was rejected: the authorization anchor moved 3 lines between runs with no code change.
- Keeping a history of fingerprints per finding was rejected as extra state; the fallback already absorbs drift.
- Agent-declared identity ("this is SR-003") was rejected because it is not deterministic and costs prompt tokens.

### D2. Stale marking is gated on run completeness

`mergeRun` marks findings stale only when `run.mode === "full" && run.complete`. `MergeResult` gains `staleSkipped: boolean`, which is true for incomplete full runs. `renderReport` and `formatSummary` print one line when it is true: "Stale marking skipped: the run was incomplete." `RunRecord` needs no new field, because `mode` and `complete` already determine it.

Alternative considered: coverage-aware partial marking, rejected by the user in favor of the simpler rule.

### D3. Triage stage between same-type merge and the cap

New flow inside the pipeline:

```
hunt agents -> mergeDuplicateHypotheses -> [triage] -> applyHypothesisCap -> ids, fingerprints -> verify
```

- Triage runs only when at least 2 candidates remain. Candidates get temporary labels `C-1..C-n` in partition order. Final `H-NNN` ids are assigned after the cap as today, so ids stay deterministic.
- The triage agent:
  - Uses role `triage` and the read-only built-in tools, so it can open code to judge whether one fix covers several candidates.
  - Calls a new terminating tool, `submit_triage({ groups: [{ primary, members, reason }] })`.
  - Its input is a compact JSON list of candidates: label, type, claim, anchors, source, sink, severity estimate.
- Validation in the tool rejects:
  - unknown labels;
  - a label used in more than one group;
  - groups with fewer than two members;
  - a `primary` that is not one of its group's members.
  The error names the offending labels, and the agent may resubmit. An empty `groups` list is valid ("nothing to merge").
- Groups are applied by a pure function in `partition.ts`, `applyTriageGroups(candidates, groups)`:
  - The primary keeps its own fields, so its fingerprint is unchanged.
  - `severity_estimate` becomes the most severe in the group.
  - `source_partition` becomes the union of the members' partitions.
  - The other members become `consequences: [{ vuln_type, description: claim, anchors }]`.
  - The group takes the position of its first member, so ordering stays deterministic.
- Failure handling: if no valid submission arrives (timeout, error, or no call after the nudge), candidates proceed ungrouped. The failure is added to the run's `errors`, so it shows in the report's Errors section and in the run log, but not to `incomplete_reasons`.
- `Progress` gains `{ stage: "triage" }`, and the status bar shows `security-review: triage`.

Alternatives considered:

- A mechanical cross-type rule (same file, function, and sink): on real data it would have folded the separate rate-limit issue into the SQL injection.
- Linking findings without merging: it leaves the noise in place.
- Triage after verification: it would not save verification agents.

### D4. Consequences in the data model and verification

New TypeBox schemas in `schema.ts`:

- `Consequence = { vuln_type, description, anchors (minItems 1) }`.
- Optional `consequences` on `StoredHypothesis` and on `Finding`.
- `TriageInput`, closed like the other agent inputs.

The hunt tool input is unchanged. Hunters never submit consequences.

`affirmerPrompt` and `challengerPrompt` add a "Consequences" section when it is present. Role prompts:

- `affirmer.md`: argue the primary issue and fold real consequences into impact and severity.
- `challenger.md`: give the verdict on the primary issue. Consequences fall with it when it is refuted. When the prior false-positive concerns a different code path than the hypothesis, disregard it; this applies because of the D1 fallback.

`buildFinding` copies the hypothesis's consequences onto the finding. Refuted records keep them because they embed the stored hypothesis. The report lists consequences under each finding.

### D5. `triage` role in settings

`ROLES` gains `triage`. It is placed after `hunt`, the order the stages run in. Defaults and overrides work as for the other roles, and the README settings table lists it.

## Risks / Trade-offs

- **[Risk] A fallback match joins two different issues** when one issue of a type is fixed and another appears in the same file. The old id and status carry over; a `false-positive` status on the old issue would then label the new one.
  → Every observation is still fully verified each run, and the challenger is told to disregard a prior that concerns a different code path. The README documents the trade-off. Ambiguous cases (two candidates) never match.
- **[Risk] Triage over-groups:** an independent issue becomes a "consequence" and disappears if the primary is refuted.
  → The prompt defines grouping strictly as "fixing the primary removes every member". Consequences are kept in refuted records for review. The faux-provider tests and the fixture real-model check verify that the rate-limit issue stays separate.
- **[Trade-off] One more agent per run** with at least 2 hypotheses. It is typically repaid by fewer affirmer/challenger pairs. The fixture run would have dropped from 4 verifications to 3.
- **[Trade-off] Old duplicate findings stay in existing stores.** This is accepted (see Non-Goals).

## Migration Plan

None required. The store format stays `version: 1`, and the new fields are optional on non-closed objects, so stores written by either version load in the other. Rollback means reinstalling the previous version.
