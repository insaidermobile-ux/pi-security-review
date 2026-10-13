# Tasks

Assumptions recorded from design.md open questions: `report.md` is fully regenerated on every run; initial default caps are 4 concurrent agents, 24 hypotheses per run, and a 10-minute per-agent timeout. All of these are settings and can be tuned later without changing the plan.

## 1. Package scaffold

- [x] 1.1 Initialize the repository as a pi package: `package.json` with `pi-package` keyword, `peerDependencies` on pi host packages, TypeScript config, `extensions/` and `skills/` directories; verify `pi -e ./` loads with no extension errors
- [x] 1.2 Add a test runner (Node test or vitest) and a `test` script; verify a trivial test runs green
- [x] 1.3 Add `README.md` with install instructions (`pi install git:...`), usage of `/security-review` and `/security-review full`, and the prompt-injection limitation; verify the install command in the README works against a local checkout
- [x] 1.4 Add project `.gitignore` covering `node_modules/`, build output, and `.security-review/`; verify `git status` is clean after a build

## 2. Settings and schema

- [x] 2.1 Implement typed settings loading (per-role model overrides, exclude globs, max concurrent agents, max hypotheses, per-agent timeout) merged from global and project pi configuration with project precedence; verify unit tests cover precedence and defaults
- [x] 2.2 Implement settings validation that fails fast with the setting name and expected type, including unresolvable model identifiers; verify unit tests for a non-numeric cap and an unknown model
- [x] 2.3 Define TypeBox schemas for Profile, Hypothesis, Argument (affirm and challenge variants), Finding, RefutedHypothesis, and the store file; verify unit tests reject a hypothesis without anchors and a challenge argument without verdict
- [x] 2.4 Implement the finding fingerprint (vulnerability type, anchor file, enclosing function, sink; no line numbers) and three-part title formatting; verify unit tests show identical fingerprints after line shifts

## 3. Git scope resolution

- [x] 3.1 Implement work-tree detection and base reference fallback chain (`origin/HEAD`, `origin/main`, `origin/master`, `main`, `master`); verify unit tests against fixture repositories with and without a remote and with no candidate base
- [x] 3.2 Implement default-mode file set: merge-base diff plus modified and untracked non-ignored files, minus exclude globs; verify fixture tests cover committed, unstaged, untracked, and ignored files
- [x] 3.3 Implement full-mode file set: tracked plus untracked non-ignored files minus exclude globs; verify fixture test matches expected list
- [x] 3.4 Implement the empty-scope and not-a-repository early exits with the specified messages; verify tests assert the suggestion of `full` and the git requirement message

## 4. Findings store

- [x] 4.1 Implement reading and atomic writing of `.security-review/findings.json` (write to temp file, then rename); verify a test that interrupts mid-write leaves the old file parseable
- [x] 4.2 Implement merge of run results into the store: fingerprint dedup, preserved id and user status, refreshed anchors and verification, `last_seen` update, `open` status for new findings; verify unit tests for re-observed and new findings and for a `false-positive` surviving a re-observation
- [x] 4.3 Implement stale marking after full-mode runs only and retention of refuted hypotheses per run; verify tests for full-mode stale marking and default-mode no-op
- [x] 4.4 Implement profile caching keyed by project fingerprint (lockfiles and top-level structure); verify a test that the cache hits on unchanged fingerprint and misses on change
- [x] 4.5 Implement the `.gitignore` check for `.security-review/` with a once-per-project recommendation flag persisted in the store; verify tests for ignored and not-ignored cases

## 5. Audit agent runtime

- [x] 5.1 Implement an agent factory over the pi SDK: `createAgentSession` with in-memory session manager, `cwd` set to the audited project, selected model, and an explicitly assembled tool set; verify a test that a created agent's tool list contains no `write` or `edit`
- [x] 5.2 Implement the constrained read-only shell tool with an allowlist (`git log`, `git show`, `git blame`, `rg`, `cat`, `ls`, `wc`) and rejection of anything else; verify unit tests for allowed and rejected commands, including shell metacharacter attempts
- [x] 5.3 Implement submission tools `submit_profile`, `submit_hypothesis`, and `submit_argument` with `outputSchema`, collecting validated results into the orchestrator and returning actionable validation errors; verify tests that an invalid submission is rejected and a valid one is captured
- [x] 5.4 Implement a bounded parallel runner with per-agent timeout, failure isolation, disposal of sessions, and usage aggregation; verify tests that a timed-out agent does not block others and that aggregated usage equals the sum of children

## 6. Role prompts

- [x] 6.1 Write the profile role prompt producing stack, entry points, trust boundaries, auth model, and external inputs via `submit_profile`; verify a dry run on a small fixture project yields a schema-valid profile
- [x] 6.2 Write the hunt role prompt with two variants: class-cluster assignment over a diff (default mode) and subtree assignment over all classes (full mode), instructing submission of hypotheses only; verify a dry run on a fixture with a known injection produces a hypothesis anchored on it
- [x] 6.3 Write the affirmer role prompt producing an ordered attack path, missing defenses with citations, and preconditions via `submit_argument`; verify a dry run on the fixture hypothesis yields a schema-valid affirm argument
- [x] 6.4 Write the challenger role prompt implementing the ordered attribution, code-defense, and threat-model tests, consuming the affirmer argument and any prior false-positive context, and returning verdict plus confidence; verify dry runs yield `confirmed` on the real fixture issue and `refuted` on a fixture guarded by validation
- [x] 6.5 Write the report role prompt or deterministic renderer producing `report.md` grouped by severity with both arguments, verdict, remediation, and a refuted section; verify a snapshot test of the rendered report from fixture findings

## 7. Pipeline orchestration

- [x] 7.1 Implement the profile stage with cache reuse in default mode and forced refresh in full mode; verify tests for both paths
- [x] 7.2 Implement the hunt stage: partition by vulnerability class (default) or by subtree (full), spawn agents within the concurrency cap, merge duplicate hypotheses by type and overlapping anchors, apply the hypothesis cap with severity prioritization and record the excess as unverified; verify tests for partitioning per mode, dedup, and cap overflow
- [x] 7.3 Implement the verify stage: for each hypothesis run affirmer then challenger as separate agents, pass the affirmer argument and matching false-positive context to the challenger, map verdicts to vulnerability, risk, or refuted; verify tests that the challenger input contains the affirmer argument and that verdict mapping is correct
- [x] 7.4 Implement the report stage writing `report.md`, merging into the store, and producing the summary data (counts by severity, refuted count, paths, incomplete flag); verify an end-to-end test on a fixture project with mocked model responses produces store, report, and summary
- [x] 7.5 Implement partial-result handling: failed or timed-out agents mark the run incomplete while remaining work continues; verify a test with one failing hunt agent still produces findings from the others

## 8. Command and UX

- [x] 8.1 Register `/security-review` with `pi.registerCommand`, argument completion for `full`, and a usage error for unknown arguments; verify the command appears in `/commands` output and rejects `/security-review foo`
- [x] 8.2 Wire the command handler: load and validate settings, resolve scope, run the pipeline, and handle early exits; verify manual runs of the not-a-repo, empty-scope, and invalid-settings paths show the specified messages
- [x] 8.3 Implement status-bar progress via `ctx.ui.setStatus` per stage with counts for hunt and verify, cleared on completion or error; verify by observing the status text during a run and its absence afterwards
- [x] 8.4 Post the completion summary into the session, including the `.gitignore` recommendation when applicable, and include aggregated child usage in the command result; verify `/session` totals increase by the aggregated amount after a run
- [x] 8.5 Document settings keys, defaults, and role model overrides in `README.md`; verify every documented key is read by the settings loader

## 9. Integration verification

- [x] 9.1 Run `/security-review` end to end against a fixture repository with a seeded vulnerability on a feature branch using a real model; verify the finding is confirmed, stored, and reported, and that `.security-review/` is untracked
- [x] 9.2 Re-run against the same repository after marking the finding `false-positive`; verify the status is preserved and the challenger context included the prior verdict
- [x] 9.3 Run `/security-review full` on the fixture; verify subtree partitioning was used and non-re-observed findings are marked stale
- [x] 9.4 Install the package from a git URL into a clean pi profile and run the command; verify no extension errors and no dependency on third-party pi packages

## Workflow follow-up

- Archive the change after the integration checks pass and the README reflects the shipped behavior.
