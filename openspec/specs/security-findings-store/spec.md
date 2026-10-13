# security-findings-store Specification

## Purpose

Defines the finding record, the typed submission interface agents use to report results, and the persistent findings store that lets repeated runs deduplicate results and preserve user decisions.

## Requirements

### Requirement: Finding record has mandatory identification fields
Every finding SHALL contain a stable id, a fingerprint, a title, a class (vulnerability or risk), a vulnerability type, a severity (critical, high, medium, low), a confidence (high, medium, low), the scope mode, a status, and first-seen and last-seen timestamps.

#### Scenario: Identification fields present
- **WHEN** a hypothesis is confirmed or downgraded
- **THEN** the resulting finding contains every mandatory identification field with values from the allowed sets

### Requirement: Finding record carries evidence and verification
Every finding SHALL contain at least one anchor (file, line, optional function), an ordered data flow, a description, a remediation, and a verification record holding the affirmer argument, the challenger argument, and the verdict. CWE identifier, CVSS vector and score, introducing commit, and a list of consequences (each with a vulnerability type, a description, and at least one anchor) are optional.

#### Scenario: Verification record complete
- **WHEN** a finding is created
- **THEN** its verification record holds both arguments and the verdict

#### Scenario: Invalid finding is rejected
- **WHEN** a finding is produced without an anchor or without a verdict
- **THEN** it is not written to the store and the error is logged for the run

#### Scenario: Finding with consequences
- **WHEN** a finding is created from a hypothesis that carries consequences
- **THEN** the finding record and its report entry list each consequence with its vulnerability type, description, and anchors

### Requirement: Finding title follows a three-part form
A finding title SHALL name the affected component or location, the vulnerability type, and the consequence.

#### Scenario: Title shape
- **WHEN** a finding is created
- **THEN** its title identifies where the issue is, what kind of issue it is, and what an attacker achieves

### Requirement: Agents submit results through validated tools
Hypotheses, verification arguments, and the project profile SHALL be submitted by agents through dedicated tools with declared parameter and output schemas. Submissions that fail schema validation SHALL be rejected at call time with an error the agent can act on. Free-form agent text SHALL NOT be used as a data source.

#### Scenario: Schema violation at submission
- **WHEN** an agent calls a submission tool with a missing required field or a value outside an enumerated set
- **THEN** the call fails with a validation message and nothing is recorded

#### Scenario: Agent narrates instead of submitting
- **WHEN** an agent describes a vulnerability in text but never calls the submission tool
- **THEN** no hypothesis or finding is recorded from that agent

### Requirement: Store is persisted inside the audited project
Findings SHALL be stored at `.security-review/findings.json` relative to the audited project root, alongside `report.md`, the cached project profile, and per-run logs.

#### Scenario: First run creates the directory
- **WHEN** a run completes in a project with no `.security-review/` directory
- **THEN** the directory is created with `findings.json` and `report.md`

### Requirement: Store files are never committed by the extension
The extension SHALL NOT stage or commit any file under `.security-review/`. When that directory is not ignored by git, the extension SHALL tell the user once per project and recommend adding it to `.gitignore`.

#### Scenario: Directory not ignored
- **WHEN** a run completes and `.security-review/` is not matched by `.gitignore`
- **THEN** the summary includes a recommendation to ignore it

#### Scenario: Directory already ignored
- **WHEN** `.security-review/` is matched by `.gitignore`
- **THEN** no recommendation is shown

### Requirement: Fingerprint is stable across line changes
A finding's fingerprint SHALL be derived from its vulnerability type, the anchor's file path and enclosing function, and the sink, and SHALL NOT depend on line numbers.

#### Scenario: Code shifts
- **WHEN** lines are inserted above a previously found issue and a new run observes it again
- **THEN** the new observation has the same fingerprint as the stored finding

### Requirement: Repeat runs deduplicate by fingerprint
When a run produces a finding whose fingerprint matches a stored finding, the store SHALL update the stored finding's anchors, last-seen timestamp, and verification record, and SHALL keep its id and status.

#### Scenario: Re-observed finding
- **WHEN** a run re-observes a stored finding
- **THEN** the store contains one record with the original id, refreshed anchors and verification, and the original status

### Requirement: User-set status is preserved
The status values `accepted-risk`, `fixed`, and `false-positive` SHALL survive repeat runs and SHALL never be overwritten by the extension. New findings SHALL start with status `open`.

#### Scenario: False positive persists
- **WHEN** a user sets a finding's status to false-positive and a later run re-observes it
- **THEN** the finding's status remains false-positive

### Requirement: Stale findings are marked only in full mode
After a complete full-mode run, stored findings that were not re-observed SHALL be marked `stale`. After an incomplete full-mode run, no finding SHALL be marked `stale`, and the report and session summary SHALL state that stale marking was skipped because the run was incomplete. After a default-mode run, findings outside the run's scope SHALL be left unchanged.

#### Scenario: Finding disappears in full mode
- **WHEN** a full-mode run completes without re-observing a stored open finding
- **THEN** that finding is marked stale

#### Scenario: Incomplete full-mode run
- **WHEN** a full-mode run ends incomplete because a hunt agent timed out, and a stored open finding was not re-observed
- **THEN** that finding stays open, and the report and session summary say that stale marking was skipped

#### Scenario: Finding outside diff scope
- **WHEN** a default-mode run completes and a stored finding's files are not in scope
- **THEN** that finding is unchanged

### Requirement: Refuted hypotheses are retained
Each run SHALL record refuted hypotheses with the challenger's reasoning in the store, separate from findings, so users can review what was discarded.

#### Scenario: Refuted record
- **WHEN** the challenger refutes a hypothesis
- **THEN** the store's refuted list for that run contains the hypothesis, the affirmer argument, and the challenger reasoning

### Requirement: A store changed by the branch under review is not trusted
The store and the cached profile hold the user's own decisions and are given to agents as trusted context. When `findings.json` or `profile.json` is tracked by git and differs between the review base (the merge base with the default branch) and `HEAD`, the run SHALL stop before any model call, name the files, and say how to restore them or stop tracking them.

#### Scenario: Branch marks a finding as a false positive
- **WHEN** a commit on the branch under review changes a tracked `findings.json`
- **THEN** the run stops with an error naming the file and no agent is started

#### Scenario: Tracked but unchanged, or untracked
- **WHEN** the store files are untracked, or tracked and identical to the review base
- **THEN** the run proceeds

### Requirement: Results are stored before the report summary and on top of the current store
The run SHALL write the report and merge its findings into the store before the summary agent runs, so that a failure or interruption after verification loses only the summary. The merge SHALL start from the store as it is at that moment, not as it was when the run started. When the store cannot be read at that moment, the run SHALL keep its results in the run log and say where.

#### Scenario: Status edited during the run
- **WHEN** the user changes a finding's status in `findings.json` while a run is in progress
- **THEN** the status is still there after the run

#### Scenario: Summary agent fails
- **WHEN** the summary agent fails or never returns
- **THEN** `findings.json` and `report.md` already contain the run's findings

### Requirement: Store is written atomically
Updates to `findings.json` SHALL be written so that an interrupted run leaves either the previous content or the new content, never a truncated file.

#### Scenario: Interrupted write
- **WHEN** the process is interrupted while the store is being saved
- **THEN** `findings.json` is parseable and contains either the pre-run or post-run state

### Requirement: Unambiguous type and file match as fallback
When a run produces a finding that matches no stored finding by fingerprint, the store SHALL treat it as a re-observation of a stored finding with the same vulnerability type and primary anchor file, if exactly one such stored finding is not already matched in this run and exactly one such unmatched finding was produced. The stored finding SHALL then be updated as for a fingerprint match and SHALL take the new fingerprint. Otherwise a new finding SHALL be created.

#### Scenario: Authorization issue described differently
- **WHEN** a stored open `missing-authz` finding in `src/server.js` is re-observed with a different anchor line, function name, and sink, and no other `missing-authz` finding exists in that file on either side
- **THEN** the store keeps one record with the original id and status, refreshed anchors, and the new fingerprint

#### Scenario: Two candidates in one file
- **WHEN** two stored `missing-authz` findings exist in `src/server.js` and a run produces one `missing-authz` finding there whose fingerprint matches neither
- **THEN** a new finding is created and both stored findings keep their ids

#### Scenario: User status survives a fallback match
- **WHEN** a stored finding marked false-positive is re-observed through the fallback match
- **THEN** the finding's status remains false-positive
