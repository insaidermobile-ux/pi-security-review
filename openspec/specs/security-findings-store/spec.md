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
Every finding SHALL contain at least one anchor (file, line, optional function), an ordered data flow, a description, a remediation, and a verification record holding the affirmer argument, the challenger argument, and the verdict. CWE identifier, CVSS vector and score, and introducing commit are optional.

#### Scenario: Verification record complete
- **WHEN** a finding is created
- **THEN** its verification record holds both arguments and the verdict

#### Scenario: Invalid finding is rejected
- **WHEN** a finding is produced without an anchor or without a verdict
- **THEN** it is not written to the store and the error is logged for the run

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
After a full-mode run, stored findings that were not re-observed SHALL be marked `stale`. After a default-mode run, findings outside the run's scope SHALL be left unchanged.

#### Scenario: Finding disappears in full mode
- **WHEN** a full-mode run completes without re-observing a stored open finding
- **THEN** that finding is marked stale

#### Scenario: Finding outside diff scope
- **WHEN** a default-mode run completes and a stored finding's files are not in scope
- **THEN** that finding is unchanged

### Requirement: Refuted hypotheses are retained
Each run SHALL record refuted hypotheses with the challenger's reasoning in the store, separate from findings, so users can review what was discarded.

#### Scenario: Refuted record
- **WHEN** the challenger refutes a hypothesis
- **THEN** the store's refuted list for that run contains the hypothesis, the affirmer argument, and the challenger reasoning

### Requirement: Store is written atomically
Updates to `findings.json` SHALL be written so that an interrupted run leaves either the previous content or the new content, never a truncated file.

#### Scenario: Interrupted write
- **WHEN** the process is interrupted while the store is being saved
- **THEN** `findings.json` is parseable and contains either the pre-run or post-run state
