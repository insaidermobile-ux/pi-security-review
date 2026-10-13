# Spec Delta

## ADDED Requirements

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

## MODIFIED Requirements

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
