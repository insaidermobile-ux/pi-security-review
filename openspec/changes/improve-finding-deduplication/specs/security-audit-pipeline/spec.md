# Spec Delta

## ADDED Requirements

### Requirement: Hypotheses sharing a root cause are verified together
After same-type duplicates are merged and before the hypothesis cap is applied, a triage agent SHALL group hypotheses that a single code fix would eliminate. Each group SHALL be verified as one hypothesis: the member the triage agent names as the root cause is the primary issue, and the other members are carried as its consequences. Hypotheses outside any group SHALL proceed unchanged.

#### Scenario: Injection and the disclosure it enables
- **WHEN** hunting yields a SQL injection hypothesis and a secret disclosure hypothesis that is only reachable through that injection
- **THEN** a single hypothesis with the SQL injection as primary issue and the secret disclosure as a consequence proceeds to verification

#### Scenario: Independent issues on the same code
- **WHEN** hunting yields a SQL injection hypothesis and a missing rate limit hypothesis on the same function, which need different fixes
- **THEN** both proceed to verification as separate hypotheses

#### Scenario: Grouped hypotheses count once against the cap
- **WHEN** triage groups three hypotheses into one
- **THEN** the group counts as one hypothesis toward the configured hypothesis cap

### Requirement: Triage is skipped or tolerated without losing coverage
No triage agent SHALL run when fewer than two hypotheses remain after same-type merging. When the triage agent fails, times out, or submits no valid grouping, all hypotheses SHALL proceed to verification ungrouped, the failure SHALL be recorded in the run log and shown in the report, and the run SHALL NOT be marked incomplete for that reason.

#### Scenario: Single hypothesis
- **WHEN** hunting yields exactly one hypothesis
- **THEN** no triage agent runs and the hypothesis proceeds to verification

#### Scenario: Triage agent fails
- **WHEN** the triage agent times out
- **THEN** every hypothesis is verified separately, the report notes that triage was unavailable, and the run's completeness is unaffected

### Requirement: Triage groupings are validated
The triage agent SHALL submit its grouping through a validated tool. A submission SHALL be rejected with an actionable error when a group names an unknown hypothesis, a hypothesis appears in more than one group, a group has fewer than two members, or the named primary issue is not a member of its group.

#### Scenario: Overlapping groups
- **WHEN** the triage agent submits two groups that both contain the same hypothesis
- **THEN** the submission is rejected with an error naming that hypothesis and the agent may resubmit

### Requirement: Verification assesses consequences with the primary issue
For a hypothesis that carries consequences, the affirmer and challenger SHALL receive the consequences with the primary issue. The verdict SHALL apply to the primary issue, and a confirmed or downgraded finding SHALL keep the consequences. A refuted hypothesis SHALL be recorded together with its consequences.

#### Scenario: Confirmed root cause with consequences
- **WHEN** the challenger confirms a hypothesis that carries a consequence
- **THEN** the resulting finding lists that consequence

#### Scenario: Refuted root cause
- **WHEN** the challenger refutes a hypothesis that carries consequences
- **THEN** the refuted record for the run contains the hypothesis with its consequences and no finding is created for them

## MODIFIED Requirements

### Requirement: Audit runs as ordered stages
A run SHALL execute the stages profile, hunt, triage, verify, and report in that order. A stage SHALL start only after the previous stage has completed or has produced partial results marked as such.

#### Scenario: Normal run
- **WHEN** a run starts with a non-empty scope
- **THEN** the profile stage completes before hunting begins, hunting completes before triage, triage completes before verification, and verification completes before the report is written

#### Scenario: Stage fails partway
- **WHEN** a hunt agent fails or times out
- **THEN** hypotheses from the other hunt agents still proceed to verification and the run is marked incomplete in the output

### Requirement: Known false positives inform the challenger
When the findings store contains a finding with status `false-positive` that matches a hypothesis under the store's finding matching rules (exact fingerprint, or the unambiguous vulnerability type and primary file fallback), the challenger SHALL receive that prior finding and its reasoning as context.

#### Scenario: Previously dismissed hypothesis
- **WHEN** a hypothesis matches a stored finding marked false-positive
- **THEN** the challenger is given the prior verdict and must present new evidence to confirm it again

#### Scenario: Dismissed issue described differently
- **WHEN** a hypothesis has a different fingerprint than a stored false-positive finding but is the only hypothesis of its vulnerability type in that finding's primary file, and that finding is the only unmatched stored finding of that type in the file
- **THEN** the challenger is given the prior false-positive verdict
