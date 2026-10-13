# security-audit-pipeline Specification

## Purpose

Defines the staged security audit performed on the in-scope code: project profiling, hypothesis hunting, adversarial verification by independent affirmer and challenger agents, and report generation, together with the isolation guarantees for those agents.

## Requirements

### Requirement: Audit runs as ordered stages
A run SHALL execute the stages profile, hunt, triage, verify, and report in that order. A stage SHALL start only after the previous stage has completed or has produced partial results marked as such.

#### Scenario: Normal run
- **WHEN** a run starts with a non-empty scope
- **THEN** the profile stage completes before hunting begins, hunting completes before triage, triage completes before verification, and verification completes before the report is written

#### Scenario: Stage fails partway
- **WHEN** a hunt agent times out, or fails and its failure remains after any retry
- **THEN** hypotheses from the other hunt agents still proceed to verification and the run is marked incomplete in the output

### Requirement: Transient model request failures are retried
An audit agent whose model request fails with a transient provider error (rate limit, overload, server or network error) SHALL retry the request up to 6 times with exponential backoff starting at 5 seconds and capped at 60 seconds per wait.

#### Scenario: Short rate limit
- **WHEN** an audit agent's model request is answered with a rate-limit error twice and then succeeds
- **THEN** the agent continues and finishes normally

### Requirement: A hunt agent that fails transiently is re-run once
A hunt agent that still fails with a transient error after its retries SHALL be re-run once, after the other hunt agents have finished. A successful re-run's hypotheses SHALL replace those of the failed attempt, and the run SHALL NOT be incomplete because of that agent. After a failed re-run, both attempts' hypotheses SHALL proceed and the run SHALL be incomplete. Other failures SHALL NOT be re-run. The run log SHALL record both attempts.

#### Scenario: Rate limit outlasts in-session retries
- **WHEN** a hunt agent fails with a rate-limit error after exhausting its retries, and its re-run succeeds
- **THEN** the re-run's hypotheses proceed to verification, the run is complete, and the run log lists both attempts

#### Scenario: Re-run also fails
- **WHEN** a hunt agent fails with a rate-limit error and its re-run fails with the same error
- **THEN** hypotheses submitted by either attempt proceed to verification and the run is marked incomplete

#### Scenario: Timeout is not re-run
- **WHEN** a hunt agent times out
- **THEN** it is not re-run and the run is marked incomplete

### Requirement: A rejected profile request stops hunting on the same model
When the profile agent's model request is rejected with a provider error that is neither transient nor a context overflow, and the hunt role uses the same model, the hunt and verify stages SHALL NOT start. The run SHALL end incomplete with a reason naming the model, and the report and store SHALL be written. Timeouts, cancellations, transient errors, context overflow, and a profile agent that finishes without submitting SHALL NOT stop the run.

#### Scenario: Provider refuses every request
- **WHEN** the profile agent's request is rejected with a non-transient provider error and every role uses the session model
- **THEN** no hunt or verification agent runs, the run is marked incomplete with a reason naming the model and the error, and the report is written

#### Scenario: Hunt uses another model
- **WHEN** the profile agent's request is rejected with a non-transient provider error and the hunt role is configured with a different model
- **THEN** the hunt stage runs without a project profile

#### Scenario: Profile agent times out
- **WHEN** the profile agent times out
- **THEN** the hunt stage runs

### Requirement: Agent failures are reported compactly
Agents of the same stage that fail with the same error SHALL be reported as one incomplete reason naming the number of agents, at most three labels, and the error. Labels and errors in incomplete reasons SHALL be shortened. The run log SHALL keep each agent's full error.

#### Scenario: Many hunt agents fail the same way
- **WHEN** six hunt agents fail with the same error
- **THEN** the run has one incomplete reason for them, of the form `6 hunt agents failed (<label>, <label>, <label> and 3 more): <error>`, and the run log lists all six with their full errors

#### Scenario: Long error
- **WHEN** an agent fails with an error longer than 300 characters
- **THEN** the incomplete reason shows a shortened error ending in an ellipsis

### Requirement: Profile stage produces a project profile
The profile stage SHALL produce a structured description of the project covering technology stack, entry points, trust boundaries, authentication and authorization model, and external input sources. This profile SHALL be provided to every later agent.

#### Scenario: Profile is reused in default mode
- **WHEN** a default-mode run starts and a cached profile exists whose project fingerprint matches the current project
- **THEN** the cached profile is used and the profile stage does not call a model

#### Scenario: Profile is refreshed in full mode
- **WHEN** a full-mode run starts
- **THEN** the profile is regenerated regardless of any cached profile

### Requirement: Hunt stage yields hypotheses, not findings
Hunt agents SHALL produce hypotheses. Each hypothesis MUST include at least one code anchor (file and line), a claim, a vulnerability type, a suspected source, and a suspected sink. Hypotheses missing any required field SHALL be rejected at submission.

#### Scenario: Valid hypothesis
- **WHEN** a hunt agent submits a hypothesis with all required fields
- **THEN** it is accepted and queued for verification

#### Scenario: Hypothesis without anchor
- **WHEN** a hunt agent submits a hypothesis with no code anchor
- **THEN** the submission is rejected with a validation error and the agent may retry

### Requirement: Hunt partitioning depends on scope mode
In default mode, the hunt stage SHALL partition work by vulnerability class, giving each agent the whole scope and one class cluster. In full mode, it SHALL partition work by module or directory, giving each agent one subtree and all classes.

#### Scenario: Default mode partitioning
- **WHEN** a default-mode run enters the hunt stage
- **THEN** each hunt agent receives the full in-scope diff and is assigned one vulnerability class cluster

#### Scenario: Full mode partitioning
- **WHEN** a full-mode run enters the hunt stage
- **THEN** each hunt agent receives one subtree of the project and hunts for all vulnerability classes within it

### Requirement: Duplicate hypotheses are merged before verification
Hypotheses with the same vulnerability type and overlapping anchors SHALL be merged into one before the verify stage.

#### Scenario: Two agents report the same issue
- **WHEN** two hunt agents submit hypotheses with the same vulnerability type anchored on the same function
- **THEN** a single hypothesis proceeds to verification

### Requirement: Each hypothesis is verified by an affirmer then a challenger
For every hypothesis, the verify stage SHALL run an affirmer agent and then a challenger agent as separate agents. The challenger SHALL receive the affirmer's complete argument.

#### Scenario: Sequential verification
- **WHEN** a hypothesis enters verification
- **THEN** the affirmer submits an argument first, and the challenger starts only after that argument is available

#### Scenario: Agents are independent
- **WHEN** the affirmer and challenger run for one hypothesis
- **THEN** they are separate agent sessions with no shared conversation history other than the inputs explicitly provided

### Requirement: Affirmer constructs the attack path
The affirmer SHALL submit an argument containing an ordered attack path from source to sink, the defenses it found missing, and the preconditions an attacker needs.

#### Scenario: Affirmer argument
- **WHEN** the affirmer finishes
- **THEN** its submitted argument contains a non-empty attack path and a list of missing defenses, each citing a code location or stating it was not found

### Requirement: Challenger applies attribution, code-defense, and threat-model tests
The challenger SHALL evaluate, in order: whether the attacker is a trusted role abusing granted capabilities or the harmful final step is executed outside the audited component; whether code defenses or preconditions block or downgrade the path; and whether the attack has independent security value under the project's threat model. It SHALL return a verdict of confirmed, downgraded, or refuted with a confidence level.

#### Scenario: Attribution failure
- **WHEN** the challenger determines that the assumed attacker is already a trusted role exercising granted capabilities
- **THEN** the verdict is refuted and the reasoning cites the attribution test

#### Scenario: Defense found in code
- **WHEN** the challenger locates validation between source and sink that makes the path unreachable
- **THEN** the verdict is refuted and the argument cites the file and line of the defense

#### Scenario: Path valid but impact limited
- **WHEN** the path is reachable but preconditions imply the system is already compromised at a more fundamental level
- **THEN** the verdict is downgraded and the hypothesis becomes a risk finding

#### Scenario: Path valid and impactful
- **WHEN** the challenger finds no attribution failure, no blocking defense, and independent impact
- **THEN** the verdict is confirmed and the hypothesis becomes a vulnerability finding

### Requirement: Known false positives inform the challenger
When the findings store contains a finding with status `false-positive` that matches a hypothesis under the store's finding matching rules (exact fingerprint, or the unambiguous vulnerability type and primary file fallback), the challenger SHALL receive that prior finding and its reasoning as context.

#### Scenario: Previously dismissed hypothesis
- **WHEN** a hypothesis matches a stored finding marked false-positive
- **THEN** the challenger is given the prior verdict and must present new evidence to confirm it again

#### Scenario: Dismissed issue described differently
- **WHEN** a hypothesis has a different fingerprint than a stored false-positive finding but is the only hypothesis of its vulnerability type in that finding's primary file, and that finding is the only unmatched stored finding of that type in the file
- **THEN** the challenger is given the prior false-positive verdict

### Requirement: Verification is static
Verification agents SHALL reason from source code, configuration, and version history only. They SHALL NOT build, run, or test the audited project.

#### Scenario: No execution
- **WHEN** any verification agent runs
- **THEN** no build, test, or application process of the audited project is started

### Requirement: Audit agents are read-only
Every audit agent SHALL operate with a tool set that cannot create, modify, or delete files in the audited project and cannot execute arbitrary shell commands. Shell access, when provided, SHALL be limited to an allowlist of read-only inspection commands.

#### Scenario: Write attempt
- **WHEN** an audit agent attempts to call a file-writing or editing tool
- **THEN** no such tool is available to it and the attempt fails

#### Scenario: Disallowed shell command
- **WHEN** an audit agent attempts a shell command outside the read-only allowlist
- **THEN** the command is rejected and not executed

### Requirement: Agents run in isolated sessions
Each audit agent SHALL run in its own session that is not persisted to the user's session list and is disposed when the agent finishes.

#### Scenario: Session list unaffected
- **WHEN** a run spawns several audit agents
- **THEN** none of them appear in pi's saved sessions after the run

### Requirement: Report stage produces human-readable output
The report stage SHALL produce a Markdown report listing confirmed and downgraded findings grouped by severity, each with anchors, data flow, both verification arguments, verdict, and remediation, followed by a section of refuted hypotheses with the challenger's reasoning.

#### Scenario: Report content
- **WHEN** a run completes
- **THEN** the report contains every finding from this run with its verification arguments and a refuted section

### Requirement: Parallelism and hypothesis count are bounded
The number of concurrently running agents and the number of hypotheses verified per run SHALL be limited by configurable caps.

#### Scenario: Hypothesis cap reached
- **WHEN** hunting yields more hypotheses than the configured cap
- **THEN** hypotheses are prioritized by severity estimate, the excess are listed as unverified in the report, and the run is marked incomplete

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
