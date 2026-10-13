# Spec Delta

## Purpose

Defines the staged security audit performed on the in-scope code: project profiling, hypothesis hunting, adversarial verification by independent affirmer and challenger agents, and report generation, together with the isolation guarantees for those agents.

## ADDED Requirements

### Requirement: Audit runs as ordered stages
A run SHALL execute the stages profile, hunt, verify, and report in that order. A stage SHALL start only after the previous stage has completed or has produced partial results marked as such.

#### Scenario: Normal run
- **WHEN** a run starts with a non-empty scope
- **THEN** the profile stage completes before hunting begins, hunting completes before verification, and verification completes before the report is written

#### Scenario: Stage fails partway
- **WHEN** a hunt agent fails or times out
- **THEN** hypotheses from the other hunt agents still proceed to verification and the run is marked incomplete in the output

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
When the findings store contains a finding with status `false-positive` whose fingerprint matches a hypothesis, the challenger SHALL receive that prior finding and its reasoning as context.

#### Scenario: Previously dismissed hypothesis
- **WHEN** a hypothesis matches a stored finding marked false-positive
- **THEN** the challenger is given the prior verdict and must present new evidence to confirm it again

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
