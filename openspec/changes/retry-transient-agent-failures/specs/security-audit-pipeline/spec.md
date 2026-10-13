# Spec Delta

## ADDED Requirements

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

## MODIFIED Requirements

### Requirement: Audit runs as ordered stages
A run SHALL execute the stages profile, hunt, triage, verify, and report in that order. A stage SHALL start only after the previous stage has completed or has produced partial results marked as such.

#### Scenario: Normal run
- **WHEN** a run starts with a non-empty scope
- **THEN** the profile stage completes before hunting begins, hunting completes before triage, triage completes before verification, and verification completes before the report is written

#### Scenario: Stage fails partway
- **WHEN** a hunt agent times out, or fails and its failure remains after any retry
- **THEN** hypotheses from the other hunt agents still proceed to verification and the run is marked incomplete in the output
