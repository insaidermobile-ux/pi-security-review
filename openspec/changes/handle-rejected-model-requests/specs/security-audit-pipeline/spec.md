# Spec Delta

## ADDED Requirements

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
