# security-review-configuration Specification

## Purpose

Defines the user-tunable settings of the security review extension: model selection per agent role, exclude patterns, and run limits.

## Requirements

### Requirement: Session model is the default for every role
When no override is configured, every agent role (profile, hunt, affirmer, challenger, report) SHALL use the model active in the user's pi session at the time the command is invoked.

#### Scenario: No overrides configured
- **WHEN** the user runs `/security-review` with the session model set to a given provider and model
- **THEN** all audit agents are created with that same model

### Requirement: Model can be overridden per role
The extension SHALL accept a per-role model override in its settings, using the `provider/model` form. A role with an override SHALL use that model; roles without one SHALL use the session model.

#### Scenario: Challenger override
- **WHEN** settings specify a model for the challenger role only
- **THEN** challenger agents use that model and all other roles use the session model

#### Scenario: Unknown model in override
- **WHEN** a role override names a model that pi cannot resolve
- **THEN** the command stops before auditing and reports which role's override is invalid

### Requirement: Exclude patterns narrow the scope
The extension SHALL accept a list of glob patterns in its settings. Files matching any pattern SHALL be removed from the audited file set in both default and full modes.

#### Scenario: Vendor directory excluded
- **WHEN** settings exclude a pattern matching a vendored dependency directory and that directory contains changed files
- **THEN** those files are not in the audited file set

### Requirement: Run limits are configurable with defaults
The extension SHALL expose settings for maximum concurrent agents, maximum hypotheses verified per run, and per-agent timeout. Each SHALL have a built-in default used when unset.

#### Scenario: Defaults applied
- **WHEN** no limits are configured
- **THEN** the run uses the built-in defaults for concurrency, hypothesis cap, and timeout

#### Scenario: Custom concurrency
- **WHEN** settings set maximum concurrent agents to a value
- **THEN** no more than that many audit agents run at the same time

### Requirement: Settings can be project-local or user-global
The extension SHALL read settings from the user's global pi configuration and from the project's local pi configuration, with project-local values taking precedence.

#### Scenario: Project overrides global
- **WHEN** the same setting is present in both the global and project configuration
- **THEN** the project value is used

### Requirement: Invalid settings fail fast
When a setting has an invalid type or value, the command SHALL stop before auditing and report the setting name and the problem.

#### Scenario: Non-numeric limit
- **WHEN** the hypothesis cap is configured as a non-numeric value
- **THEN** the command stops and names the setting and expected type
