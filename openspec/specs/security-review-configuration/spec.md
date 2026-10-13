# security-review-configuration Specification

## Purpose

Defines the user-tunable settings of the security review extension: model selection per agent role, exclude patterns, and run limits.

## Requirements

### Requirement: Session model is the default for every role
When no override is configured, every agent role (profile, hunt, triage, affirmer, challenger, report) SHALL use the model active in the user's pi session at the time the command is invoked.

#### Scenario: No overrides configured
- **WHEN** the user runs `/security-review` with the session model set to a given provider and model
- **THEN** all audit agents are created with that same model

#### Scenario: Triage role override
- **WHEN** settings specify a model for the `triage` role
- **THEN** the triage agent uses that model and the setting is accepted as a known role

### Requirement: Model can be overridden per role
The extension SHALL accept a per-role model override in its settings, using the `provider/model` form. A role with an override SHALL use that model; roles without one SHALL use the session model.

#### Scenario: Challenger override
- **WHEN** settings specify a model for the challenger role only
- **THEN** challenger agents use that model and all other roles use the session model

#### Scenario: Unknown model in override
- **WHEN** a role override names a model that pi cannot resolve
- **THEN** the command stops before auditing and reports which role's override is invalid

### Requirement: Roles can use models served by pi-claude-bridge
When a role's model is served by the `claude-bridge` provider and the bridge is installed, each audit agent of that role SHALL register its system prompt with the bridge before its requests, so that the bridge accepts them. The registered prompt SHALL carry only the role's instructions, without project context files or skills. Agents on other providers SHALL be unaffected.

#### Scenario: Session model served by the bridge
- **WHEN** the session model is a `claude-bridge` model and no role overrides are configured
- **THEN** every audit agent's request is accepted by the bridge and the run completes

#### Scenario: Bridge not installed
- **WHEN** a role uses a model from another provider
- **THEN** no prompt is registered and the agent runs as before

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
