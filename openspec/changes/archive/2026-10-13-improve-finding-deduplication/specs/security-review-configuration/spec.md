# Spec Delta

## MODIFIED Requirements

### Requirement: Session model is the default for every role
When no override is configured, every agent role (profile, hunt, triage, affirmer, challenger, report) SHALL use the model active in the user's pi session at the time the command is invoked.

#### Scenario: No overrides configured
- **WHEN** the user runs `/security-review` with the session model set to a given provider and model
- **THEN** all audit agents are created with that same model

#### Scenario: Triage role override
- **WHEN** settings specify a model for the `triage` role
- **THEN** the triage agent uses that model and the setting is accepted as a known role
