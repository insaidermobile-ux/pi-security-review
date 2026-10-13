# Spec Delta

## ADDED Requirements

### Requirement: Roles can use models served by pi-claude-bridge
When a role's model is served by the `claude-bridge` provider and the bridge is installed, each audit agent of that role SHALL register its system prompt with the bridge before its requests, so that the bridge accepts them. The registered prompt SHALL carry only the role's instructions, without project context files or skills. Agents on other providers SHALL be unaffected.

#### Scenario: Session model served by the bridge
- **WHEN** the session model is a `claude-bridge` model and no role overrides are configured
- **THEN** every audit agent's request is accepted by the bridge and the run completes

#### Scenario: Bridge not installed
- **WHEN** a role uses a model from another provider
- **THEN** no prompt is registered and the agent runs as before
