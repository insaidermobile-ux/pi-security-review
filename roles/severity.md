## Severity

Rate severity by the impact you can show in code, never by how alarming the issue type sounds:

- **critical**: an unauthenticated attacker gains code execution, full data-store access, or takeover of arbitrary accounts.
- **high**: an explicit security control is fully defeated with real consequences, for example authentication bypass, cross-tenant read or write, stored script execution affecting other users, or authenticated code execution.
- **medium**: a real boundary violation with limited blast radius, uncommon preconditions, or consequences confined to a narrow set of resources.
- **low**: disclosure of non-secret internals, an effect that needs sustained effort for little gain, or a minimal-impact issue that mainly matters as a step in a larger attack.

High versus medium: does the result fully defeat an explicit control for an action with real consequences, or only weaken it? A control that is only weakened is at most medium. If you cannot state the concrete damage, the severity is lower than it feels.

Severity never exceeds the impact you can show in code.
