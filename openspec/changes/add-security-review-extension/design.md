# Design

## Context

See proposal.md for motivation. This is a greenfield pi extension with no existing code.

Constraints that shape the approach:

- Must install and work with only pi host-provided packages. No dependency on `pi-subagents` or other third-party pi extensions.
- Audit agents need to read and search code, so they require tools. A bare model call (`ctx.modelRegistry.streamSimple()`) is insufficient for hunting and verification.
- The extension runs inside the user's interactive pi session. Long-running work must not block the UI and must report progress.
- Audited projects are untrusted input. Agents must not be able to modify them.
- Reference behaviors: Claude Code's `/security-review` resolves scope as `git diff --merge-base origin/HEAD` and fails outside a git repository. VulnHunter's `verify` stage uses a `security-affirmer` / `security-challenger` pair performing static analysis only.

## Goals / Non-Goals

**Goals:**

- Self-contained extension: `pi install` and `/security-review` works.
- Low false-positive rate through adversarial verification with recorded arguments.
- Schema-enforced findings at submission time, not post-hoc parsing.
- Idempotent repeat runs against a persistent store.
- Audit agents are read-only by construction.

**Non-Goals:**

- Dynamic PoC execution or sandboxing. Verification is static (read code, locate defenses, reason about threat model).
- Coverage tracking, wiki/cognition anchors, or other VulnHunter platform machinery.
- Hardening against prompt injection in audited code. Documented limitation.
- Running outside pi (CLI, CI). The pipeline is structured so this could be added later, but it is not designed for now.

## Decisions

### D1. Pipeline shape

```
/security-review [full]
       |
       v
  [scope] ----> [profile] ----> [hunt] ----> [verify] ----> [report]
                                  |             |
                       submit_hypothesis   submit_argument (affirm, then challenge)
                                                |
                                    .security-review/findings.json + report.md
```

Stages:

1. **scope**: resolve the file set and (in diff mode) the diff text. Pure git, no model.
2. **profile**: one agent builds a compact project profile: stack, entry points, trust boundaries, auth model, external inputs. Cached in `.security-review/profile.json` and reused when the project fingerprint (lockfiles, top-level structure) has not changed. In `full` mode the profile is always refreshed.
3. **hunt**: N parallel agents generate *hypotheses*, not findings. Each hypothesis is a claim with an anchor, a suspected source and sink, and a vulnerability type.
4. **verify**: for each hypothesis, two sequential agents. The **affirmer** constructs the attack path and lists missing defenses. The **challenger** receives the affirmer's argument and attempts to refute it. The challenger's verdict determines whether the hypothesis becomes a `vulnerability`, is downgraded to a `risk`, or is refuted and logged.
5. **report**: one agent (or a deterministic writer plus a short model summary) produces `report.md` and the in-session summary.

Rationale: this is VulnHunter's decide-spiral reduced to a linear pass. The adversarial verify stage is where most false-positive reduction happens; everything else is support for it. A linear pipeline is predictable, easy to show as progress, and sufficient for a single-run tool.

Alternative considered: a single-pass audit plus a separate filtering call (Claude Code's model). Simpler, but filtering without a constructed attack path discards less and explains nothing.

### D2. Agent runtime: pi SDK `createAgentSession` inside the extension

Each agent is an `AgentSession` created with `SessionManager.inMemory()`, `cwd` set to the audited project, and an explicitly assembled tool set. Sessions are disposed after use.

Alternatives considered:

- `pi-subagents` package: gives parallelism and model selection for free, but makes the extension unusable without it and relies on an external permission extension for read-only enforcement.
- `ctx.modelRegistry.streamSimple()`: no tools, so agents cannot read code. Usable only for the final summary.

Rationale: self-containment and the ability to construct a read-only tool set directly outweigh the orchestration code we must write (parallel execution, timeouts, result collection, usage aggregation).

### D3. Read-only tool set for audit agents

Audit agents receive: `read`, `grep`, `find`/`glob`, and a constrained `bash` whose allowlist covers read-only inspection commands (`git log`, `git show`, `git blame`, `rg`, `cat`, `ls`, `wc`). No `write`, `edit`, or unrestricted `bash`. Each role additionally receives its submission tool (see D4).

Rationale: the audited project is untrusted. Even with prompt injection in the source, an agent that has no mutating tool cannot damage the project. This is a structural guarantee, not a prompt instruction.

Trade-off: agents cannot run the project's test suite or build to confirm behavior. Accepted; this is consistent with static-only verification (Non-Goals).

### D4. Structured submission through typed tools

Agents hand results back by calling tools with TypeBox parameter schemas and declared `outputSchema`, so validation happens at call time:

- `submit_hypothesis({ anchors[], claim, vuln_type, cwe?, suspected_source, suspected_sink })` — hunt role.
- `submit_argument({ hypothesis_id, side: "affirm", attack_path[], missing_defenses[], preconditions[] })` — affirmer role.
- `submit_argument({ hypothesis_id, side: "challenge", attribution: {...}, defenses_found[], threat_model_notes, verdict: confirmed|downgraded|refuted, confidence })` — challenger role.
- `submit_profile({...})` — profile role.

The orchestrator collects tool call results; agent free text is ignored for data purposes.

Alternative considered: have agents write YAML/Markdown files validated afterwards (VulnHunter's approach). Rejected: schema breakage is detected late and parsing failures are common.

### D5. Finding schema

```
Finding
  id               string   "SR-NNN", stable across runs via fingerprint
  fingerprint      string   hash(vuln_type, normalized anchor file + function, sink)
  title            string   "<component/location> <vuln type> <consequence>"
  finding_class    enum     vulnerability | risk
  vuln_type        string   short tag
  cwe              string?  "CWE-NNN"
  severity         enum     critical | high | medium | low
  cvss_vector      string?
  cvss_score       number?  0..10
  confidence       enum     high | medium | low   (from challenger)
  anchors[]        { file, line, function? }  min 1
  data_flow[]      ordered steps source -> sink
  description      { background, detail, attack_scenario }
  verification     { affirmer: {...}, challenger: {...}, verdict }
  remediation      { summary, patch? }
  scope            enum     diff | full
  introduced_in    string?  commit sha, diff mode only
  status           enum     open | accepted-risk | fixed | false-positive
  first_seen / last_seen   run timestamps
```

Refuted hypotheses are kept in a separate `refuted[]` array with the challenger's reasoning so users can audit what was discarded.

Rationale: `verification` is first-class because the recorded argument pair is the product's main differentiator. `fingerprint` and `status` enable idempotent re-runs. Fields tied to dynamic PoC/EXP from VulnHunter are omitted.

### D6. Persistent store and deduplication

Location: `<project>/.security-review/findings.json` (plus `profile.json`, `report.md`, and per-run logs under `runs/`). The extension never stages or commits these files and, on first run, suggests adding `.security-review/` to `.gitignore` if not already ignored.

On each run:

- New findings are matched by `fingerprint`. Matches update `last_seen` and refresh anchors/line numbers; user-set `status` is preserved.
- Findings with `status: false-positive` are passed to the challenger as prior context so the same hypothesis is not re-confirmed without new evidence.
- Findings not re-observed in `full` mode are marked `stale`; in `diff` mode they are left untouched since the scope does not cover them.

Alternative considered: session-only results. Rejected by decision; no idempotency and no way to suppress known false positives.

### D7. Scope resolution

Default (diff) mode:

1. Verify the cwd is inside a git work tree; otherwise fail with an actionable message.
2. Determine base ref: `origin/HEAD` if it resolves, else `origin/main`, `origin/master`, then local `main`, `master`.
3. Diff set = `git diff --merge-base <base> --name-only` plus `git status --porcelain` untracked and modified files.
4. If the set is empty (for example, the user is on the default branch with a clean tree), stop and suggest `/security-review full`.

Full mode: all tracked files plus untracked-but-not-ignored files, minus user exclude patterns from settings.

### D8. Hunt partitioning by mode

- **diff**: partition by vulnerability class. Each hunt agent gets the whole diff plus the project profile and owns one cluster (injection; authn/authz; secrets and crypto; deserialization and file handling; SSRF and network; business logic and race conditions). Rationale: diffs are small, so cross-cutting review per class is cheap and catches issues that span files.
- **full**: partition by module/directory. Each agent owns a subtree and hunts across all classes. Rationale: full codebases are too large to hand to every class-agent; module ownership bounds context.

Agent count is derived from scope size with a configurable cap.

### D9. Verify protocol: sequential, challenger sees affirmer

The affirmer runs first. The challenger receives the hypothesis, the affirmer's full argument, the project profile, and any prior `false-positive` findings with matching fingerprints. The challenger applies three ordered tests adapted from VulnHunter's challenger skill:

1. **Attribution**: Is the assumed attacker already a trusted role abusing granted capabilities? Is the final harmful step executed unconditionally by the audited component, or does it depend on a downstream consumer? Either failure refutes the hypothesis without further analysis.
2. **Code defenses**: boundary checks, validation, allowlists, sanitization between source and sink; privileged or non-default preconditions; runtime mitigations that downgrade impact; documented intentional behavior. Every check cites a location or states "not found".
3. **Threat-model review**: does the attack precondition imply the system is already compromised at a more fundamental level (no independent security value)? Do out-of-path trust boundaries block the attacker before reaching the source?

Alternative considered: blind challenger plus a third arbiter agent. More independent, but requires an extra model call per hypothesis and the challenger wastes effort rediscovering the attack path. Rejected by decision.

### D10. Models per role

Default: the parent session's current model for every role. Extension settings allow an override per role (`profile`, `hunt`, `affirmer`, `challenger`, `report`). Typical tuning: cheaper model for `hunt`, strongest for `challenger`.

### D11. Progress and UX

The command sets status-bar text through `ctx.ui` as stages advance, for example `security-review: hunt 3/6` and `security-review: verify 7/12`. On completion it posts a short summary into the session (counts by severity, path to `report.md`) and clears the status. Aggregated usage from all child sessions is included in the command's result so session totals stay accurate.

### D12. Package layout

```
pi-security-review/
  package.json          keywords: ["pi-package"], peerDependencies on pi host packages,
                        "pi": { "extensions": ["./extensions/security-review/index.ts"] }
  extensions/
    security-review/    index.ts (entry), command, pipeline, agent runtime, tools,
                        scope, store, schema, report
  roles/                one role prompt each: profile, hunt, affirmer, challenger, report,
                        plus shared ground rules (common.md)
```

Role prompts live in `roles/`, not `skills/` or `prompts/`: pi auto-discovers those directories in a package and would expose the internal role prompts to the user's main session as skills or prompt templates. The explicit `pi` manifest limits the package to its one extension.

## Risks / Trade-offs

- [Prompt injection in audited code steers an agent] → Agents are read-only by construction; the worst case is a bad or missing finding, not damage. Documented limitation.
- [Cost grows with hypothesis count: two agents per hypothesis] → Cap hypotheses per run; dedupe hypotheses by anchor+type before verify; allow cheaper models for hunt.
- [Static verification misses runtime-only defenses or confirms unreachable paths] → Challenger must cite locations; findings carry `confidence`; dynamic PoC is a documented future extension.
- [Scope resolution fails on unusual git setups (shallow clones, no remote, detached HEAD)] → Ordered fallback chain plus clear error text with the exact command the user can run to fix it.
- [Large full-mode runs exceed context or time limits] → Module partitioning with a cap on agent count; per-agent timeouts; partial results are still written to the store with the run marked incomplete.
- [Line numbers in findings drift between runs] → Fingerprint uses file+function+sink rather than line; anchors are refreshed on re-observation.
- [Concurrent in-memory sessions compete for provider rate limits] → Configurable parallelism cap with sensible default.

## Open Questions

- Exact default caps (max hunt agents, max hypotheses per run, per-agent timeout). Can be tuned after first real runs without changing the approach.
- Whether `report.md` should be regenerated fully each run or appended with a per-run section. Does not affect the store or the pipeline.
