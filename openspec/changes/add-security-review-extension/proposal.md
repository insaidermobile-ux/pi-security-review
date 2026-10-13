# Proposal

## Why

Pi has no built-in way to audit a codebase for security vulnerabilities. Developers using pi today either run ad-hoc prompts (inconsistent, no false-positive control, no persistent results) or leave pi for external tools. Claude Code ships `/security-review`, Codex has an equivalent, and VulnHunter shows that adversarial verification dramatically reduces false positives. Pi users deserve the same capability, delivered as an installable extension that works out of the box.

## What Changes

- New pi extension `pi-security-review`, distributed as a pi package (installable with `pi install`).
- New slash command `/security-review` that audits the current project for security vulnerabilities.
  - Default scope: all changes not yet merged into the default branch (merge-base against `origin/HEAD`, with fallback to `main`/`master`), including uncommitted and untracked files.
  - `/security-review full`: audits the entire project, honoring `.gitignore` and user-configured excludes.
- Multi-stage audit pipeline: scope resolution, project profiling, hypothesis hunting, adversarial verification (independent affirmer and challenger agents), and report generation.
- Structured, schema-validated findings. Agents submit hypotheses and arguments through typed tools rather than free-form text, so every finding has required anchors, classification, severity, and a recorded verification verdict.
- Persistent findings store at `.security-review/findings.json` in the audited project (git-untracked). Repeat runs deduplicate against it and preserve user-set statuses such as `false-positive` and `accepted-risk`.
- Human-readable `report.md` alongside the JSON store, plus a concise summary posted into the pi session.
- Stage-by-stage progress shown in the pi status bar during a run.
- Per-role model configuration: the session's current model is used for every role by default; each role (`profile`, `hunt`, `affirmer`, `challenger`, `report`) can be overridden in extension settings.
- Audit agents run in isolated in-memory pi sessions with a read-only tool set. They cannot write, edit, or execute arbitrary commands against the audited project.

Explicitly out of scope for this change:

- Dynamic proof-of-concept generation or execution (no sandbox).
- CI integration, GitHub Action, or pull-request commenting.
- Dependency on third-party pi packages such as `pi-subagents`.

## Capabilities

### New Capabilities

- `security-review-command`: The `/security-review` slash command, its argument handling (`full`), scope resolution against git, pre-flight checks (git repository present, non-empty scope), and progress reporting in the pi status bar.
- `security-audit-pipeline`: The staged audit flow (profile, hunt, verify, report), the partitioning strategy per scope mode, the adversarial affirmer/challenger verification protocol, and the isolation guarantees for audit agents.
- `security-findings-store`: The finding schema, the typed submission tools used by agents, the persistent `.security-review/findings.json` store with deduplication and status preservation across runs, and the generated `report.md`.
- `security-review-configuration`: Extension settings covering per-role model overrides, exclude patterns, and other user-tunable behavior.

### Modified Capabilities

None. This is a greenfield project with no existing specs.

## Impact

- **New code**: a TypeScript pi extension (command registration, orchestration over the pi SDK `createAgentSession`, typed tools with output schemas, status-bar integration, JSON/Markdown writers) plus skill/prompt resources for each agent role.
- **Runtime dependencies**: only pi host-provided packages (`@earendil-works/pi-coding-agent` and related). No external services.
- **Audited project footprint**: a `.security-review/` directory is created in the target project. The extension recommends adding it to `.gitignore` and never commits it.
- **Cost**: each run spawns multiple model sessions (profile, N hunt agents, two agents per hypothesis, report). Token usage is aggregated and reported back to the parent session.
- **Security posture**: audit agents operate with a deliberately restricted tool set. The extension itself does not harden against prompt injection embedded in the audited code; this is documented as a known limitation, consistent with comparable tools.
