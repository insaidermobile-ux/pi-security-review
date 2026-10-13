# pi-security-review

Adversarial, multi-agent security review for [pi](https://pi.dev). Run `/security-review` in a pi session and the extension audits your unmerged changes (or the whole project) for exploitable vulnerabilities, then tries hard to refute every candidate before reporting it.

Inspired by Claude Code's `/security-review` and by the affirmer/challenger verification in [VulnHunter](https://github.com/Clouditera/VulnHunter).

## How it works

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

1. **scope**: resolves which files to audit using git.
2. **profile**: one agent describes the project: stack, entry points, trust boundaries, auth model, external inputs. Cached between runs.
3. **hunt**: several agents in parallel look for candidate vulnerabilities and submit *hypotheses* with code anchors, a suspected source, and a suspected sink.
4. **verify**: for every hypothesis an **affirmer** agent builds the attack path, then an independent **challenger** agent tries to refute it. It checks attribution (is the "attacker" already trusted?), code defenses between source and sink, and whether the attack has independent security value. Confirmed hypotheses become `vulnerability` findings, downgraded ones become `risk` findings, and refuted ones are kept in a log with the reasoning.
5. **report**: writes `report.md`, merges findings into `findings.json`, and posts a summary into the session.

Agents submit results through schema-validated tools, so every finding has anchors, a severity, a confidence, and both verification arguments.

## Install

Requires pi 1.1 or later.

```bash
# from GitHub
pi install git:github.com/<owner>/pi-security-review

# from a local checkout
pi install ./pi-security-review

# project-local install (writes .pi/settings.json instead of your user settings)
pi install -l ./pi-security-review

# try it for one session without installing
pi -e ./pi-security-review
```

## Usage

Run the command inside a git repository.

| Command | Scope |
|---|---|
| `/security-review` | Changes not yet merged into the default branch: the merge-base diff against `origin/HEAD` (falling back to `origin/main`, `origin/master`, `main`, `master`), plus uncommitted and untracked files. Ignored files are skipped. |
| `/security-review full` | The whole project: tracked files plus untracked files not ignored by `.gitignore`. |

Both modes remove files matched by your configured `exclude` patterns.

Progress is shown in pi's status bar, for example `security-review: hunt 3/6` and then `security-review: verify 7/12`. When the run finishes, a summary with counts by severity is posted into the session.

### Output

Everything is written to `.security-review/` in the audited project:

| File | Contents |
|---|---|
| `findings.json` | Persistent findings store. Repeat runs deduplicate by a line-independent fingerprint. |
| `report.md` | Human-readable report for the latest run, regenerated each run. |
| `profile.json` | Cached project profile. |
| `runs/` | Per-run logs. |

The extension never stages or commits these files. If `.security-review/` is not ignored, the summary recommends adding it to `.gitignore`.

### Triage

Each finding has a `status`: `open`, `accepted-risk`, `fixed`, `false-positive`, or `stale`. Edit `status` in `findings.json` to record your decision. The extension preserves `accepted-risk`, `fixed`, and `false-positive` across runs. When a hypothesis matches a finding marked `false-positive`, the challenger sees your earlier verdict and must present new evidence to confirm it again.

After a `full` run, findings that were not observed again are marked `stale`. Default (diff) runs never mark findings stale, because they only see part of the project.

## Settings

Settings live under the `securityReview` key of pi's settings files: `~/.pi/agent/settings.json` (global) and `.pi/settings.json` in the project (read only when the project is trusted). Project values take precedence. All keys are optional.

```json
{
  "securityReview": {
    "models": {
      "hunt": "zai/glm-5.3-flash",
      "challenger": "anthropic/claude-opus-5-5"
    },
    "exclude": ["vendor/**", "*.min.js", "test/fixtures"],
    "maxConcurrentAgents": 4,
    "maxHypotheses": 24,
    "agentTimeoutSeconds": 600
  }
}
```

| Key | Default | Description |
|---|---|---|
| `models` | session model for every role | Per-role model override as `provider/model`. Roles: `profile`, `hunt`, `affirmer`, `challenger`, `report`. A typical setup uses a cheaper model for `hunt` and the strongest one for `challenger`. |
| `exclude` | `[]` | Glob patterns removed from the audited files in both modes. A pattern without a slash also matches by name at any depth; a directory name excludes everything below it. |
| `maxConcurrentAgents` | `4` | Maximum number of audit agents running at the same time. |
| `maxHypotheses` | `24` | Maximum hypotheses verified per run. The most severe are verified first; the rest are listed as unverified and the run is marked incomplete. |
| `agentTimeoutSeconds` | `600` | Time limit for each audit agent. A timed-out agent marks the run incomplete; other agents continue. |

Invalid values stop the command before any model call, with the setting name and the expected type. Unknown keys and unknown model identifiers are reported the same way.

Agents use the session's thinking level.

## Security model and limitations

- **Read-only agents.** Audit agents get `read`, `grep`, `find`, `ls`, and a restricted shell that only runs an allowlist of inspection commands (`git log/show/blame/diff/grep/ls-files`, `rg`, `cat`, `head`, `tail`, `ls`, `wc`) without a shell interpreter. They have no `write`, `edit`, or general `bash`, so they cannot modify the audited project.
- **Static verification only.** Agents never build, run, or test the audited project. Defenses that only exist at runtime can be missed, and reachability is argued from code, not demonstrated. Each finding carries a `confidence` value.
- **Prompt injection.** The audited code is untrusted input. Comments or strings in it can steer an agent's reasoning and cause missed or spurious findings. Read-only tools limit the damage to the report itself. This is a known limitation shared by comparable tools.
- **Cost.** A run uses one profile agent, six hunt agents in default mode (one per vulnerability class) or one per project subtree in `full` mode, two agents per verified hypothesis, and one summary agent. Token usage of all agents is added to your session totals (`/session`). Use the settings above to bound cost.
- **Deduplication is heuristic.** Findings are matched across runs by a fingerprint of vulnerability type, file, enclosing function, and sink API, not by line number. Models sometimes describe the same issue differently, especially authorization issues, which have no single sink; such a repeat appears as a new finding and the old one becomes `stale` after the next `full` run.
- **Overlapping findings.** Agents hunting different vulnerability classes can report several consequences of one root cause (for example SQL injection and the secret disclosure it enables) as separate findings.
- **Not included.** No proof-of-concept execution, sandboxing, CI integration, or pull-request comments.

## Development

```bash
npm install
npm run check            # typecheck + tests (no model calls; agents run against pi's faux provider)
./scripts/check-load.sh  # load the package into pi and list its commands

# real-model checks against the seeded fixture in test/fixtures/vulnerable-app (uses your pi credentials)
node scripts/dry-run.ts all [--model provider/id]   # profile, hunt, affirmer, and challenger roles
node scripts/rpc-run.ts --cwd <repo> -- "/security-review"   # whole command through pi's RPC mode
```

Role prompts are in `roles/`. The fixture under `test/fixtures/vulnerable-app` is deliberately vulnerable; exclude `test/fixtures` when running `/security-review full` on this repository.
