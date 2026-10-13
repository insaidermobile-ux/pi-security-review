# pi-security-review

Adversarial, multi-agent security review for [pi](https://pi.dev). Run `/security-review` in a pi session and the extension audits your unmerged changes (or the whole project) for exploitable vulnerabilities, then tries hard to refute every candidate before reporting it.

Inspired by Claude Code's `/security-review` and by the affirmer/challenger verification in [VulnHunter](https://github.com/Clouditera/VulnHunter).

## How it works

```
/security-review [full]
       |
       v
  [scope] --> [profile] --> [hunt] --> [triage] --> [verify] --> [report]
                              |           |            |
                 submit_hypothesis  submit_triage  submit_argument (affirm, then challenge)
                                                       |
                                       .security-review/findings.json + report.md
```

1. **scope**: resolves which files to audit using git.
2. **profile**: one agent describes the project: stack, entry points, trust boundaries, auth model, external inputs. Cached between runs.
3. **hunt**: several agents in parallel look for candidate vulnerabilities and submit *hypotheses* with code anchors, a suspected source, and a suspected sink.
4. **triage**: when there are at least two hypotheses, one agent groups the ones a single code fix would remove, for example a SQL injection and the secret disclosure it enables. Each group is verified as one hypothesis: the root cause, with the others attached as consequences. If triage fails, hypotheses are verified separately.
5. **verify**: for every hypothesis an **affirmer** agent builds the attack path, then an independent **challenger** agent tries to refute it. It checks attribution (is the "attacker" already trusted?), code defenses between source and sink, and whether the attack has independent security value. Confirmed hypotheses become `vulnerability` findings, downgraded ones become `risk` findings, and refuted ones are kept in a log with the reasoning.
6. **report**: writes `report.md` and merges findings into `findings.json`, then one agent writes a short summary for the report, and the command posts the result into the session.

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

Progress is shown in pi's status bar, for example `security-review: hunt 3/6`, `security-review: triage`, and then `security-review: verify 7/12`. When the run finishes, a summary with counts by severity is posted into the session.

To stop a running review, press Esc. Agents stop, what was already verified is kept in the report and the store, and the run is marked incomplete. Where pi runs commands without queueing them, such as RPC mode, send `/security-review cancel`; in the terminal a command typed during a review waits until the review ends.

### Output

Everything is written to `.security-review/` in the audited project:

| File | Contents |
|---|---|
| `findings.json` | Persistent findings store. Repeat runs deduplicate by a line-independent fingerprint, falling back to vulnerability type and file when that match is unambiguous. |
| `report.md` | Human-readable report for the latest run, regenerated each run. |
| `profile.json` | Cached project profile. |
| `runs/` | Per-run logs. |

The extension never stages or commits these files. If `.security-review/` is not ignored, the summary recommends adding it to `.gitignore`.

Keep the directory out of git. `findings.json` and `profile.json` hold your own decisions and are given to agents as trusted context, so a branch that changes them could hide a finding from its own review. If either file is tracked and differs between the review base and `HEAD`, the command stops before any model call and tells you how to restore the file or stop tracking it.

### Reviewing findings

Each finding has a `status`: `open`, `accepted-risk`, `fixed`, `false-positive`, or `stale`. Edit `status` in `findings.json` to record your decision. The extension preserves `accepted-risk`, `fixed`, and `false-positive` across runs. When a hypothesis matches a finding marked `false-positive`, the challenger sees your earlier verdict and must present new evidence to confirm it again. A status you set while a review is running is kept: the run merges its results into the store as it is when verification ends.

After a complete `full` run, findings that were not observed again are marked `stale`. A `full` run that ends incomplete (an agent failed or timed out, the hypothesis cap was reached, a verified hypothesis could not be recorded, or the run was cancelled) marks nothing stale and says so in the summary, because unobserved findings may simply not have been checked. Default (diff) runs never mark findings stale, because they only see part of the project.

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
| `models` | session model for every role | Per-role model override as `provider/model`. Roles: `profile`, `hunt`, `triage`, `affirmer`, `challenger`, `report`. A typical setup uses a cheaper model for `hunt` and the strongest one for `challenger`. |
| `exclude` | `[]` | Glob patterns removed from the audited files in both modes. A pattern without a slash also matches by name at any depth; a directory name excludes everything below it. Wildcards match names that begin with a dot, so `*.json` covers `.eslintrc.json`. |
| `maxConcurrentAgents` | `4` | Maximum number of audit agents running at the same time. |
| `maxHypotheses` | `24` | Maximum hypotheses verified per run. The most severe are verified first; the rest are listed as unverified and the run is marked incomplete. |
| `agentTimeoutSeconds` | `600` | Time limit for each audit agent, including waits between retries. A timed-out agent marks the run incomplete; other agents continue. |

Invalid values stop the command before any model call, with the setting name and the expected type. Unknown keys and unknown model identifiers are reported the same way.

Agents use the session's thinking level.

## Security model and limitations

- **Read-only agents, confined to the project.** Audit agents get `read`, `grep`, `find`, `ls`, and a restricted shell that only runs an allowlist of inspection commands (`git log/show/blame/diff/grep/ls-files`, `rg`, `cat`, `head`, `tail`, `ls`, `wc`) without a shell interpreter. They have no `write`, `edit`, or general `bash`, so they cannot modify the audited project. Options that make these commands run a program or write a file are rejected, including abbreviated spellings. Every path must stay inside the project: absolute paths outside it, `~`, `..`, and symbolic links that lead outside are refused, so an agent cannot read your SSH keys or other projects. `rg` does not follow symbolic links.
- **Static verification only.** Agents never build, run, or test the audited project. Defenses that only exist at runtime can be missed, and reachability is argued from code, not demonstrated. Each finding carries a `confidence` value.
- **Prompt injection.** The audited code is untrusted input. Comments or strings in it can steer an agent's reasoning and cause missed or spurious findings. Read-only tools confined to the project limit the damage to the report itself. Your session's model does not see what audit agents wrote: the message it receives has only counts, finding ids, and file paths, while titles and the summary are shown to you alone. If you then ask the model to read `report.md` or `findings.json`, it reads text written by agents that read untrusted code. This is a known limitation shared by comparable tools.
- **Rate limits and provider errors.** Audit agents retry a model request that fails with a transient error (rate limit, overload, server or network error) up to 6 times, waiting 5, 10, 20, 40, 60, and 60 seconds. A hunt agent that still fails this way is run once more after the other hunt agents finish; if that works, the run stays complete and the Errors section of the report notes the re-run. Quota and billing errors are not retried. If your provider throttles concurrent requests, lower `maxConcurrentAgents`.
- **A refused model stops the run early.** If the provider refuses the profile agent's request with an error that retrying cannot fix, such as an invalid key or exhausted quota, no hunt agents start on the same model. The run ends incomplete with that error. When many agents fail with the same error, the summary reports it once, shortened; the run log in `.security-review/runs/` keeps each agent's full error.
- **Models served by `pi-claude-bridge`.** Audit agents run without extensions, so the bridge would not recognize their prompts and would refuse them. The extension registers each agent's prompt with the bridge itself. Claude Code then receives its own system prompt plus the role instructions, without your project context files or skills, and can call only the audit agent's read-only tools. Each agent uses your Claude subscription quota, and the bridge writes one Claude Code session file per agent under `~/.claude/projects/`. Registration relies on an internal part of the bridge, verified with version 0.9.2. If a later version changes it, the bridge refuses the requests again and the run stops after the profile agent; set `securityReview.models` to another model until this extension is updated.
- **Cost.** A run uses one profile agent, six hunt agents in default mode (one per vulnerability class) or one per project subtree in `full` mode, one triage agent when there are at least two hypotheses, two agents per verified hypothesis, and one summary agent, plus a re-run for each hunt agent that failed on a transient error. Triage usually pays for itself by merging hypotheses before verification. Token usage of all agents is added to your session totals (`/session`). Use the settings above to bound cost.
- **Deduplication is heuristic.** Findings are matched across runs by a fingerprint of vulnerability type, file, enclosing function, and sink API, not by line number. When the fingerprint differs, a finding still matches a stored one of the same type in the same file, but only if there is exactly one candidate on each side; otherwise it becomes a new finding. If an issue is fixed and a different issue of the same type appears in the same file, the new one inherits the old id and status. It is still fully verified, and the challenger is told to disregard an earlier false-positive verdict about a different code path.
- **Root-cause grouping is a judgment call.** Triage may miss a group, which leaves a duplicate finding, or group too eagerly: a consequence is dropped together with its root cause when the root cause is refuted. Refuted records keep their consequences so you can review them. Findings that earlier versions already split stay split.
- **Not included.** No proof-of-concept execution, sandboxing, CI integration, or pull-request comments.

## Development

```bash
npm install
npm run check            # typecheck + tests (no model calls; agents run against pi's faux provider)
./scripts/check-load.sh  # load the package into pi and list its commands

# real-model checks against the seeded fixture in test/fixtures/vulnerable-app (uses your pi credentials)
node scripts/dry-run.ts all [--model provider/id]   # profile, hunt, triage, affirmer, and challenger roles
node scripts/rpc-run.ts --cwd <repo> -- "/security-review"   # whole command through pi's RPC mode

# a fixture repository that outlives the command, for rpc-run
SR_KEEP_TEMP=1 node -e 'import("./test/git-fixtures.ts").then((m) => console.log(m.makeFixtureRepo()))'
```

Role prompts are in `roles/`. The fixture under `test/fixtures/vulnerable-app` is deliberately vulnerable; exclude `test/fixtures` when running `/security-review full` on this repository.
