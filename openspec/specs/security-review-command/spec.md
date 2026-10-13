# security-review-command Specification

## Purpose

Provides the `/security-review` slash command in pi that starts a security audit of the current project, resolves what code is in scope, and reports progress to the user.

## Requirements

### Requirement: Command is available in pi
The extension SHALL register a slash command named `security-review` that is listed in pi's command menu when the extension is loaded.

#### Scenario: Command appears after load
- **WHEN** the extension is installed and a pi session starts
- **THEN** `/security-review` is present in the command menu with a description

### Requirement: Default scope is unmerged changes
When invoked without arguments, the command SHALL audit the set of files changed relative to the merge-base with the default branch, plus modified and untracked files in the working tree.

#### Scenario: Feature branch with commits and uncommitted edits
- **WHEN** the user runs `/security-review` on a branch with commits not on the default branch and additional unstaged edits
- **THEN** the audited file set includes files from those commits and the unstaged edits

#### Scenario: Untracked file is included
- **WHEN** the working tree contains a new file that is not tracked by git and not ignored
- **THEN** that file is included in the audited file set

#### Scenario: Ignored file is excluded
- **WHEN** the working tree contains a file matched by `.gitignore`
- **THEN** that file is not included in the audited file set

### Requirement: Default branch resolution has a fallback chain
The command SHALL resolve the base reference in this order: `origin/HEAD`, `origin/main`, `origin/master`, local `main`, local `master`. It SHALL use the first that exists.

#### Scenario: Remote HEAD is set
- **WHEN** `origin/HEAD` resolves to a branch
- **THEN** the merge-base is computed against that branch

#### Scenario: Repository has no remote
- **WHEN** no `origin` remote exists and a local `main` branch exists
- **THEN** the merge-base is computed against local `main`

#### Scenario: No candidate base exists
- **WHEN** none of the candidate references exist
- **THEN** the command stops with an error naming the references it tried and suggesting `/security-review full`

### Requirement: Full mode audits the whole project
When invoked with the argument `full`, the command SHALL audit all tracked files and all untracked files not matched by `.gitignore`, minus user-configured exclude patterns.

#### Scenario: Full mode on a repository
- **WHEN** the user runs `/security-review full`
- **THEN** the audited file set is the entire project minus ignored files and configured excludes

#### Scenario: Unknown argument
- **WHEN** the user runs `/security-review` with an argument other than `full`
- **THEN** the command stops with a usage message listing accepted arguments

### Requirement: Command requires a git repository
The command SHALL fail with an actionable message when the current working directory is not inside a git work tree.

#### Scenario: Not a git repository
- **WHEN** the user runs `/security-review` outside a git work tree
- **THEN** the command stops before any audit work and explains that a git repository is required

### Requirement: Empty scope stops early
In default mode, when the resolved file set is empty, the command SHALL stop without running the audit and suggest `full` mode.

#### Scenario: Clean tree on default branch
- **WHEN** the user runs `/security-review` on the default branch with no uncommitted or untracked changes
- **THEN** the command reports that there are no unmerged changes and suggests `/security-review full`

### Requirement: Progress is shown in the status bar
While a run is active, the command SHALL display the current stage and, where applicable, a progress count in pi's status bar, and SHALL clear it when the run ends.

#### Scenario: Stage transitions
- **WHEN** the pipeline moves from hunting to verification
- **THEN** the status bar text changes from a hunt indicator with progress to a verify indicator with progress

#### Scenario: Run completes or fails
- **WHEN** the run finishes successfully or stops due to an error
- **THEN** the status bar text set by the command is cleared

### Requirement: Summary is posted to the session
On completion, the command SHALL post a summary into the pi session containing finding counts by severity, the number of refuted hypotheses, and the paths of the generated report and findings store.

#### Scenario: Run with findings
- **WHEN** a run completes with at least one finding
- **THEN** the session shows counts per severity and the paths to `report.md` and `findings.json`

#### Scenario: Run with no findings
- **WHEN** a run completes and every hypothesis was refuted or none were raised
- **THEN** the session shows that no findings were confirmed and still names the report path

### Requirement: Agent-written text stays out of the session model's context
The part of the summary that enters the session model's context SHALL contain only counts, finding identifiers with severity, class, and status, paths, and fixed wording, with a note that the report and store are data written by audit agents. Finding titles, the report summary, and error and incompleteness reasons SHALL be shown to the user only.

#### Scenario: Finding title written by an agent
- **WHEN** a run completes with a finding whose title was written by an audit agent
- **THEN** the user sees the title in the summary, and the message content delivered to the session model names the finding only by identifier, severity, class, and status

### Requirement: A running review can be cancelled
The user SHALL be able to stop a running review: with Esc in the terminal interface, and with `/security-review cancel` where a command can be sent while another runs. A cancelled run SHALL stop its agents, start no new ones, keep what was already verified in the report and the store, be marked incomplete, and still post its summary. A session that shuts down SHALL stop its running review without posting anything.

#### Scenario: Cancelled during hunting
- **WHEN** the user presses Esc while hunt agents are running
- **THEN** the agents stop, no verification agent starts, and the summary says the review was cancelled

#### Scenario: Cancel without a running review
- **WHEN** the user runs `/security-review cancel` and no review is running
- **THEN** the command says that no review is running and does nothing else

#### Scenario: Second review while one is running
- **WHEN** a review is started while another is running in the same session
- **THEN** the second is not started and the user is told how to cancel the first

### Requirement: Child model usage is accounted for
The command SHALL include the aggregated token usage of all audit agents in its result so that session usage totals remain accurate.

#### Scenario: Usage aggregation
- **WHEN** a run spawns several audit agents
- **THEN** the command result's usage equals the sum of the agents' usage plus the command's own
