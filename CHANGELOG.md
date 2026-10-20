# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-20

### Added

- Hunters, affirmers, and challengers rate severity with one shared scale. A path that fully defeats an explicit control ranks above one that only weakens it. Severity never exceeds the impact the agent can show in code.
- Two hunt classes. "Feature abuse and data exposure" covers legitimate features used against other users. "Wildcard" covers anything the other classes would miss. Default mode now runs eight hunt agents instead of six.
- The access control, injection, and business logic classes ask more specific questions, such as whether a cheaper code path skips the check and whether a request body can override the caller's identity.
- The profile agent picks up to four of nine security domains, such as AI agents, supply chain and CI, or client-side code. Every hunt prompt gets the attack classes of those domains. Affirmer and challenger prompts get each domain's rules for what counts as a finding. With two domains, a hunt prompt grows by about 2k tokens.
- `THIRD_PARTY_NOTICES.md`. The severity scale, the domain guidance, and part of the class descriptions come from Cloudflare's security-audit-skill (MIT), condensed for a review that does not run code.

### Changed

- The extension regenerates a cached `profile.json` that has no `domains` field, once per project.

### Security

- The audit agents' `shell` tool now checks paths attached to git short options, such as `git diff -O/abs/file`, `git blame -S/abs/file`, and `git ls-files -X/abs/file`. Before, these paths skipped the check. An agent could read git's error message and learn whether a file outside the project exists.

## [0.1.2] - 2026-10-17

### Changed

- Replace the README slogan with a description of how the review works.
- Simplify the package description, workflow explanation, and usage instructions.

## [0.1.1] - 2026-10-15

### Added

- English visual cover and workflow infographic for GitHub, npm, and the pi package gallery.
- Package documentation images included in the npm tarball.

### Changed

- Gallery preview and package description highlight adversarial verification.
- README image URLs work on both GitHub and npm.

## [0.1.0] - 2026-10-13

### Added

- `/security-review` command for unmerged changes or a full-project review.
- Multi-agent profiling, vulnerability hunting, root-cause triage, and adversarial affirmer/challenger verification.
- Read-only inspection tools confined to the audited project.
- Persistent findings with deduplication, review statuses, and full-run stale tracking.
- Markdown reports, per-run logs, and in-session summaries.
- Per-role model settings, exclusions, concurrency and hypothesis limits, and agent timeouts.

[0.1.0]: https://github.com/insaidermobile-ux/pi-security-review/releases/tag/v0.1.0

[0.1.1]: https://github.com/insaidermobile-ux/pi-security-review/compare/v0.1.0...v0.1.1

[0.2.0]: https://github.com/insaidermobile-ux/pi-security-review/releases/tag/v0.2.0
