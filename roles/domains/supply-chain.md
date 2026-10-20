<!-- Adapted from SUPPLY-CHAIN-AND-RELEASE.md in Cloudflare's security-audit-skill (MIT). See THIRD_PARTY_NOTICES.md. -->
# Supply chain and CI

## Hunt

- A mutable or known-vulnerable dependency is not a finding by itself. Show who can influence resolution, which build consumes it, and what execution or release boundary follows.
- Follow integrity across every handoff: source, resolved inputs, build worker, artifact, test result, signature, promotion, and the consumer that installs or updates.
- CI configuration is authorization code. For each workflow, establish the triggering event, whose code runs, which secrets and tokens exist, and what the job may publish or change.
- A checksum fetched from the same untrusted place as the artifact does not establish integrity.

Attack classes:

- **Dependency source confusion**: resolver configuration can pick an unintended public or private namespace, fallback registry, mirror, or source URL. Check lockfile and checksum use, alternate build files, and first install versus update.
- **Mutable build inputs**: builds consume branches, tags, unpinned submodules, downloaded tools, remote includes, floating CI actions (`uses: owner/action@main`), or container tags whose content can change without review, where a less trusted party controls the content.
- **Generated content without review**: schemas, vendored archives, generated clients, or binary blobs become shipped code without the same review gate as source.
- **Build-context inclusion**: secrets, local configuration, or developer artifacts end up in a package or image because the build context or `files` list exceeds the intended release inputs.
- **Untrusted code in a privileged workflow**: a pull request, fork, issue comment, or dependency update runs contributor code with secrets, write tokens, or deploy rights (`pull_request_target` or `workflow_run` with a checkout of the contributor's ref).
- **Workflow expression injection**: branch names, commit messages, issue titles, artifact names, or matrix values interpolated into shell commands or `${{ }}` expressions.
- **Cache and artifact trust mixing**: a lower-trust job populates a cache, artifact, or workspace that a higher-trust job restores and executes or releases.
- **Automation identity overreach**: CI tokens with more permissions than the job needs, where untrusted job input can select the affected resource.
- **Build-to-release substitution**: tests, signatures, and publication refer to mutable tags, filenames, or channels instead of one immutable digest.
- **Release and signing policy gaps**: a release or signature accepted from the wrong workflow, repository, branch, or key role; the consumer checks that a signature is valid but not whose it is.
- **Update metadata and rollback**: an updater authenticates the payload but not version, platform, channel, target path, or rollback state.
- **Plugin and extension trust**: an extension gains host authority beyond its declared scope, or install hooks run before authenticity and capability checks. Installing arbitrary plugins as the same user on purpose is not a boundary.

Moves:

- Walk back from a released artifact or installed update to every source, generated input, credential, worker, cache, and authorization decision.
- Compare untrusted and protected workflow events side by side, and mark every cache, artifact, or output that crosses between them.
- Read the failure paths: revoked key, failed download, missing signature, partial release.

## Verify

- Name the lower-trust actor, the source, cache, artifact, or metadata they control, the trusted job or updater that consumes it, and the result: unauthorized publication, code inclusion, secret disclosure, or privileged execution.
- Show artifact identity across the broken handoff: a different mutable name or unbound digest must reach a real consumer.
- An outdated or vulnerable dependency without a reachable vulnerable call, and missing least privilege without a reachable privileged action, are hardening notes.
- Check package-manager, repository-host, registry, and signing defaults for the pinned versions before asserting a gap. Branch protection, runner configuration, environment approvals, and registry settings are usually outside the repository: when one decides the outcome, state which fact it is.
