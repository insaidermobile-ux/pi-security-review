<!-- Adapted from DESKTOP-MOBILE-AND-LOCAL-IPC.md in Cloudflare's security-audit-skill (MIT). See THIRD_PARTY_NOTICES.md. -->
# Desktop, mobile, and local IPC

## Hunt

- Name the realistic attacker: another app, another OS user, a restricted child process, an untrusted document, or a remote origin. Self-harm within the same account and authority is not a boundary violation.
- Paths, process names, bundle or package ids, and claimed sender fields are not peer authentication. Look for OS peer credentials, code-signing identity, capability handles, or protected channel state.
- The native bridge or helper must authorize each operation and its final resource after parsing. A trusted UI or broker does not make attacker-influenced arguments trusted.

Attack classes:

- **Deep-link ambiguity**: another app or a web page can invoke a route that changes state, imports data, completes sign-in, or selects an account without a current-session, one-time binding. Check URI normalization, duplicate parameters, and scheme, host, and path matching.
- **App and account handoff**: OAuth, SSO, magic-link, invite, pairing, or payment callbacks returning to the wrong app, profile, tenant, or pending transaction.
- **File-open and intent authority**: associated files, share intents, drag and drop, clipboard records, or notification actions trigger privileged operations without checking content type, sender, user intent, and final target.
- **Webview origin to bridge**: remote or attacker-controlled frames can reach a JavaScript-to-native bridge meant for packaged content; origin checked only on initial load or by URL prefix, not after navigation, redirects, subframes, or popups.
- **Over-broad bridge capabilities**: a generic bridge lets web content choose arbitrary files, commands, IPC methods, or credentials. In Electron, look at `nodeIntegration`, `contextIsolation`, `sandbox`, exposed preload APIs, and `shell.openExternal` with untrusted URLs.
- **Webview file and universal access**: settings or custom protocol handlers that let remote content read app-local files or internal origins.
- **IPC peer authentication**: Unix sockets, named pipes, XPC, Binder, D-Bus, native messaging, or loopback HTTP servers that accept any local peer without checking OS credentials or code identity, with a meaningful method behind them.
- **Claimed principal versus channel identity**: the channel belongs to one app or user, but request fields select another user, profile, or capability.
- **Exported components**: Android activities, services, receivers, or providers, or local automation endpoints, invokable by other apps and performing operations meant for the app itself.
- **IPC lifecycle**: predictable request ids, world-writable socket paths, inherited descriptors, or stale channels after restart.
- **Privileged helper as confused deputy**: a low-privilege caller selects a privileged command, file, service, or setting without per-operation authorization.
- **Installer and update paths**: a privileged installer reads scripts, packages, or symlinks writable by a lower-trust user after authorization.
- **Local file TOCTOU**: check-then-use on paths that can be replaced by symlinks or renames during a privileged read or write.
- **Local secret exposure**: tokens in keychain items, files, backups, logs, clipboard, or notification previews readable by another app, profile, or user with less authority.
- **Account switch and logout leakage**: caches, background tasks, widgets, local databases, or webview storage that survive logout and appear under the next account.

Moves:

- List every process, app component, local endpoint, URI scheme, file association, webview origin, and helper with its OS identity, privilege, possible callers, and callable operations.
- Read the final packaging inputs: merged manifests, entitlements, installer rules, native-messaging registrations, and protocol handlers.

## Verify

- Name the attacker's starting capability, the OS or app principal crossed, the entry channel, the accepted argument or state, and the unauthorized operation or disclosure.
- Check the OS isolation, peer credential, signing, entitlement, permission, consent, and installer controls that apply. For webview bridges, cite both the origin control and the native sink; for IPC, cite peer authentication and per-resource authorization; for helpers, check the final normalized destination.
- Plaintext secrets readable only by the same intended OS account are not automatically a vulnerability: name the lower-trust reader. A missing restrictive webview setting without reachable protected content is a hardening note.
- Manifest merging, code signing, OS version, device policy, and installer ACLs may not be visible in the repository: when one decides the outcome, state which fact it is.
