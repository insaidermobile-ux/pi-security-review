<!-- Adapted from CLIENT-SIDE.md in Cloudflare's security-audit-skill (MIT). See THIRD_PARTY_NOTICES.md. -->
# Client-side and browser

## Hunt

- A client-side candidate needs a controllable source and an executing or disclosing sink. Browser-only sources include URL fragments, `window.name`, `postMessage` data, storage, and cached content the server never sees.
- The impact must reach a victim's session, another origin, or shared persistence. Self-injection and disclosure of the attacker's own data are not findings.
- Framework escaping, same-origin policy, CSP, COOP/CORP, service-worker scope, and default `noopener` are real controls; check them before assigning impact.
- Browser storage and caches are shared per origin and may outlive login. Identify who writes, who reads, and what clears each record.

Attack classes:

- **DOM-based XSS**: `location`, `document.referrer`, `window.name`, message data, or storage reaching `innerHTML`, `outerHTML`, `document.write`, string-evaluating APIs, executable URLs, jQuery HTML APIs, or framework escape hatches such as `dangerouslySetInnerHTML` and `v-html`.
- **DOM clobbering**: injected `id` or `name` attributes shadow a global or configuration value that code later trusts.
- **Prototype pollution with a gadget**: an attacker-controlled key reaches a deep merge or path assignment, and a reachable gadget reads the polluted property to change authorization, execution, navigation, or rendering.
- **`postMessage` trust**: a handler acts on `event.data` without an exact origin allowlist (substring, prefix, or unanchored regex checks do not count); sensitive data sent with target `*`.
- **Cross-site WebSocket use**: an upgrade accepts ambient cookies from any origin without an `Origin` check or channel token.
- **Credentialed CORS**: the server reflects or loosely matches `Origin` with credentials allowed and returns sensitive data.
- **Service-worker takeover and cache confusion**: attacker-influenced content can become the worker script or widen its scope; personalized responses cached without account or auth state and served after logout or account switch.
- **Storage disclosure and stale authorization**: tokens, private responses, or authorization decisions in `localStorage`, IndexedDB, Cache Storage, or extension storage readable by another account or a less trusted same-origin component, or still used after logout.
- **Cross-tab confusion**: `storage` events, `BroadcastChannel`, or shared workers carry identity or commands between tabs without binding them to the current session.
- **Cross-site leaks**: an attacker page distinguishes protected state (whether a private object or account exists) through load errors, frame counts, redirects, timing, or cache state.
- **Clickjacking**: a state-changing action can be framed without `frame-ancestors` or `X-Frame-Options`.
- **Navigation confusion**: a client source controls a redirect or navigation without scheme and destination checks, including `javascript:` and `data:` URLs; `window.opener` kept on purpose.
- **Browser extensions**: content scripts or pages accepting messages from web pages, and broad host permissions reachable from page-controlled data.

Moves:

- Start from DOM, navigation, worker, message, and storage sinks, trace back to browser-only and server-controlled sources, and record which browser policy should stop the path.
- Walk account switch, logout, worker update, offline fallback, and stale-tab paths.

## Verify

- Cite the source, the sink, the browser policy involved, the affected origin or session, and the observable mutation or disclosure. Self-injection and access to the attacker's own data are not findings.
- For prototype pollution, show both the recursive write and a security-relevant gadget. For DOM clobbering, show that the markup survives sanitization and that the shadowed value is used.
- For service workers and storage, show that an attacker-controlled write or cache entry reaches a different account, tenant, or later authorization state.
- For messaging, CORS, WebSocket, and cross-site leak claims, show the exact origin check and the protected state or action exposed, and check whether CSP, COOP/CORP, cookie, or SameSite policy already blocks it. A bare wildcard with credentials is rejected by browsers and is not a finding.
- Missing framing or security headers on read-only content are hardening notes. When the outcome depends on a deployed header, extension permission, or browser version not visible in the repository, state which fact decides it.
