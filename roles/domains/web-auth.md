<!-- Adapted from WEB-PROTOCOL-AND-AUTH.md in Cloudflare's security-audit-skill (MIT). See THIRD_PARTY_NOTICES.md. -->
# Web protocols and authentication

## Hunt

- Access-control review asks whether a principal may perform an operation. This domain asks whether the HTTP or identity layer can confuse which principal, request, assurance level, or token the operation belongs to.
- For every credential, find the signature or secret verification and every binding its role needs: issuer, audience, origin, client, session, principal, resource, assurance, expiry, and one-time use.
- `Host`, `Forwarded`, `X-Forwarded-*`, `Origin`, `Referer`, redirect targets, callback state, and URLs built from the request are trust decisions. Trace each to the identity or response it affects.
- A missing header, cookie attribute, MFA prompt, or rate limit is not a finding alone.

Attack classes:

- **Request framing and cache disagreement**: a front end and back end disagree on length or header normalization; a request value changes cached content but is missing from the cache key; a private dynamic path is cached as a static asset.
- **Host and forwarded-header trust**: client-supplied host or proxy headers decide absolute URLs, tenant routing, reset links, cache keys, or the client address used for authorization.
- **Response-header injection**: untrusted data reaches `Location`, `Set-Cookie`, or another header with CR/LF or unsafe normalization.
- **CSRF**: a cookie-authenticated state change accepts a cross-site request without an anti-CSRF token, same-site binding, or strict `Origin` check. Include JSON, multipart, method-override, legacy, and login routes.
- **Session fixation and invalidation**: session ids not rotated on login, account switch, MFA completion, or impersonation, or still valid after logout, password change, or account disable.
- **Cookie scope**: an over-broad `Domain` or `Path`, or sibling cookies that components select differently, where a less trusted origin can gain or replace the credential.
- **JWT verification**: signature skipped or algorithm and key chosen by the token (`alg`, `kid`, `jku`, `x5u`), decode-without-verify paths, missing `exp`, `nbf`, `aud`, or `iss` checks. A valid token for another service is invalid here.
- **OAuth/OIDC binding**: exact `redirect_uri` matching where this code is the authorization server, session-bound `state`, PKCE, ID-token issuer, audience, signature, and nonce, and which IdP a callback belongs to in multi-provider flows.
- **SAML**: the element whose signature is checked is not the element used as identity; unsigned fallbacks; parser configuration; audience, recipient, validity, and replay checks.
- **MFA and step-up**: a first factor alone can enroll, replace, or disable the second factor; a challenge upgrades the wrong session, account, or action; an alternate route skips the assurance check.
- **WebAuthn and passkeys**: challenge, RP ID, origin, credential, and user handle not bound to the initiating session; account-linking confusion.
- **Account linking and recovery**: linking an identity without verified ownership and a current session; reset tokens that are predictable, reusable, unbound to user and action, or that leave old sessions alive; email or phone change as a weaker path.
- **API keys**: a key works on broader tenants, resources, or environments than its record grants, or request parameters override the binding; secret keys reachable from client bundles, URLs, logs, or responses.
- **mTLS and identity headers**: client-certificate identity headers trusted from any peer, or subject text mapped to an account loosely; fail-open fallback when certificates are missing or expired.

Moves:

- Walk issue → store → transmit → consume → refresh → revoke for every credential, and compare normal, error, retry, legacy, and account-switch paths.
- List every route to the same identity and the same sensitive operation; the effective policy is the weakest one.

## Verify

- Framing and cache findings need two components that interpret the same request, response, or key differently. Name both and the value each one sees.
- For token, MFA, passkey, account-link, recovery, API-key, and mTLS findings, cite the verification line and the missing binding (principal, session, resource, origin, audience, action, or assurance), and show that the server accepts the invalid credential or transition.
- For CSRF, name the ambient credential, the state-changing route, the accepted cross-site request shape, and the missing check. Read-only actions and routes that require a non-ambient bearer token do not qualify.
- A missing header, cookie flag, MFA prompt, or rate limit is a hardening note unless it leads to an accepted invalid request, cross-principal impact, an assurance downgrade, or credential disclosure. Responses that only reveal whether a public account exists are not findings by themselves.
- Check framework and library defaults before asserting a missing check. Proxy chains, edge cache keys, IdP policy, certificate trust, and deployed auth modes may live outside the repository: when one decides the outcome, state which fact it is instead of assuming it.
