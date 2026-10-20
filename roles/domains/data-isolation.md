<!-- Adapted from DATA-ISOLATION-AND-LIFECYCLE.md in Cloudflare's security-audit-skill (MIT). See THIRD_PARTY_NOTICES.md. -->
# Data isolation and lifecycle

## Hunt

- A tenant or owner field on a record is not isolation. Find the query, key, path, policy, or row-level control that enforces it on each read and write path.
- Trace derived copies. Data protected in primary storage can leak through search, caches, analytics, exports, previews, logs, replicas, and backups with different access rules.
- Deletion and revocation are lifecycle contracts. Check current, historical, cached, indexed, exported, restored, and queued copies.

Attack classes:

- **Missing tenant or owner enforcement**: a read, update, delete, list, count, or bulk query identifies an object without binding it to the authenticated tenant or owner, or takes that identity from the request body. Compare direct, nested, background, admin, import, and legacy paths.
- **Key and namespace collision**: cache keys, object paths, unique constraints, search document ids, or temporary files that omit tenant or environment, so two principals can read or overwrite the same key.
- **Policy and query disagreement**: row-level policy, ORM default scopes, and raw or service clients apply different predicates; check joins, aggregates, views, `unscoped` clients, and paths where the request context is missing.
- **Blob and signed-reference overreach**: attachment ids, version ids, share links, or signed URLs that allow more than the issuer's access, or stay valid after the ACL changes.
- **Derived-copy ACL drift**: a record's ACL or lifecycle changes without invalidating its search, cache, embedding, thumbnail, feed, or preview copies; filtering only at ingestion, not at retrieval.
- **Alternate readers**: private content or credentials written to analytics, logs, traces, or diagnostics with broader access or tenant mixing.
- **Enumeration oracles**: counts, filters, sort order, error messages, unique-constraint errors, or timing reveal whether a protected object or account exists.
- **Export and backup scope**: an export, report, or backup includes other tenants, hidden fields, soft-deleted data, secrets, or history above the requester's access; the finished artifact downloadable by others.
- **Import and restore authority**: import or restore bypasses ownership, ACL, uniqueness, or validation, overwrites existing resources, or writes into a tenant the requester cannot write.
- **Migration defaults**: old records without tenant or ACL fields, colliding ids, or new and old readers applying different defaults during rollout.
- **Soft-delete bypass**: lookups, search, relations, links, jobs, or restore paths that ignore the deleted or revoked flag; identifiers re-registrable while references remain.
- **Stale authorization**: membership removal, role downgrade, or token revocation that does not invalidate sessions, caches, subscriptions, or jobs.
- **Retention overrun and restore of invalid state**: queued work, retries, or exports that recreate deleted data; restores that bring back permissions current policy no longer allows.

Moves:

- Pick one protected record and draw its write, query, cache, index, event, export, backup, deletion, and restore paths, marking the principal and tenant at every edge.
- Start at bypass clients, background jobs, migrations, global uniqueness, and cache keys, which often lack the request's identity.

## Verify

- Name the attacker or lower-trust principal, the protected data or state, the affected owner or tenant, the alternate copy or operation, and the unauthorized disclosure or mutation.
- Cite both the intended policy and the path that omits or contradicts it, and check that no other layer enforces the same tenant or lifecycle condition.
- Privacy or retention preferences are not vulnerabilities by themselves; there must be an explicit access boundary or deletion guarantee and an unauthorized reader or later operation. Enumeration needs a concrete confidential predicate, not general response variance.
- External cache, object storage, replica, analytics, and backup policies are often outside the repository: when one decides the outcome, state which fact it is.
