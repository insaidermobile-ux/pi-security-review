# Security review report

- Run: `20261012T100000-abcd` (2026-10-12T10:00:00.000Z to 2026-10-12T10:05:00.000Z)
- Scope: changes against `origin/main` (merge-base `fedcba987654`), 4 files
- Result: 1 vulnerability, 1 risk, 1 refuted, 1 unverified
- By severity: 0 critical, 1 high, 1 medium, 0 low
- **Incomplete run:** hunt agent failed (hunt:network-ssrf: timed out after 600s)

## Summary

One high-severity SQL injection needs fixing before merge.

## Findings

### High

#### SR-001: User search endpoint (src/users.ts): sql injection leading to reading any user's records

**Vulnerability** · severity high · confidence high · status open · CWE-89 · CVSS 8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) · introduced in `0123456789ab`

**Location:** `src/users.ts:12` (searchUsers)

**Background.** The API exposes a user search endpoint.

**Detail.** User input is concatenated into SQL.

**Attack scenario.** GET /users?name=' OR 1=1 -- returns every row.

**Data flow**

1. `src/server.ts:5`: GET /users reads req.query.name
2. `src/users.ts:12`: name is concatenated into the SQL string passed to db.query

<details><summary>Verification</summary>

**Affirmer**

- Missing defenses: parameterized query (not found)
- Preconditions: network access to the API

**Challenger**

- Attribution: attacker is trusted role: no; harmful step outside component: no. Anonymous caller, query runs in the audited code.
- Defenses examined: input validation at not found (none)
- Threat model: Unauthenticated data access has independent value.
- Reasoning: No defense blocks the path.

**Verdict:** confirmed (confidence high)

</details>

**Remediation.** Use a parameterized query.

```diff
- db.query(`... ${name}`)
+ db.query('... $1', [name])
```

### Medium

#### SR-002: Admin settings (src/admin.ts): ssrf leading to requests to internal hosts

**Risk** · severity medium · confidence medium · status open · introduced in uncommitted changes

**Location:** `src/admin.ts:4`

**Background.** The API exposes a user search endpoint.

**Detail.** User input is concatenated into SQL.

**Attack scenario.** GET /users?name=' OR 1=1 -- returns every row.

**Data flow**

1. `src/server.ts:5`: GET /users reads req.query.name
2. `src/users.ts:12`: name is concatenated into the SQL string passed to db.query

<details><summary>Verification</summary>

**Affirmer**

- Missing defenses: parameterized query (not found)
- Preconditions: network access to the API

**Challenger**

- Attribution: attacker is trusted role: no; harmful step outside component: no. Anonymous caller, query runs in the audited code.
- Defenses examined: input validation at not found (none)
- Threat model: Unauthenticated data access has independent value.
- Reasoning: No defense blocks the path.

**Verdict:** downgraded (confidence high)

</details>

**Remediation.** Restrict webhook hosts.

## Refuted hypotheses

### H-003: path-traversal at `src/files.ts:9` (download)

**Claim.** The name query parameter is concatenated into SQL

**Why it was refuted** (confidence high): A defense blocks the path.

- resolve and prefix check at `src/files.ts:9` (blocks)

## Unverified hypotheses

These were raised but not verified in this run (cap reached or an agent failed).

- H-004 [low] sql-injection at `src/users.ts:12` (searchUsers): The name query parameter is concatenated into SQL
