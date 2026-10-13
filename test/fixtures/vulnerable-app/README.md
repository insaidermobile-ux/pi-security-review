# vulnerable-app fixture

Deliberately vulnerable code used by the dry runs and integration checks. Not a real application.

- `base/` is committed on `main`.
- `feature/` is overlaid on a `feature` branch and adds a seeded SQL injection in `src/users.js` (`searchUsers`).
- `src/files.js` contains a path traversal *candidate* that is blocked by a resolve-and-prefix check; a correct challenger refutes it.
- `src/admin.js` lets administrators change server settings; reporting it as a vulnerability fails the attribution test.
