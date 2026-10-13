# Contributing

Small, focused bug fixes and improvements are welcome. Open an issue to discuss larger changes first. For vulnerabilities in the extension, follow [SECURITY.md](SECURITY.md) instead of filing a public issue.

## Development

Use Node.js 22.18 or later. From a local checkout:

```bash
npm install
npm run check
```

`npm run check` runs typechecking and tests. Tests use pi's faux provider and make no real model calls. Role prompts live in `roles/`; see the [README development section](README.md#development) for load checks and optional real-model checks.

Keep the README settings example and settings table in sync with the settings loader. `test/readme.test.ts` enforces documented keys, defaults, and roles.

Before opening a pull request, run `npm run check`, add or update tests for behavior changes, and update relevant documentation. Keep reports and logs free of credentials and private project content.
