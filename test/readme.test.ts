import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { DEFAULT_SETTINGS, ROLES, resolveSettings } from "../extensions/security-review/settings.ts";

const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");

test("every documented setting is read by the settings loader", () => {
	const example = readme.match(/```json\n(\{\n\s+"securityReview"[\s\S]*?)\n```/);
	assert.ok(example, "README has a settings example");
	const { settings, errors } = resolveSettings(JSON.parse(example[1]!));
	assert.deepEqual(errors, []);
	const documented = [...readme.matchAll(/^\| `(\w+)` \|/gm)].map((m) => m[1]);
	assert.deepEqual(documented.sort(), Object.keys(DEFAULT_SETTINGS).sort());
	assert.equal(settings.models.challenger, "anthropic/claude-opus-5-5");
	const rolesDoc = readme.match(/Roles: (.*?)\./)?.[1] ?? "";
	assert.deepEqual([...rolesDoc.matchAll(/`(\w+)`/g)].map((m) => m[1]), [...ROLES]);
	for (const [key, value] of Object.entries(DEFAULT_SETTINGS)) {
		if (typeof value === "number") assert.match(readme, new RegExp(`\\| \`${key}\` \\| \`${value}\` \\|`), `${key} default documented`);
	}
});
