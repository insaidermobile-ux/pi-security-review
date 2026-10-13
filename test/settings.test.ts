import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import { DEFAULT_SETTINGS, ROLES, resolveRoleModels, resolveSettings } from "../extensions/security-review/settings.ts";
import { tempDir } from "./temp.ts";

describe("resolveSettings", () => {
	test("uses defaults when nothing is configured", () => {
		const { settings, errors } = resolveSettings({}, {});
		assert.deepEqual(errors, []);
		assert.deepEqual(settings, DEFAULT_SETTINGS);
		assert.equal(settings.maxConcurrentAgents, 4);
		assert.equal(settings.maxHypotheses, 24);
		assert.equal(settings.agentTimeoutSeconds, 600);
	});

	test("project layer takes precedence over global layer", () => {
		const global = { securityReview: { maxHypotheses: 10, exclude: ["vendor/**"], models: { hunt: "a/cheap", challenger: "a/strong" } } };
		const project = { securityReview: { maxHypotheses: 5, models: { challenger: "b/stronger" } } };
		const { settings, errors } = resolveSettings(global, project);
		assert.deepEqual(errors, []);
		assert.equal(settings.maxHypotheses, 5);
		assert.deepEqual(settings.exclude, ["vendor/**"]);
		assert.deepEqual(settings.models, { hunt: "a/cheap", challenger: "b/stronger" });
	});

	test("reports a non-numeric cap with the setting name and expected type", () => {
		const { settings, errors } = resolveSettings({ securityReview: { maxHypotheses: "lots" } });
		assert.equal(errors.length, 1);
		assert.match(errors[0]!, /securityReview\.maxHypotheses: expected a positive integer, got "lots"/);
		assert.equal(settings.maxHypotheses, DEFAULT_SETTINGS.maxHypotheses);
	});

	test("reports unknown keys, unknown roles, and malformed values", () => {
		const { errors } = resolveSettings({
			securityReview: { maxHypothesis: 3, exclude: "vendor", models: { judge: "a/b", hunt: "no-slash" }, agentTimeoutSeconds: 0 },
		});
		assert.ok(errors.some((e) => e.includes("securityReview.maxHypothesis: unknown setting")));
		assert.ok(errors.some((e) => e.includes("securityReview.exclude: expected an array")));
		assert.ok(errors.some((e) => e.includes("securityReview.models.judge: unknown role")));
		assert.ok(errors.some((e) => e.includes('securityReview.models.hunt: expected "provider/model"')));
		assert.ok(errors.some((e) => e.includes("securityReview.agentTimeoutSeconds: expected a positive integer")));
	});

	test("ignores layers without the section", () => {
		const { errors } = resolveSettings(undefined, { defaultModel: "x" });
		assert.deepEqual(errors, []);
	});
});

describe("resolveRoleModels", () => {
	const session = { provider: "anthropic", id: "session-model" };
	const known = [session, { provider: "openai", id: "strong" }];
	const find = (provider: string, id: string) => known.find((m) => m.provider === provider && m.id === id);

	test("uses the session model for every role without overrides", () => {
		const { models, errors } = resolveRoleModels(DEFAULT_SETTINGS, session, find);
		assert.deepEqual(errors, []);
		for (const role of ["profile", "hunt", "triage", "affirmer", "challenger", "report"] as const) assert.equal(models![role], session);
	});

	test("accepts a triage override as a known role", () => {
		const { settings, errors } = resolveSettings({ securityReview: { models: { triage: "openai/strong" } } });
		assert.deepEqual(errors, []);
		const { models } = resolveRoleModels(settings, session, find);
		assert.equal(models!.triage.id, "strong");
		assert.equal(models!.affirmer, session);
	});

	test("applies a per-role override only to that role", () => {
		const { models } = resolveRoleModels({ ...DEFAULT_SETTINGS, models: { challenger: "openai/strong" } }, session, find);
		assert.equal(models!.challenger.id, "strong");
		assert.equal(models!.hunt, session);
	});

	test("reports which role's override names an unknown model", () => {
		const { models, errors } = resolveRoleModels({ ...DEFAULT_SETTINGS, models: { affirmer: "nope/missing" } }, session, find);
		assert.equal(models, undefined);
		assert.deepEqual(errors, ['securityReview.models.affirmer: model "nope/missing" is not known to pi']);
	});

	test("reports a missing session model for roles without override", () => {
		const { errors } = resolveRoleModels({ ...DEFAULT_SETTINGS, models: { hunt: "openai/strong" } }, undefined, find);
		assert.equal(errors.length, ROLES.length - 1);
	});
});

describe("readSettingsLayers", () => {
	test("reads the project layer only when trusted", async () => {
		const { readSettingsLayers } = await import("../extensions/security-review/settings-source.ts");
		const project = tempDir("sr-settings-");
		mkdirSync(join(project, ".pi"));
		writeFileSync(join(project, ".pi", "settings.json"), JSON.stringify({ securityReview: { maxHypotheses: 7 } }));
		const trusted = resolveSettings(...readSettingsLayers(project, true));
		assert.equal(trusted.settings.maxHypotheses, 7);
		const untrusted = readSettingsLayers(project, false);
		assert.equal(untrusted.length, 1);
	});
});
