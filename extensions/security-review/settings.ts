/**
 * Extension settings, read from the `securityReview` key of pi's global (`~/.pi/agent/settings.json`)
 * and project (`.pi/settings.json`) settings files. Project values take precedence.
 */

export const SETTINGS_KEY = "securityReview";

export const ROLES = ["profile", "hunt", "triage", "affirmer", "challenger", "report"] as const;
export type Role = (typeof ROLES)[number];

export interface SecurityReviewSettings {
	/** Per-role model override as `provider/model`. Roles without an entry use the session model. */
	models: Partial<Record<Role, string>>;
	/** Glob patterns removed from the audited file set in both modes. */
	exclude: string[];
	maxConcurrentAgents: number;
	maxHypotheses: number;
	agentTimeoutSeconds: number;
}

export const DEFAULT_SETTINGS: SecurityReviewSettings = {
	models: {},
	exclude: [],
	maxConcurrentAgents: 4,
	maxHypotheses: 24,
	agentTimeoutSeconds: 600,
};

export interface SettingsResult {
	settings: SecurityReviewSettings;
	errors: string[];
}

type Layer = Record<string, unknown>;

function isObject(value: unknown): value is Layer {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function section(rawSettings: unknown): Layer | undefined {
	if (!isObject(rawSettings)) return undefined;
	return rawSettings[SETTINGS_KEY] as Layer | undefined;
}

function describe(value: unknown): string {
	return typeof value === "string" ? JSON.stringify(value) : `${JSON.stringify(value)} (${Array.isArray(value) ? "array" : typeof value})`;
}

/** Merge the `securityReview` sections of the given layers, later layers taking precedence. */
function mergeLayers(layers: unknown[], errors: string[]): Layer {
	const merged: Layer = {};
	for (const layer of layers) {
		const value = section(layer);
		if (value === undefined) continue;
		if (!isObject(value)) {
			errors.push(`${SETTINGS_KEY}: expected an object, got ${describe(value)}`);
			continue;
		}
		for (const [key, entry] of Object.entries(value)) {
			if (key === "models" && isObject(entry) && isObject(merged.models)) {
				merged.models = { ...merged.models, ...entry };
			} else {
				merged[key] = entry;
			}
		}
	}
	return merged;
}

function positiveInteger(merged: Layer, key: keyof SecurityReviewSettings, errors: string[]): number {
	const value = merged[key];
	const fallback = DEFAULT_SETTINGS[key] as number;
	if (value === undefined) return fallback;
	if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
		errors.push(`${SETTINGS_KEY}.${key}: expected a positive integer, got ${describe(value)}`);
		return fallback;
	}
	return value;
}

/**
 * Resolve effective settings from settings layers ordered from lowest to highest precedence
 * (global first, then project). Invalid values are reported in `errors` and replaced by defaults.
 */
export function resolveSettings(...layers: unknown[]): SettingsResult {
	const errors: string[] = [];
	const merged = mergeLayers(layers, errors);
	const known = new Set<string>(Object.keys(DEFAULT_SETTINGS));
	for (const key of Object.keys(merged)) {
		if (!known.has(key)) errors.push(`${SETTINGS_KEY}.${key}: unknown setting`);
	}

	const models: Partial<Record<Role, string>> = {};
	if (merged.models !== undefined) {
		if (!isObject(merged.models)) {
			errors.push(`${SETTINGS_KEY}.models: expected an object mapping role to "provider/model", got ${describe(merged.models)}`);
		} else {
			for (const [role, value] of Object.entries(merged.models)) {
				if (!(ROLES as readonly string[]).includes(role)) {
					errors.push(`${SETTINGS_KEY}.models.${role}: unknown role, expected one of ${ROLES.join(", ")}`);
				} else if (typeof value !== "string" || !/^[^/\s]+\/\S+$/.test(value)) {
					errors.push(`${SETTINGS_KEY}.models.${role}: expected "provider/model", got ${describe(value)}`);
				} else {
					models[role as Role] = value;
				}
			}
		}
	}

	let exclude: string[] = [];
	if (merged.exclude !== undefined) {
		if (!Array.isArray(merged.exclude) || merged.exclude.some((p) => typeof p !== "string" || p.length === 0)) {
			errors.push(`${SETTINGS_KEY}.exclude: expected an array of non-empty glob strings, got ${describe(merged.exclude)}`);
		} else {
			exclude = merged.exclude as string[];
		}
	}

	return {
		settings: {
			models,
			exclude,
			maxConcurrentAgents: positiveInteger(merged, "maxConcurrentAgents", errors),
			maxHypotheses: positiveInteger(merged, "maxHypotheses", errors),
			agentTimeoutSeconds: positiveInteger(merged, "agentTimeoutSeconds", errors),
		},
		errors,
	};
}

export interface ModelLike {
	provider: string;
	id: string;
}

export interface RoleModelsResult<M extends ModelLike> {
	models: Record<Role, M> | undefined;
	errors: string[];
}

/**
 * Resolve the model for every role: the configured override when present, else the session model.
 * Unresolvable overrides and a missing session model are reported as errors.
 */
export function resolveRoleModels<M extends ModelLike>(
	settings: SecurityReviewSettings,
	sessionModel: M | undefined,
	find: (provider: string, modelId: string) => M | undefined,
): RoleModelsResult<M> {
	const errors: string[] = [];
	const resolved: Partial<Record<Role, M>> = {};
	for (const role of ROLES) {
		const override = settings.models[role];
		if (override) {
			const slash = override.indexOf("/");
			const model = find(override.slice(0, slash), override.slice(slash + 1));
			if (model) resolved[role] = model;
			else errors.push(`${SETTINGS_KEY}.models.${role}: model "${override}" is not known to pi`);
		} else if (sessionModel) {
			resolved[role] = sessionModel;
		} else {
			errors.push(`no model is selected in this session and ${SETTINGS_KEY}.models.${role} is not set`);
		}
	}
	return { models: errors.length === 0 ? (resolved as Record<Role, M>) : undefined, errors };
}
