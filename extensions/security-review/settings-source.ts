import { getAgentDir, SettingsManager } from "@earendil-works/pi-coding-agent";

/**
 * Read the raw global and project settings layers, lowest precedence first.
 * Project settings are only read when the project is trusted, matching pi's own behavior.
 */
export function readSettingsLayers(cwd: string, projectTrusted: boolean): unknown[] {
	const manager = SettingsManager.create(cwd, getAgentDir(), { projectTrusted });
	return projectTrusted ? [manager.getGlobalSettings(), manager.getProjectSettings()] : [manager.getGlobalSettings()];
}
