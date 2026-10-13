import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const created: string[] = [];

process.on("exit", () => {
	if (process.env.SR_KEEP_TEMP) return;
	for (const dir of created) rmSync(dir, { recursive: true, force: true });
});

/** A temporary directory removed when the process exits, unless SR_KEEP_TEMP is set (for manual runs). */
export function tempDir(prefix: string): string {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	created.push(dir);
	return dir;
}
