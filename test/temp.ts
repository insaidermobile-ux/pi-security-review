import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const created: string[] = [];

process.on("exit", () => {
	for (const dir of created) rmSync(dir, { recursive: true, force: true });
});

/** A temporary directory removed when the test process exits. */
export function tempDir(prefix: string): string {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	created.push(dir);
	return dir;
}
