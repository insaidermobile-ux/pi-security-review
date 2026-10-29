import assert from "node:assert/strict";
import { symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import { createReadOnlyTools, isInsideProject } from "../extensions/security-review/read-tools.ts";
import { runTool } from "./faux.ts";
import { makeRepo } from "./git-fixtures.ts";
import { tempDir } from "./temp.ts";

describe("confined read tools", () => {
	function fixture() {
		const repo = makeRepo({ "src/a.ts": "const inside = 1;\n" });
		const outsideDir = tempDir("sr-outside-");
		const outside = join(outsideDir, "secret.txt");
		writeFileSync(outside, "SECRET\n");
		symlinkSync(outside, join(repo, "src/link.txt"));
		symlinkSync(outsideDir, join(repo, "linked-dir"));
		const tools = new Map(createReadOnlyTools(repo).map((tool) => [tool.name, tool]));
		const run = async (name: string, params: Record<string, unknown>): Promise<string> => {
			try {
				const result = await runTool(tools.get(name)!, params as never);
				const content = result.content[0];
				return content?.type === "text" ? content.text : "";
			} catch (error) {
				return `ERROR: ${(error as Error).message}`;
			}
		};
		return { repo, outside, outsideDir, tools, run };
	}

	test("replace pi's read, grep, find, and ls", () => {
		assert.deepEqual([...fixture().tools.keys()], ["read", "grep", "find", "ls"]);
	});

	test("read files and list directories inside the project", async () => {
		const { run } = fixture();
		assert.match(await run("read", { path: "src/a.ts" }), /const inside = 1/);
		assert.match(await run("ls", { path: "src" }), /a\.ts/);
		assert.match(await run("ls", {}), /src\//);
	});

	test("refuse absolute, home, parent, and symlinked paths outside the project", async () => {
		const { run, outside, outsideDir } = fixture();
		const refused = /^ERROR: Path .* is outside the project/;
		for (const path of [outside, `@${outside}`, "~/.ssh/id_rsa", "../secret.txt", "src/link.txt", "linked-dir/secret.txt"]) {
			assert.match(await run("read", { path }), refused, `read ${path}`);
		}
		for (const name of ["grep", "find", "ls"]) {
			for (const path of [outsideDir, `@${outsideDir}`, "~", "..", "linked-dir", `file://${outsideDir}`]) {
				assert.match(await run(name, { path, pattern: "SECRET" }), refused, `${name} ${path}`);
			}
		}
	});

	test("isInsideProject accepts paths that do not exist yet", () => {
		const { repo } = fixture();
		assert.equal(isInsideProject(repo, "src/missing.ts"), true);
		assert.equal(isInsideProject(repo, "."), true);
		assert.equal(isInsideProject("/no/such/root", "src/a.ts"), true);
		assert.equal(isInsideProject("/no/such/root", "/etc/passwd"), false);
		// A missing file behind a link out of the project is refused like an existing one.
		const { repo: linked, outsideDir } = fixture();
		symlinkSync(join(outsideDir, "missing.txt"), join(linked, "dangling.txt"));
		for (const path of ["linked-dir/missing.txt", "linked-dir/no/such/dir", "dangling.txt"]) assert.equal(isInsideProject(linked, path), false, path);
	});
});
