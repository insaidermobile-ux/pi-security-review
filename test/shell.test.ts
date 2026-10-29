import assert from "node:assert/strict";
import { existsSync, readdirSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import { git } from "../extensions/security-review/scope.ts";
import { checkCommand, createShellTool, ShellRejection } from "../extensions/security-review/shell.ts";
import { runTool } from "./faux.ts";
import { makeRepo, sh } from "./git-fixtures.ts";
import { tempDir } from "./temp.ts";

describe("read-only shell", () => {
	const root = "/project";

	test("allows inspection commands", () => {
		assert.deepEqual(checkCommand("rg -n 'select .* from' src", root), ["rg", "-n", "select .* from", "src"]);
		assert.deepEqual(checkCommand("cat src/a.ts", root), ["cat", "src/a.ts"]);
		assert.deepEqual(checkCommand("git log -n 3 -- src/a.ts", root), [
			"git", "-c", "core.pager=cat", "--no-pager", "log", "--no-ext-diff", "--no-textconv", "-n", "3", "--", "src/a.ts",
		]);
		assert.deepEqual(checkCommand("git blame -L 10,20 src/a.ts", root).slice(4), ["blame", "--no-textconv", "-L", "10,20", "src/a.ts"]);
		assert.deepEqual(checkCommand("ls -laR src", root), ["ls", "-laR", "src"]);
		assert.deepEqual(checkCommand("wc -l src/a.ts", root), ["wc", "-l", "src/a.ts"]);
		assert.ok(checkCommand("git diff HEAD~3..HEAD", root).includes("diff"));
	});

	test("allows options that only resemble denied ones", () => {
		// The pickaxe value and the pattern contain "O", which is a pager option only as a `git grep` flag.
		assert.ok(checkCommand("git log -SOAuth", root).includes("-SOAuth"));
		assert.ok(checkCommand("git grep -eOAuth src", root).includes("-eOAuth"));
		assert.ok(checkCommand("git diff --text HEAD~1", root).includes("--text"));
		assert.ok(checkCommand("git diff --output-indicator-new=x HEAD~1", root).includes("diff"));
		assert.deepEqual(checkCommand("rg -tzig main", root), ["rg", "-tzig", "main"]);
		assert.deepEqual(checkCommand("rg foo -- -z", root), ["rg", "foo", "--", "-z"]);
		// Attached values inside the project, and flags combined with value-taking options, stay allowed.
		assert.ok(checkCommand("git diff -O.gitorder HEAD~1", root).includes("-O.gitorder"));
		assert.ok(checkCommand("git log -n5 -pM", root).includes("-pM"));
		assert.ok(checkCommand("git log -L1,5:src/a.ts", root).includes("-L1,5:src/a.ts"));
		assert.ok(checkCommand("git blame -C -S.revs src/a.ts", root).includes("-S.revs"));
		assert.ok(checkCommand("git ls-files -oiX.gitignore", root).includes("-oiX.gitignore"));
	});

	const rejected: Array<[string, RegExp]> = [
		["rm -rf src", /not allowed/],
		["bash -c ls", /not allowed/],
		["node -e 1", /not allowed/],
		["cat a.ts | sh", /operator "\|"/],
		["cat a.ts; rm a.ts", /operator ";"/],
		["cat a.ts && rm a.ts", /operator "&"/],
		["cat $(whoami)", /operator "\$"/],
		["cat `whoami`", /operator "`"/],
		["cat a.ts > b.ts", /operator ">"/],
		["git -c core.pager=sh log", /must come first/],
		["git commit -m x", /must come first/],
		["git push", /must come first/],
		["git checkout main", /must come first/],
		["git log --output=pwned", /--output=pwned is not allowed/],
		["git diff --ext-diff", /not allowed/],
		["git grep -Ocat foo", /not allowed/],
		["git grep --open-files-in-pager=sh x", /not allowed/],
		// git accepts unambiguous abbreviations of long options.
		["git grep \"--op=sh -c 'id > pwned' #\" x", /--op=sh .* is not allowed/],
		["git grep --open x", /not allowed/],
		["git log --outp=pwned", /not allowed/],
		["git diff --ext", /not allowed/],
		["git show --textc", /not allowed/],
		["git grep -nO sh x", /not allowed/],
		["git grep -5Osh x", /not allowed/],
		["rg --follow foo", /not allowed/],
		// ls and wc must not reach files outside the project through a symbolic link inside it.
		["ls -lRL src", /not allowed/],
		["ls -H src", /not allowed/],
		["ls --dereference src", /not allowed/],
		["ls --deref src", /not allowed/],
		["wc --files0-from=list.txt", /not allowed/],
		// A submodule's config, and so its filter drivers, are not neutralized.
		["git status --ignore-submodules=none", /not allowed/],
		["git diff --submodule=diff", /not allowed/],
		["git grep --recurse-submodules x", /not allowed/],
		["rg -L foo", /not allowed/],
		["rg -f/etc/passwd foo", /outside the project/],
		// git short options with an attached file value: an order file, a revisions file, an exclude file.
		["git diff -O/etc/hosts", /outside the project/],
		["git diff -pO/etc/hosts", /outside the project/],
		["git log -p -O../order", /outside the project/],
		["git show -O~/order", /outside the project/],
		["git blame -S/etc/hosts src/a.ts", /outside the project/],
		["git ls-files -o -i -X/etc/hosts", /outside the project/],
		["git ls-files -oiX/etc/hosts", /outside the project/],
		["rg -f=/etc/passwd foo", /outside the project/],
		["cat -- /etc/passwd", /outside the project/],
		// Names inherited from Object.prototype are not commands.
		["constructor", /not allowed/],
		["toString x", /not allowed/],
		["__proto__", /not allowed/],
		["rg --pre sh foo", /not allowed/],
		["rg --pre=./x foo", /not allowed/],
		["rg -zl foo", /not allowed/],
		["tail -f log.txt", /not allowed/],
		["cat ../secret", /outside the project/],
		["cat /etc/passwd", /outside the project/],
		["cat ~/.ssh/id_rsa", /outside the project/],
		["rg --file=/etc/passwd x", /outside the project/],
		["cat 'unterminated", /Unterminated/],
	];
	for (const [command, pattern] of rejected) {
		test(`rejects: ${command}`, () => {
			assert.throws(() => checkCommand(command, root), (error: unknown) => error instanceof ShellRejection && pattern.test(error.message));
		});
	}

	test("executes allowed commands inside the project without a shell", async () => {
		const repo = makeRepo({ "src/a.ts": "const token = 'x';\n" });
		const tool = createShellTool(repo);
		const result = await runTool(tool, { command: "rg -n token src" });
		const text = result.content[0]!.type === "text" ? result.content[0]!.text : "";
		assert.match(text, /^exit 0\nsrc\/a\.ts:1:const token/);
		const log = await runTool(tool, { command: "git log --oneline" }, "2");
		assert.match(log.content[0]!.type === "text" ? log.content[0]!.text : "", /initial/);
	});

	test("searches the project when no path is given instead of waiting on stdin", async () => {
		const repo = makeRepo({ "src/a.ts": "const token = 'x';\n" });
		const started = Date.now();
		const result = await runTool(createShellTool(repo), { command: "rg -n token" });
		assert.match(result.content[0]!.type === "text" ? result.content[0]!.text : "", /^exit 0\nsrc\/a\.ts:1:const token/);
		assert.ok(Date.now() - started < 10_000);
	});

	test("an abbreviated pager option cannot run a program", async () => {
		const repo = makeRepo({ "src/a.ts": "const token = 'x';\n" });
		const command = `git grep "--op=sh -c 'echo pwned > pwned' #" token`;
		await assert.rejects(runTool(createShellTool(repo), { command }), ShellRejection);
		assert.equal(existsSync(join(repo, "pwned")), false);
	});

	test("programs configured by the repository do not run while reading it", async () => {
		const repo = makeRepo({ "a.txt": "hello\n", ".gitattributes": "a.txt filter=x diff=x\n" });
		const marks = tempDir("sr-marks-");
		sh(repo, "config", "filter.x.clean", `sh -c 'touch ${marks}/clean; cat'`);
		sh(repo, "config", "filter.x.smudge", `sh -c 'touch ${marks}/smudge; cat'`);
		sh(repo, "config", "filter.x.required", "true");
		sh(repo, "config", "diff.x.textconv", `sh -c 'touch ${marks}/textconv; cat "$0"'`);
		sh(repo, "config", "log.showSignature", "true");
		sh(repo, "config", "gpg.program", `sh -c 'touch ${marks}/gpg' --`);
		const tool = createShellTool(repo);
		for (const command of ["git status", "git blame a.txt", "git cat-file --filters HEAD:a.txt", "git diff HEAD", "git log -p --format=%G?"]) {
			// A stale modification time makes git re-read the file through the clean filter.
			utimesSync(join(repo, "a.txt"), new Date(0), new Date(0));
			const result = await runTool(tool, { command });
			assert.match(result.content[0]!.type === "text" ? result.content[0]!.text : "", /^exit 0/, command);
		}
		utimesSync(join(repo, "a.txt"), new Date(0), new Date(0));
		assert.equal((await git(repo, ["status", "--porcelain"])).code, 0);
		assert.deepEqual(readdirSync(marks), []);
	});

	test("refuses a symbolic link that leaves the project", () => {
		const repo = makeRepo({ "src/a.ts": "1\n" });
		const outside = join(tempDir("sr-outside-"), "secret.txt");
		writeFileSync(outside, "SECRET\n");
		symlinkSync(outside, join(repo, "src/link.txt"));
		symlinkSync("a.ts", join(repo, "src/inside.txt"));
		assert.throws(() => checkCommand("cat src/link.txt", repo), /outside the project/);
		assert.deepEqual(checkCommand("cat src/inside.txt", repo), ["cat", "src/inside.txt"]);
	});
});
