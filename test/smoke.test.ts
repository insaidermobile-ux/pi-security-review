import assert from "node:assert/strict";
import { test } from "node:test";

test("test runner executes TypeScript tests", () => {
	assert.equal(1 + 1, 2);
});
