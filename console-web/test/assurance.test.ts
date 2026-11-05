// How much a task's decision rests on (D101), as the machine worked it out: the page shows 05's own
// line and never derives one, so it cannot say more than the gate found.
import { test } from "node:test";
import assert from "node:assert/strict";
import { checksLine } from "../src/api.ts";

test("the line under the verdict is the machine's own words", () => {
  assert.equal(checksLine({ assurance: { checks_required: 0, summary: "none required; behaviour not verified" } }), "Checks: none required; behaviour not verified");
  assert.equal(checksLine({ assurance: { summary: "1 passed, signed by CI (merge enforcement not confirmed from here)" } }), "Checks: 1 passed, signed by CI (merge enforcement not confirmed from here)");
});

test("a record from a 05 without it shows nothing, never a guess", () => {
  assert.equal(checksLine({}), null);
  assert.equal(checksLine({ assurance: {} }), null);
  assert.equal(checksLine({ assurance: { summary: 3 } }), null);
  assert.equal(checksLine(undefined), null);
});
