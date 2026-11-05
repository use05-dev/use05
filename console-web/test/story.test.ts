// A task's story on the console (D102): rows say where each line comes from, the agent's words
// never arrive (only how many of its claims stand where), and nothing is made up for a record
// from a 05 that does not send a story.
import { test } from "node:test";
import assert from "node:assert/strict";
import { storyRows } from "../src/api.ts";

test("each row says where it comes from, the agent's only by counts", () => {
  const rows = storyRows({
    story: {
      claim_counts: { supported: 1, unsupported: 0, contradicted: 1 },
      observed: ["2 files changed in src/billing/ · +40 −10", "1 test file edited by this change"],
      checked: "1 failed, 1 passed on the machine that ran it",
      needs_you: ["the test check failed on this tree"],
      not_known: ["behaviour beyond these checks"],
    },
  });
  assert.deepEqual(
    rows.map((r) => [r.label, r.text, !!r.attention]),
    [
      ["Agent says", "its claims: 1 contradicted by a check, 1 backed by a check (its words stay on its machine)", true],
      ["05 saw", "2 files changed in src/billing/ · +40 −10", false],
      ["05 saw", "1 test file edited by this change", false],
      ["Checked", "1 failed, 1 passed on the machine that ran it", false],
      ["Needs you", "the test check failed on this tree", true],
      ["Not known", "behaviour beyond these checks", false],
    ],
  );
});

test("no claims: the agent's row says only that its words stay on its machine", () => {
  const rows = storyRows({ story: { claim_counts: { supported: 0, unsupported: 0, contradicted: 0 }, observed: [], checked: "none required; behaviour not verified", needs_you: [], not_known: [] } });
  assert.deepEqual(rows.map((r) => r.label), ["Agent says", "Checked"]);
  assert.equal(rows[0].text, "its words stay on its machine");
});

test("a record without a story shows none, and odd values are dropped, never shown", () => {
  assert.deepEqual(storyRows({}), []);
  assert.deepEqual(storyRows(undefined), []);
  const rows = storyRows({ story: { observed: [3, "a file"], needs_you: "not a list", checked: 5 } });
  assert.deepEqual(rows.map((r) => [r.label, r.text]), [["Agent says", "its words stay on its machine"], ["05 saw", "a file"]]);
});
