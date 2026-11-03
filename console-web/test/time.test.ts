// When something happened, in the words a person would use. A week-old session must never read as
// recent, so past a week it is the date, and the exact moment is always on hover.
import { test } from "node:test";
import assert from "node:assert/strict";
import { ago, stamp } from "../src/api.ts";

const before = (seconds: number) => new Date(Date.now() - seconds * 1000).toISOString();

test("recent times are relative", () => {
  assert.equal(ago(before(5)), "just now");
  assert.equal(ago(before(5 * 60)), "5 min ago");
  assert.equal(ago(before(3 * 3600)), "3 h ago");
});

test("a day or more back says which day, not 'recent'", () => {
  assert.equal(ago(before(30 * 3600)), "yesterday");
  assert.equal(ago(before(3 * 86400)), "3 d ago");
  const old = ago(before(12 * 86400));
  assert.doesNotMatch(old, /ago|just now/, `a 12 day old session is a date, got ${old}`);
});

test("missing or unreadable times are said plainly", () => {
  assert.equal(ago(null), "never");
  assert.equal(ago("not a time"), "unknown");
  assert.equal(stamp(null), "");
  assert.equal(stamp("not a time"), "");
  assert.match(stamp("2026-11-03T15:00:00Z"), /Nov/);
});
