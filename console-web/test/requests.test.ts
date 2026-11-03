// A long task piles up approval requests, one for every tree the machine asked about. Only the
// newest is the person's to answer; Home must not list the same finished work eight times.
import { test } from "node:test";
import assert from "node:assert/strict";
import { currentRequests } from "../src/requests.ts";

const ask = (id: string, task: string, at: string, over: Record<string, unknown> = {}) => ({ id, repo_id: "r1", task_id: task, created_at: at, ...over });

test("only the newest request for a task is current", () => {
  const asks = [ask("a", "t1", "2026-11-03T08:00:00Z"), ask("b", "t1", "2026-11-03T09:00:00Z"), ask("c", "t1", "2026-11-03T07:00:00Z")];
  const now = currentRequests(asks);
  assert.deepEqual([...now].map((a) => a.id), ["b"]);
});

test("different tasks and different repositories each keep their own", () => {
  const asks = [ask("a", "t1", "2026-11-03T08:00:00Z"), ask("b", "t2", "2026-11-03T08:00:00Z"), { ...ask("c", "t1", "2026-11-03T08:00:00Z"), repo_id: "r2" }];
  assert.equal(currentRequests(asks).size, 3);
});

test("work CI holds is told apart by its tree, not by a task it has none of", () => {
  const asks = [ask("a", "-", "2026-11-03T08:00:00Z", { from: "ci", tree: "x" }), ask("b", "-", "2026-11-03T09:00:00Z", { from: "ci", tree: "y" }), ask("c", "-", "2026-11-03T10:00:00Z", { from: "ci", tree: "x" })];
  assert.deepEqual([...currentRequests(asks)].map((a) => a.id).sort(), ["b", "c"]);
});
