// Before a passkey signs, the browser reads the statement itself: a testing sign-off must be the one
// the person asked for (this tree, this outcome, this note), and an approval must be an approval.
// The machine or the console could otherwise hand back anything for the passkey to sign.
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkStatement } from "../src/passkey.ts";

const TREE = "a".repeat(40);
const OTHER = "b".repeat(40);
const unsigned = (type: string, predicate: unknown, tree = TREE) => ({
  payload: Buffer.from(JSON.stringify({ _type: "https://in-toto.io/Statement/v1", subject: [{ name: "tree", digest: { gitTree: tree } }], predicateType: type, predicate })).toString("base64"),
  payload_type: "application/vnd.in-toto+json",
  challenge: "",
});
const testing = (over: Record<string, unknown> = {}, tree = TREE) =>
  unsigned("https://use05.dev/testing/v0", { outcome: "tested", task: "t1", note: "paid an invoice", tester: "sam", created: "2026-11-02T10:00:00Z", ...over }, tree);
const approval = (over: Record<string, unknown> = {}) =>
  unsigned("https://use05.dev/approval/v0", { decision: "approve", scope: "outcome", task: "t1", policy_sha256: "p", rationale: "", approver: "sam", created: "", expires: "", ...over });
const want = { type: "testing" as const, tree: TREE, outcome: "tested" as const, note: "paid an invoice", task: "t1" };

test("the testing sign-off the person asked for passes", () => {
  assert.doesNotThrow(() => checkStatement(testing(), want));
});

test("an approval handed back for a testing sign-off is refused", () => {
  assert.throws(() => checkStatement(approval(), want), /not the sign-off you asked for/);
});

test("a sign-off for another tree, outcome, note or task is refused", () => {
  assert.throws(() => checkStatement(testing({}, OTHER), want), /not the sign-off you asked for/);
  assert.throws(() => checkStatement(testing({ outcome: "skipped" }), want), /not the sign-off you asked for/);
  assert.throws(() => checkStatement(testing({ note: "nothing" }), want), /not the sign-off you asked for/);
  assert.throws(() => checkStatement(testing({ task: "t2" }), want), /not the sign-off you asked for/);
});

test("an approval must approve, and a testing statement is not one", () => {
  assert.doesNotThrow(() => checkStatement(approval(), { type: "approval" }));
  assert.throws(() => checkStatement(approval({ decision: "reject" }), { type: "approval" }), /not an approval/);
  assert.throws(() => checkStatement(testing(), { type: "approval" }), /not an approval/);
  assert.throws(() => checkStatement(approval({ scope: "intent" }), { type: "approval", scope: "outcome" }), /not an approval/);
  assert.throws(() => checkStatement(approval(), { type: "approval", tree: OTHER }), /not an approval/);
});

test("an unreadable statement is refused", () => {
  assert.throws(() => checkStatement({ payload: "%%%", payload_type: "", challenge: "" }, { type: "approval" }), /not an approval/);
});

test("a discard must be of the work shown, and nothing else passes for one", () => {
  const discard = (task: string, subjectTask = task) => ({
    payload: Buffer.from(JSON.stringify({ _type: "https://in-toto.io/Statement/v1", subject: [{ name: "work", digest: { task: subjectTask, gitCommit: "c".repeat(40) } }], predicateType: "https://use05.dev/discard/v0", predicate: { task, branch: "claude/x", head: "c".repeat(40), unpushed: 1, uncommitted: 0, by: "sam", created: "" } })).toString("base64"),
    payload_type: "application/vnd.in-toto+json",
    challenge: "",
  });
  assert.doesNotThrow(() => checkStatement(discard("t1"), { type: "discard", task: "t1" }));
  assert.throws(() => checkStatement(discard("t2"), { type: "discard", task: "t1" }), /not a discard of this work/);
  assert.throws(() => checkStatement(discard("t1", "t2"), { type: "discard", task: "t1" }), /not a discard of this work/);
  assert.throws(() => checkStatement(discard("t2", "t1"), { type: "discard", task: "t1" }), /not a discard of this work/);
  assert.throws(() => checkStatement(approval(), { type: "discard", task: "t1" }), /not a discard of this work/);
  assert.throws(() => checkStatement(discard("t1"), { type: "approval" }), /not an approval/);
});

test("a rejection signs only when the person asked to reject, and an approval never stands in for it", () => {
  assert.doesNotThrow(() => checkStatement(approval({ decision: "reject", rationale: "out of scope" }), { type: "approval", decision: "reject" }));
  assert.throws(() => checkStatement(approval({ decision: "approve" }), { type: "approval", decision: "reject" }), /not an approval/);
  assert.throws(() => checkStatement(approval({ decision: "reject" }), { type: "approval" }), /not an approval/);
});
