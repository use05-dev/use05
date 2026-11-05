// A repository's environments on the console (D93): the page says what the machine's records
// say and no more, and a passkey signs a sign-off only when it is the one the person asked for,
// on that environment, in their words.
import { test } from "node:test";
import assert from "node:assert/strict";
import { deployWords, waitingWords } from "../src/api.ts";
import { checkStatement } from "../src/passkey.ts";

test("a deploy is called confirmed only when its record says so, and never without probes", () => {
  assert.equal(deployWords({ deployed: { confirmed: true, probes: 2 } }), "deploy confirmed");
  assert.equal(deployWords({ deployed: { confirmed: false, probes: 1 } }), "deploy not confirmed");
  assert.equal(deployWords({ deployed: { confirmed: true, probes: 0 } }), "no probes: 05 cannot tell what it runs");
  assert.equal(deployWords({ deployed: { confirmed: false, probes: 1, action: "reverted" } }), "not confirmed, reverted");
  assert.equal(deployWords({ deployed: null }), "no deploy record");
  assert.equal(deployWords(undefined), "no deploy record");
});

test("what waits to come up is counted, and nothing is said when nothing waits", () => {
  assert.equal(waitingWords({ waiting: 1, from: "uat" }), "1 commit from uat can come up");
  assert.equal(waitingWords({ waiting: 3, from: "uat" }), "3 commits from uat can come up");
  assert.equal(waitingWords({ waiting: 0, from: "uat" }), null);
  assert.equal(waitingWords({ waiting: 2 }), null, "the lowest environment has nothing below it");
  assert.equal(waitingWords({ waiting: "2", from: "uat" }), null);
});

const COMMIT = "c".repeat(40);
const signoff = (over: Record<string, unknown> = {}, commit = COMMIT) => ({
  payload: Buffer.from(
    JSON.stringify({
      _type: "https://in-toto.io/Statement/v1",
      subject: [{ name: "commit", digest: { gitCommit: commit } }],
      predicateType: "https://use05.dev/signoff/v0",
      predicate: { env: "prod", from: "uat", source_commit: COMMIT, decision: "approve", signer_person: "Dana", text: "Checked the invoices in uat", answers: [], confirmations: [], policy_sha256: "p", created: "", expires: "", ...over },
    }),
  ).toString("base64"),
  payload_type: "application/vnd.in-toto+json",
  challenge: "",
});
const want = { type: "signoff" as const, env: "prod", text: "Checked the invoices in uat", decision: "approve" as const };

test("the sign-off the person asked for passes", () => {
  assert.doesNotThrow(() => checkStatement(signoff(), want));
  assert.doesNotThrow(() => checkStatement(signoff(), { ...want, source: COMMIT }));
});

test("a sign-off on another environment, in other words, a no, or for another commit is refused", () => {
  assert.throws(() => checkStatement(signoff({ env: "uat" }), want), /not the sign-off you asked for/);
  assert.throws(() => checkStatement(signoff({ text: "ok" }), want), /not the sign-off you asked for/);
  assert.throws(() => checkStatement(signoff({ decision: "reject" }), want), /not the sign-off you asked for/);
  assert.throws(() => checkStatement(signoff({}, "d".repeat(40)), want), /not the sign-off you asked for/, "the subject must be the commit it names");
  assert.throws(() => checkStatement(signoff(), { ...want, source: "e".repeat(40) }), /not the sign-off you asked for/);
});
