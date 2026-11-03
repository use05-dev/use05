// What the browser shows from records: only those it can verify (the machine's pin under the team's
// pin key, then the machine's signature) and open. The rest are counted, not shown.
import { test } from "node:test";
import assert from "node:assert/strict";
import { hmacRef, newSecret, pinKey, pinWith, privateKey, publicOf, random, seal } from "../src/crypto.ts";
import { machinePin, openRecords } from "../src/opened.ts";

const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");
const enc = (s: string) => new TextEncoder().encode(s);

async function world(teamSecret = newSecret(), past: Uint8Array[] = []) {
  const teamPub = await publicOf(teamSecret);
  const idKey = random(32);
  const ed = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const edPub = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const xPub = await publicOf(newSecret());
  const pins = await pinKey(teamSecret);
  const machine = { id: "m1", name: "Mac", x_pub: b64(xPub), ed_pub: b64(edPub), pin: await pinWith(pins, "machine", `${b64(xPub)}:${b64(edPub)}`) };
  const keys = { team: await privateKey(teamSecret), teamPub, idKey, pinKey: pins, past: await Promise.all(past.map(async (p) => ({ pub: await publicOf(p), key: await privateKey(p) }))) };
  const record = async (kind: string, body: unknown, signer = ed.privateKey, to = teamPub) => {
    const sealed = await seal(to, enc(JSON.stringify(body)), enc(`use05 record ${kind}`));
    const signed = new Uint8Array([...enc("use05 record v1"), ...enc(kind), 0, ...enc("r1"), 0, ...enc(""), 0, ...sealed]);
    const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", signer, signed));
    return { kind, repo: "r1", ref: "", machine: "m1", at: "2026-11-02T10:00:00Z", sealed: b64(sealed), sig: b64(sig) };
  };
  return { machine, keys, record };
}

test("a verified record opens; a bad signature or a bad pin is counted, not shown", async () => {
  const w = await world();
  const good = await w.record("repo", { name: "acme-billing" });
  const other = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign"])) as CryptoKeyPair;
  const forged = await w.record("repo", { name: "forged" }, other.privateKey);
  const opened = await openRecords([good, forged], [w.machine], w.keys);
  assert.equal(opened.records.length, 1);
  assert.equal(opened.records[0].body.name, "acme-billing");
  assert.equal(opened.unverified, 1);

  const swapped = { ...w.machine, pin: "0".repeat(32) };
  const again = await openRecords([good], [swapped], w.keys);
  assert.equal(again.records.length, 0, "a machine whose pin the team did not make");
  assert.equal(again.unverified, 1);

  const nobody = await openRecords([good], [], w.keys);
  assert.equal(nobody.unverified, 1, "a machine nobody paired");

  // Someone who left keeps the id key; a pin made with it is not the team's.
  const byIdKey = { ...w.machine, pin: await hmacRef(w.keys.idKey, "machine", `${w.machine.x_pub}:${w.machine.ed_pub}`) };
  assert.equal((await openRecords([good], [byIdKey], w.keys)).unverified, 1, "a pin under the id key");
});

test("a record sealed to an earlier team key still opens, marked old", async () => {
  const earlier = newSecret();
  const w = await world(newSecret(), [earlier]);
  const before = await w.record("task", { title: "from before" }, undefined, await publicOf(earlier));
  const now = await w.record("task", { title: "from now" });
  const opened = await openRecords([before, now], [w.machine], w.keys);
  assert.deepEqual(opened.records.map((r) => [r.body.title, r.old]), [["from before", true], ["from now", false]]);
});

test("the latest gate verdict is by the machine's own time, which it signed, not the console's", async () => {
  const { latestGates } = await import("../src/opened.ts");
  const gate = (decision: string, machineAt: string, consoleAt: string) => ({ kind: "event", repo: "r1", ref: decision, machine: "m1", at: consoleAt, body: { kind: "gate", task: "t1", _at: machineAt, data: { decision } } });
  // The console puts the older verdict last.
  const gates = latestGates([gate("allow", "2026-11-02T10:05:00Z", "2026-11-02T10:00:00Z"), gate("block", "2026-11-02T10:00:00Z", "2026-11-02T10:09:00Z")]);
  assert.equal(gates.get("r1/t1")?.decision, "allow");
});

test("a record older than one this browser has seen is refused, not shown as current", async () => {
  const { notRolledBack } = await import("../src/opened.ts");
  const rec = (seq: number, title: string) => ({ kind: "repo", repo: "r1", ref: "", machine: "m1", at: "", body: { _seq: seq, title } });
  const seen: Record<string, number> = {};
  const first = notRolledBack([rec(5, "new")], seen);
  assert.deepEqual([first.kept.map((r) => r.body.title), first.rolledBack], [["new"], 0]);
  // Later the console serves the older copy it kept.
  const again = notRolledBack([rec(3, "old")], seen);
  assert.deepEqual([again.kept.length, again.rolledBack], [0, 1]);
  // Records from before machines numbered them pass.
  assert.equal(notRolledBack([{ ...rec(0, "unnumbered"), body: { title: "unnumbered" } }], seen).kept.length, 1);
});

test("a token's pin says what it is and for which repository; passed off as a machine it is not trusted", async () => {
  const w = await world();
  const good = await w.record("repo", { name: "acme-billing" });
  const pinned = { ...w.machine, kind: "session", repo_only: "r1", pin: await machinePin(w.keys.pinKey, { ...w.machine, kind: "session", repo_only: "r1" }) };
  assert.equal((await openRecords([good], [pinned], w.keys)).records.length, 1);
  for (const lie of [{ kind: "machine" }, { kind: "ci" }, { repo_only: "r2" }, { kind: undefined, repo_only: null }]) {
    assert.equal((await openRecords([good], [{ ...pinned, ...lie }], w.keys)).unverified, 1, JSON.stringify(lie));
  }
});
