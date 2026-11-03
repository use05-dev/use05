// The browser's sealing agrees with the helper's (Rust, crates/cloud/src/seal.rs): it opens what
// Rust sealed, from fixed vectors, and what it seals Rust opens (test/from-browser.json).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { derive, hmacRef, linkKey, open, pairCommit, pairingCode, privateKey, publicOf, seal, unwrap, wrap } from "../src/crypto.ts";

const here = dirname(fileURLToPath(import.meta.url));
const v = JSON.parse(readFileSync(join(here, "../../crates/cloud/tests/vectors.json"), "utf8"));
const hex = (s: string) => Uint8Array.from(s.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const text = (s: string) => new TextEncoder().encode(s);

test("the public key of a secret matches Rust's", async () => {
  assert.equal(toHex(await publicOf(hex(v.recipient_secret))), v.recipient_public);
});

test("opens Rust's sealed vector", async () => {
  const opened = await open(await privateKey(hex(v.recipient_secret)), hex(v.recipient_public), hex(v.sealed), text("aad"));
  assert.equal(new TextDecoder().decode(opened), "hello 05");
  await assert.rejects(open(await privateKey(hex(v.recipient_secret)), hex(v.recipient_public), hex(v.sealed), text("other")));
});

test("unwraps Rust's wrapped vector", async () => {
  assert.equal(new TextDecoder().decode(await unwrap(hex(v.wrap_key), hex(v.wrapped), text("v1"))), "team secret");
  const again = await wrap(hex(v.wrap_key), text("round trip"), text("v1"));
  assert.equal(new TextDecoder().decode(await unwrap(hex(v.wrap_key), again, text("v1"))), "round trip");
});

test("derives, pairs and references the same as Rust", async () => {
  assert.equal(toHex(await derive(text("ikm"), "use05 wrap v1")), v.derived);
  const fill = (n: number, len = 32) => new Uint8Array(len).fill(n);
  assert.equal(await pairingCode(fill(6), 3, fill(7), fill(8), fill(10, 16), fill(11, 16)), v.pairing_code);
  assert.equal(toHex(await pairCommit(fill(7), fill(8), fill(10, 16))), v.pair_commit);
  const team = hex(v.link_team_secret);
  assert.equal(toHex(await linkKey(await privateKey(team), hex(v.link_machine_public), await publicOf(team), hex(v.link_machine_public))), v.link_key);
  assert.equal(await hmacRef(new Uint8Array(32).fill(9), "repo", "github.com/acme/billing"), v.hmac_ref);
});

test("seals something Rust can open", async () => {
  const sealed = await seal(hex(v.recipient_public), text("sealed in a browser"), text("from the browser"));
  const opened = await open(await privateKey(hex(v.recipient_secret)), hex(v.recipient_public), sealed, text("from the browser"));
  assert.equal(new TextDecoder().decode(opened), "sealed in a browser");
  const fixture = join(here, "from-browser.json");
  if (!existsSync(fixture) || process.env.WRITE_FIXTURE) writeFileSync(fixture, JSON.stringify({ sealed: toHex(sealed) }, null, 2) + "\n");
});
