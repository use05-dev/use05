// The policy editor's checks in the browser are the helper's own Rust, compiled to WebAssembly.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { initSync, preview, from_base, view } from "../src/wasm/use05_policy_wasm.js";

initSync({ module: readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../src/wasm/use05_policy_wasm_bg.wasm")) });

test("removing a protected path is loosening, refused from a browser", () => {
  const p = JSON.parse(preview('[protect]\npaths = ["migrations/**"]\n', JSON.stringify([{ path: "protect.paths", value: [] }]), "[]"));
  assert.equal(p.ok, true);
  assert.deepEqual(p.loosens, ["protect.paths"]);
});

test("locking a path keeps the file's comments and only tightens", () => {
  const p = JSON.parse(preview("# ours\n[protect]\nlocked = [] # careful\n", JSON.stringify([{ path: "protect.locked", value: ["vendor/**"] }]), "[]"));
  assert.ok(p.toml.includes("# ours") && p.toml.includes('locked = ["vendor/**"]'), p.toml);
  assert.deepEqual(p.loosens, []);
});

test("reads a policy and a template", () => {
  assert.equal(JSON.parse(view("[intent]\nmode = \"always\"\n")).policy.intent.mode, "always");
  assert.equal(JSON.parse(view("not toml [")).ok, false);
  assert.equal(JSON.parse(from_base('[protect]\nlocked = ["vendor/**"]\n')).ok, true);
});
