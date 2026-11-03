// The policy editor's checks, run here (D86): the same Rust the helper runs again before it
// commits, compiled to WebAssembly, since the console never sees a team's policy.
import init, { from_base, preview, view } from "./wasm/use05_policy_wasm.js";

const ready = init();

export async function previewEdit(current: string, changes: unknown[], detected: unknown[]): Promise<any> {
  await ready;
  return JSON.parse(preview(current, JSON.stringify(changes), JSON.stringify(detected)));
}

export async function readPolicy(text: string): Promise<any> {
  await ready;
  return JSON.parse(view(text));
}

export async function baseChanges(text: string): Promise<any> {
  await ready;
  return JSON.parse(from_base(text));
}
