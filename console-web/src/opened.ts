// Records as the browser shows them: only those it can verify and open (D86). A record counts
// when the machine that sent it was pinned by the team (an HMAC under the team's id key over its
// keys, which the console cannot make), its Ed25519 signature checks, and it opens with the
// team's key. Anything else is counted as unverified and never shown.

import { open, pinWith } from "./crypto.ts";

export type Row = { kind: string; repo: string; ref: string; machine: string | null; at: string; sealed: string; sig: string };
export type MachineRow = { id: string; name?: string; x_pub: string | null; ed_pub: string | null; pin: string | null; member_id?: string | null; kind?: string; repo_only?: string | null };
export type Keys = { team: CryptoKey; teamPub: Uint8Array; idKey: Uint8Array; past?: { pub: Uint8Array; key: CryptoKey }[]; pinKey?: CryptoKey };
/// `old`: it opened only with one of the team's earlier keys.
export type Opened = { kind: string; repo: string; ref: string; machine: string; at: string; body: any; old?: boolean };

const enc = (s: string) => new TextEncoder().encode(s);
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/// The bytes a machine signs for a record.
export function signedBytes(kind: string, repo: string, ref: string, sealed: Uint8Array): Uint8Array<ArrayBuffer> {
  const head = [...enc("use05 record v1"), ...enc(kind), 0, ...enc(repo), 0, ...enc(ref), 0];
  const out = new Uint8Array(new ArrayBuffer(head.length + sealed.length));
  out.set(head);
  out.set(sealed, head.length);
  return out;
}

/// The pin the team makes for a machine paired at a terminal, or for a token: a token's binds what
/// it is (a cloud session's or CI's) and its one repository, so a console cannot pass a token off
/// as a machine, or as one for another repository.
export function machinePin(pins: CryptoKey, m: { x_pub: string | null; ed_pub: string | null; kind?: string; repo_only?: string | null }): Promise<string> {
  if (!m.kind || m.kind === "machine") return pinWith(pins, "machine", `${m.x_pub}:${m.ed_pub}`);
  return pinWith(pins, "reporter", `${m.x_pub}:${m.ed_pub}:${m.kind}:${m.repo_only ?? ""}`);
}

/// A machine the team pinned under its current pin key, with its signing key ready; null for one
/// it did not. The pin key comes from the team's secret, so someone who left cannot make one.
export async function trusted(m: MachineRow, keys: Keys): Promise<CryptoKey | null> {
  if (!m.x_pub || !m.ed_pub || !m.pin || !keys.pinKey) return null;
  if ((await machinePin(keys.pinKey, m)) !== m.pin) return null;
  return crypto.subtle.importKey("raw", unb64(m.ed_pub), { name: "Ed25519" }, false, ["verify"]);
}

/// Verify and open what the console relayed. Signed bodies of another kind (approval) use this too.
export async function openSigned(kind: string, repo: string, ref: string, sealedB64: string, sigB64: string, signer: CryptoKey, keys: Keys): Promise<any> {
  return (await openSignedAged(kind, repo, ref, sealedB64, sigB64, signer, keys)).body;
}

async function openSignedAged(kind: string, repo: string, ref: string, sealedB64: string, sigB64: string, signer: CryptoKey, keys: Keys): Promise<{ body: any; old: boolean }> {
  const sealed = unb64(sealedB64);
  if (!(await crypto.subtle.verify("Ed25519", signer, unb64(sigB64), signedBytes(kind, repo, ref, sealed)))) throw new Error("bad signature");
  const aad = enc(`use05 record ${kind}`);
  const now = await open(keys.team, keys.teamPub, sealed, aad).catch(() => null);
  const bytes = now ?? (await openWithAny(keys, sealed, aad));
  return { body: JSON.parse(new TextDecoder().decode(bytes)), old: !now };
}

/// The team's current key, then its earlier ones: a record sealed before the key changed opens with the key of its day.
export async function openWithAny(keys: Keys, sealed: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  for (const k of [{ key: keys.team, pub: keys.teamPub }, ...(keys.past ?? [])]) {
    const opened = await open(k.key, k.pub, sealed, aad).catch(() => null);
    if (opened) return opened;
  }
  throw new Error("it does not open with the team's keys");
}

export async function machineKeys(machines: MachineRow[], keys: Keys): Promise<Map<string, CryptoKey>> {
  const out = new Map<string, CryptoKey>();
  for (const m of machines) {
    const k = await trusted(m, keys).catch(() => null);
    if (k) out.set(m.id, k);
  }
  return out;
}

export async function openRecords(rows: Row[], machines: MachineRow[], keys: Keys): Promise<{ records: Opened[]; unverified: number }> {
  const signers = await machineKeys(machines, keys);
  const records: Opened[] = [];
  let unverified = 0;
  for (const r of rows) {
    const signer = r.machine ? signers.get(r.machine) : undefined;
    try {
      if (!signer) throw new Error("no pinned machine");
      const { body, old } = await openSignedAged(r.kind, r.repo, r.ref, r.sealed, r.sig, signer, keys);
      records.push({ kind: r.kind, repo: r.repo, ref: r.ref, machine: r.machine!, at: r.at, body, old });
    } catch {
      unverified += 1;
    }
  }
  return { records, unverified };
}

/// When a record was made, by the machine's own clock: inside what it signed, so the console cannot
/// reorder records. Records from before machines said so fall back to when the console got them.
export const madeAt = (r: Opened): string => (typeof r.body?._at === "string" ? r.body._at : r.at);

/// The latest gate verdict each task has, by the machine's time.
export function latestGates(records: Opened[]): Map<string, { at: string; decision: string }> {
  const gate = new Map<string, { at: string; decision: string }>();
  for (const e of records.filter((r) => r.kind === "event" && r.body.kind === "gate" && r.body.task)) {
    const k = `${e.repo}/${e.body.task}`;
    const at = madeAt(e);
    // A machine's clock counts in seconds: of two in the same second, the later one sent wins.
    if (!gate.has(k) || gate.get(k)!.at <= at) gate.set(k, { at, decision: e.body.data?.decision });
  }
  return gate;
}

/// Records the console could be replaying: an older copy of something this browser has already
/// seen newer (each record carries the machine's signed counter, `_seq`). `seen` is this browser's
/// memory of the highest counter per record, updated here. A browser that has never seen a record
/// cannot tell; one that has, can.
export function notRolledBack(records: Opened[], seen: Record<string, number>): { kept: Opened[]; rolledBack: number } {
  const kept: Opened[] = [];
  let rolledBack = 0;
  for (const r of records) {
    const seq = typeof r.body?._seq === "number" ? r.body._seq : null;
    if (seq == null) {
      kept.push(r);
      continue;
    }
    const k = `${r.machine}/${r.kind}/${r.repo}/${r.ref}`;
    if (seq < (seen[k] ?? 0)) {
      rolledBack += 1;
      continue;
    }
    seen[k] = seq;
    kept.push(r);
  }
  return { kept, rolledBack };
}
