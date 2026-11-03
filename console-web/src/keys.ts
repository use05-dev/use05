// The team's keys, held by people (D86). Each member has an X25519 key whose secret is wrapped by
// their passkey's PRF secret and again by a recovery code; the team's secret (its X25519 key and a
// 32-byte id key) is sealed to every member. The console stores only those wrapped and sealed bytes.
//
// Between passkey taps this browser keeps the team and member keys in IndexedDB as
// non-extractable keys (enough to read), plus the id key. The team's raw secret exists only in
// memory during a tap: setting up, inviting, adding a passkey, rotating.

import { get, post } from "./api";
import { derive, linkKey, newSecret, open, pinKey, pinWith, privateKey, publicOf, random, seal, unwrap, wrap } from "./crypto";
import { signOwn } from "./passkey";
import { machinePin, type MachineRow } from "./opened";

type Bytes = Uint8Array<ArrayBuffer>;
const enc = (s: string) => new TextEncoder().encode(s);
const MEMBER_AAD = enc("use05 member key");
const GRANT_AAD = enc("use05 grant");
const INVITE_AAD = enc("use05 invite");

export const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
export const unb64 = (s: string): Bytes => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)) as Bytes;
const b64url = (b: Uint8Array) => b64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64url = (s: string) => unb64(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));

/// `past`: the team's earlier keys, which still open what machines sealed before the key changed.
/// `pinKey`: what pins machines and members, from the current team secret (so it changes with it).
export type Unlocked = { version: number; teamPub: Bytes; team: CryptoKey; idKey: Bytes; memberPub: Bytes; member: CryptoKey; past?: { pub: Bytes; key: CryptoKey }[]; pinKey?: CryptoKey };
type Old = { version: number; secret: Bytes };
type Bundle = { version: number; secret: Bytes; id: Bytes; past: Old[] };

const bundleBytes = (b: Bundle) => enc(JSON.stringify({ v: b.version, secret: b64(b.secret), id: b64(b.id), past: b.past.map((o) => ({ v: o.version, secret: b64(o.secret) })) }));
const readBundle = (bytes: Uint8Array): Bundle => {
  const j = JSON.parse(new TextDecoder().decode(bytes));
  return { version: j.v, secret: unb64(j.secret), id: unb64(j.id), past: (j.past ?? []).map((o: any) => ({ version: o.v, secret: unb64(o.secret) })) };
};

// ------------------------------------------------------------------ this browser's copy

function db(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open("use05-keys", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("keys");
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function store(mode: IDBTransactionMode, work: (s: IDBObjectStore) => IDBRequest): Promise<any> {
  const d = await db();
  return new Promise((resolve, reject) => {
    const r = work(d.transaction("keys", mode).objectStore("keys"));
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

let cached: Unlocked | null = null;

export async function unlocked(): Promise<Unlocked | null> {
  if (cached) return cached;
  cached = ((await store("readonly", (s) => s.get("team")).catch(() => null)) as Unlocked | undefined) ?? null;
  return cached;
}

/// This browser's keys, if they are the team's current ones. After someone leaves, the key this
/// browser kept is the old one: unlock again (a passkey tap) to get the new one.
export async function current(): Promise<Unlocked | null> {
  const u = await unlocked();
  if (!u) return null;
  const me = await get<Mine>("/keys/me").catch(() => null);
  if (!u.pinKey || (me?.team && me.team.version > u.version)) {
    await lock();
    return null;
  }
  return u;
}

/// Read this browser's keys again: another tab may have stored newer ones.
export async function reread(): Promise<Unlocked | null> {
  cached = null;
  return unlocked();
}

async function keep(u: Unlocked) {
  cached = u;
  await store("readwrite", (s) => s.put(u, "team"));
}

/// Forget the keys in this browser (signing out).
export async function lock() {
  cached = null;
  await store("readwrite", (s) => s.delete("team")).catch(() => undefined);
}

/// Keep a bundle in this browser. The team's public key is worked out from the secret, never taken
/// from the console; and no older key than this browser has seen is ever taken again.
async function remember(bundle: Bundle, memberSecret: Bytes) {
  const seen = Number(localStorage.getItem("use05-team-version") ?? 0);
  if (bundle.version < seen) throw new Error(`This browser has seen your console's key version ${seen}; the console offered ${bundle.version}. It may be tampered with: do not continue.`);
  localStorage.setItem("use05-team-version", String(bundle.version));
  const past = await Promise.all(bundle.past.map(async (o) => ({ pub: await publicOf(o.secret), key: await privateKey(o.secret) })));
  await keep({ version: bundle.version, teamPub: await publicOf(bundle.secret), team: await privateKey(bundle.secret), idKey: bundle.id, memberPub: await publicOf(memberSecret), member: await privateKey(memberSecret), past, pinKey: await pinKey(bundle.secret) });
}

const OWN_AAD = (version: number) => enc(`use05 own grant ${version}`);
const ownKey = (memberSecret: Uint8Array) => derive(memberSecret, "use05 own grant v1");
/// Your own copy of a bundle: wrapped under a key from your secret, which the console cannot make.
const ownCopy = async (memberSecret: Uint8Array, b: Bundle) => b64(await wrap(await ownKey(memberSecret), bundleBytes(b), OWN_AAD(b.version)));

const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
/// A newer bundle follows from one you hold only if it keeps the id key and carries your key as past.
const follows = (held: Bundle, next: Bundle) => next.version > held.version && same(next.id, held.id) && next.past.some((o) => o.version === held.version && same(o.secret, held.secret));

/// A member's pin: their id and public key, vouched for under the team's pin key.
const memberPin = async (secret: Uint8Array, memberId: string, memberPub: Uint8Array) => pinWith(await pinKey(secret), "member", `${memberId}:${b64(memberPub)}`);

// ------------------------------------------------------------------ recovery codes

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// 20 random bytes, written as 32 letters and digits in groups of four.
function newRecovery(): { code: string; bytes: Bytes } {
  const bytes = random(20);
  let bits = "";
  bytes.forEach((b) => (bits += b.toString(2).padStart(8, "0")));
  const chars = bits.match(/.{5}/g)!.map((c) => BASE32[parseInt(c, 2)]).join("");
  return { code: chars.match(/.{4}/g)!.join("-"), bytes };
}

function recoveryBytes(code: string): Bytes {
  const chars = code.toUpperCase().replace(/[^A-Z2-7]/g, "");
  if (chars.length !== 32) throw new Error("A recovery code has 32 letters and digits.");
  const bits = Array.from(chars, (c) => BASE32.indexOf(c).toString(2).padStart(5, "0")).join("");
  return Uint8Array.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2))) as Bytes;
}

const passkeyWrap = async (prf: Uint8Array, memberSecret: Uint8Array) => wrap(await derive(prf, "use05 wrap v1"), memberSecret, MEMBER_AAD);
const recoveryWrap = async (code: Bytes, memberSecret: Uint8Array) => wrap(await derive(code, "use05 recovery v1"), memberSecret, MEMBER_AAD);

// ------------------------------------------------------------------ making and unlocking

/// The first member: make the team's keys and yours. Returns the recovery code to show once.
export async function setUpTeam(passkeyId: string, prf: Uint8Array): Promise<string> {
  const { member_id } = await get<Mine>("/keys/me");
  const memberSecret = newSecret();
  const bundle: Bundle = { version: 1, secret: newSecret(), id: random(32), past: [] };
  const memberPub = await publicOf(memberSecret);
  const teamPub = await publicOf(bundle.secret);
  const recovery = newRecovery();
  await post("/keys/setup", {
    member_public: b64(memberPub),
    passkey: { passkey_id: passkeyId, wrapped: b64(await passkeyWrap(prf, memberSecret)) },
    recovery: b64(await recoveryWrap(recovery.bytes, memberSecret)),
    team_public: b64(teamPub),
    grant: b64(await seal(memberPub, bundleBytes(bundle), GRANT_AAD)),
    own: await ownCopy(memberSecret, bundle),
    pin: await memberPin(bundle.secret, member_id, memberPub),
  });
  await remember(bundle, memberSecret);
  return recovery.code;
}

/// Someone joining: open the team's secret from the invitation (the link's fragment holds its
/// key, which the console never sees), make your keys, and seal your own copy.
export async function joinTeam(passkeyId: string, prf: Uint8Array, sealedBundle: string, fragment: string): Promise<string> {
  // The invitation is wrapped by a key only the link carries: what opens with it came from the admin.
  const bundle = readBundle(await unwrap(await derive(unb64url(fragment), "use05 invite v1"), unb64(sealedBundle), INVITE_AAD));
  const { member_id } = await get<Mine>("/keys/me");
  const memberSecret = newSecret();
  const memberPub = await publicOf(memberSecret);
  const recovery = newRecovery();
  await post("/keys/join", {
    member_public: b64(memberPub),
    passkey: { passkey_id: passkeyId, wrapped: b64(await passkeyWrap(prf, memberSecret)) },
    recovery: b64(await recoveryWrap(recovery.bytes, memberSecret)),
    grant: b64(await seal(memberPub, bundleBytes(bundle), GRANT_AAD)),
    own: await ownCopy(memberSecret, bundle),
    pin: await memberPin(bundle.secret, member_id, memberPub),
    version: bundle.version,
  });
  await remember(bundle, memberSecret);
  return recovery.code;
}

type Mine = {
  member_id: string;
  member_public: string | null;
  wraps: { kind: string; passkey_id: string | null; wrapped: string }[];
  grants: { version: number; sealed: string }[];
  own: { version: number; wrapped: string }[];
  team: { version: number; public: string } | null;
  rotate_needed?: boolean;
};

/// The team's current bundle for you. Your own copy (which only you could have made) is the start;
/// a newer key sealed to you is taken only if it follows from it. Then it must be the key the
/// console says machines seal to.
async function openGrant(me: Mine, memberSecret: Bytes): Promise<{ bundle: Bundle }> {
  let held: Bundle | null = null;
  const key = await ownKey(memberSecret);
  for (const o of [...me.own].sort((a, b) => b.version - a.version)) {
    const b = await unwrap(key, unb64(o.wrapped), OWN_AAD(o.version)).then(readBundle, () => null);
    if (b && b.version === o.version) {
      held = b;
      break;
    }
  }
  if (!held) throw new Error("You hold no key to these records that the console's server could not have made. Ask whoever invited you to invite you again.");
  const memberKey = await privateKey(memberSecret);
  const memberPub = await publicOf(memberSecret);
  for (const g of me.grants.filter((g) => g.version > held!.version).sort((a, b) => a.version - b.version)) {
    const next = await open(memberKey, memberPub, unb64(g.sealed), GRANT_AAD).then(readBundle, () => null);
    if (!next || !follows(held, next)) throw new Error("A new key arrived that does not follow from yours. The console's server may be tampered with: do not continue.");
    held = next;
    await post("/keys/own", { version: held.version, wrapped: await ownCopy(memberSecret, held) });
  }
  if (!me.team || me.team.version !== held.version || !same(unb64(me.team.public), await publicOf(held.secret))) {
    throw new Error("The console's server names a key that is not the one you hold. It may be tampered with: do not continue.");
  }
  return { bundle: held };
}

/// Your member secret, from a passkey's PRF secret or the recovery code. In memory only.
async function memberSecret(me: Mine, by: { passkeyId: string; prf: Uint8Array } | { code: string }): Promise<Bytes> {
  if ("code" in by) {
    const w = me.wraps.find((w) => w.kind === "recovery");
    if (!w) throw new Error("You have no recovery code.");
    return unwrap(await derive(recoveryBytes(by.code), "use05 recovery v1"), unb64(w.wrapped), MEMBER_AAD).catch(() => {
      throw new Error("That recovery code does not open your key.");
    });
  }
  const w = me.wraps.find((w) => w.kind === "passkey" && w.passkey_id === by.passkeyId);
  if (!w) throw new Error("This passkey cannot open your key yet. Unlock with your recovery code; this passkey is then set up too.");
  return unwrap(await derive(by.prf, "use05 wrap v1"), unb64(w.wrapped), MEMBER_AAD).catch(() => {
    throw new Error("This passkey cannot open your key. Unlock with your recovery code.");
  });
}

export type UnlockResult = "unlocked" | { recovery: string };

/// Unlock this browser with a passkey. A first admin with no team keys yet makes them now.
export async function unlockWith(passkeyId: string, prf: Uint8Array, admin: boolean): Promise<UnlockResult> {
  const me = await get<Mine>("/keys/me");
  if (!me.team && admin) return { recovery: await setUpTeam(passkeyId, prf) };
  const secret = await memberSecret(me, { passkeyId, prf });
  const { bundle } = await openGrant(me, secret);
  await remember(bundle, secret);
  return "unlocked";
}

/// Unlock with the recovery code; if a passkey's PRF secret is given, that passkey can unlock from now on.
export async function unlockWithRecovery(code: string, passkey?: { passkeyId: string; prf: Uint8Array }) {
  const me = await get<Mine>("/keys/me");
  const secret = await memberSecret(me, { code });
  const { bundle } = await openGrant(me, secret);
  if (passkey) await post("/keys/passkey-wrap", { passkey_id: passkey.passkeyId, wrapped: b64(await passkeyWrap(passkey.prf, secret)) });
  await remember(bundle, secret);
}

/// The team's raw secret, for a moment: inviting someone or rotating needs it.
async function rawBundle(passkeyId: string, prf: Uint8Array): Promise<Bundle> {
  const me = await get<Mine>("/keys/me");
  return (await openGrant(me, await memberSecret(me, { passkeyId, prf }))).bundle;
}

/// What an invitation carries: the team's secret wrapped by a key only its link holds. Returns
/// the sealed bundle (for the console) and the fragment (for the link only).
export async function inviteBundle(passkeyId: string, prf: Uint8Array): Promise<{ sealed: string; fragment: string }> {
  const fragmentKey = random(32);
  const sealed = await wrap(await derive(fragmentKey, "use05 invite v1"), bundleBytes(await rawBundle(passkeyId, prf)), INVITE_AAD);
  return { sealed: b64(sealed), fragment: b64url(fragmentKey) };
}

/// Let another of your passkeys unlock your key.
export async function wrapForPasskey(from: { passkeyId: string; prf: Uint8Array }, to: { passkeyId: string; prf: Uint8Array }) {
  const me = await get<Mine>("/keys/me");
  const secret = await memberSecret(me, from);
  await post("/keys/passkey-wrap", { passkey_id: to.passkeyId, wrapped: b64(await passkeyWrap(to.prf, secret)) });
}

/// A new recovery code, replacing the old one. Returns it to show once.
export async function replaceRecovery(passkeyId: string, prf: Uint8Array): Promise<string> {
  const me = await get<Mine>("/keys/me");
  const secret = await memberSecret(me, { passkeyId, prf });
  const recovery = newRecovery();
  await post("/keys/recovery", { wrapped: b64(await recoveryWrap(recovery.bytes, secret)) });
  return recovery.code;
}

/// Someone left: make the team a new key, sealed to each member who stays, with the old keys
/// inside so the team still reads what came before. The id key stays: repositories keep their ids.
/// Only members and machines whose pins check under the old key are carried over, pinned anew;
/// so a member key the console made up gets nothing. Machines keep sealing to the old key until
/// their owners confirm the new one.
export async function rotate(passkeyId: string, prf: Uint8Array): Promise<string[]> {
  const me = await get<Mine>("/keys/me");
  const secret = await memberSecret(me, { passkeyId, prf });
  const old = (await openGrant(me, secret)).bundle;
  const next: Bundle = { version: old.version + 1, secret: newSecret(), id: old.id, past: [...old.past, { version: old.version, secret: old.secret }] };
  const { members } = await get<{ members: { id: string; name: string; public: string; pin: string | null }[] }>("/keys/members");
  const unknown = [];
  for (const m of members) if (m.pin !== (await memberPin(old.secret, m.id, unb64(m.public)))) unknown.push(m.name);
  if (unknown.length) throw new Error(`The console lists a key for ${unknown.join(", ")} that you never vouched for. It may be tampered with: the key was not changed.`);
  // This browser also remembers each member's key from the last time: one that changed is refused.
  const known: Record<string, string> = JSON.parse(localStorage.getItem("use05-member-keys") ?? "{}");
  const changed = members.filter((m) => known[m.id] && known[m.id] !== m.public).map((m) => m.name);
  if (changed.length) throw new Error(`The key the console lists for ${changed.join(", ")} is not the one this browser saw before. It may be tampered with: the key was not changed.`);
  const grants = await Promise.all(members.map(async (m) => ({ member_id: m.id, sealed: b64(await seal(unb64(m.public), bundleBytes(next), GRANT_AAD)) })));
  const member_pins = await Promise.all(members.map(async (m) => ({ id: m.id, pin: await memberPin(next.secret, m.id, unb64(m.public)) })));
  const oldPins = await pinKey(old.secret);
  const newPins = await pinKey(next.secret);
  const { machines } = await get<{ machines: MachineRow[] }>("/overview");
  // Machines paired at a terminal take the new key; a token never does, so it is not pinned anew
  // and stops counting: its person makes a new one.
  const machine_pins = [];
  for (const m of machines) {
    if ((m.kind ?? "machine") !== "machine" || !m.x_pub || !m.ed_pub || m.pin !== (await machinePin(oldPins, m))) continue;
    machine_pins.push({ id: m.id, pin: await machinePin(newPins, m) });
  }
  // The base template moves to the new key; one the team did not vouch for is dropped.
  const { sealed: storedBase } = await get<{ sealed: string | null }>("/base");
  const baseText = await openBaseWith(await privateKey(old.secret), await publicOf(old.secret), oldPins, storedBase).catch(() => null);
  const base = baseText == null ? null : await sealBaseWith(await publicOf(next.secret), newPins, baseText);
  await post("/keys/rotate", { version: next.version, public: b64(await publicOf(next.secret)), grants, own: await ownCopy(secret, next), member_pins, machine_pins, base });
  await remember(next, secret);
  for (const m of members) known[m.id] = m.public;
  localStorage.setItem("use05-member-keys", JSON.stringify(known));
  return members.map((m) => m.name);
}

/// Whether someone was removed since the team's key last changed.
export async function rotateNeeded(): Promise<boolean> {
  return !!(await get<Mine>("/keys/me")).rotate_needed;
}

/// Your passkey's word to your machines: seal to the team's current key from now on. Each machine
/// checks the signature against the passkeys pinned on it; the console only relays it.
export async function confirmMachines(machines: { ed_pub: string }[]) {
  const u = await unlocked();
  if (!u) throw new Error("Unlock your console first.");
  const info = await get<{ rp_id: string; credentials: string[] }>("/keys/confirm-machines");
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [],
    predicateType: "https://use05.dev/team-key/v0",
    predicate: { machines: machines.map((m) => m.ed_pub), team_pub: b64(u.teamPub), version: u.version },
  };
  await post("/keys/confirm-machines", { envelope: await signOwn(statement, info.rp_id, info.credentials) });
}

// ------------------------------------------------------------------ the base template

const BASE_AAD = enc("use05 team base");

/// The base template as stored: sealed to the team, and vouched for under the team's pin key, which
/// the console (and anyone who left) cannot make. Anyone can seal to the team's public key.
export async function sealBaseWith(teamPub: Uint8Array, pins: CryptoKey, toml: string): Promise<string> {
  const sealed = b64(await seal(teamPub, enc(JSON.stringify({ toml })), BASE_AAD));
  return JSON.stringify({ sealed, mac: await pinWith(pins, "base", sealed) });
}

/// The template's text, if it opens and the team vouched for it; null if there is none; an error if forged.
export async function openBaseWith(team: CryptoKey, teamPub: Uint8Array, pins: CryptoKey, stored: string | null): Promise<string | null> {
  if (!stored) return null;
  const { sealed, mac } = JSON.parse(stored);
  if (mac !== (await pinWith(pins, "base", sealed))) throw new Error("The base policy was not saved by you. The console's server may be tampered with.");
  return JSON.parse(new TextDecoder().decode(await open(team, teamPub, unb64(sealed), BASE_AAD))).toml;
}

/// An admin's browser learns members' keys as it sees them (only keys the team vouched for), so a
/// key the console later changes is noticed at the next key change.
export async function noteMemberKeys() {
  const u = await unlocked();
  if (!u?.pinKey) return;
  const { members } = await get<{ members: { id: string; public: string; pin: string | null }[] }>("/keys/members");
  const known: Record<string, string> = JSON.parse(localStorage.getItem("use05-member-keys") ?? "{}");
  for (const m of members) {
    if (!known[m.id] && m.pin === (await pinWith(u.pinKey, "member", `${m.id}:${m.public}`))) known[m.id] = m.public;
  }
  localStorage.setItem("use05-member-keys", JSON.stringify(known));
}

/// A token for a cloud agent session or a CI job (D86): its own keys, made here and pinned by the
/// team, the team's naming key wrapped for it, and a bearer secret the console sees only as a
/// hash. Shown once; stored as a secret where the session or the job runs.
export async function makeReporter(kind: "session" | "ci", repo: string, name: string): Promise<string> {
  const u = await unlocked();
  if (!u?.pinKey) throw new Error("Unlock your console first.");
  const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  const x = newSecret();
  const xPub = await publicOf(x);
  const ed = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const edPub = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  // An Ed25519 key in PKCS#8 ends with its 32-byte seed.
  const seed = new Uint8Array(await crypto.subtle.exportKey("pkcs8", ed.privateKey)).slice(-32);
  const pin = await machinePin(u.pinKey, { x_pub: b64(xPub), ed_pub: b64(edPub), kind, repo_only: repo });
  const link = await linkKey(u.team, xPub, u.teamPub, xPub);
  const bearer = b64url(random(32));
  const tokenHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", enc(bearer))));
  await post("/reporters", { kind, repo, name, x_pub: b64(xPub), ed_pub: b64(edPub), pin, sealed_id_key: b64(await wrap(link, u.idKey, enc("use05 id key"))), token_hash: tokenHash, team_version: u.version });
  const person = (await get<any>("/me")).member?.name ?? "";
  const token = { v: 1, kind, url: window.location.origin, bearer, x: hex(x), ed: hex(seed), team: b64(u.teamPub), version: u.version, repo, name, person };
  return "u05_" + b64url(enc(JSON.stringify(token)));
}
