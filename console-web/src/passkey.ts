// Passkeys: sign in, add a passkey, and sign an approval. The private key never leaves the
// device; the browser only ever hands the console a signature.

const fromB64url = (s: string): Uint8Array<ArrayBuffer> => {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  const out = new Uint8Array(new ArrayBuffer(b.length));
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out;
};
const toB64 = (buf: ArrayBuffer | Uint8Array, url = false) => {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  bytes.forEach((b) => (s += String.fromCharCode(b)));
  const b64 = btoa(s);
  return url ? b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") : b64;
};

export const supported = () => typeof window !== "undefined" && !!window.PublicKeyCredential;

/// What every passkey here is asked for (WebAuthn PRF): a secret only it can reproduce, which
/// unlocks your key to the team's records. The salt is fixed, so the same passkey gives the same secret.
const PRF_SALT = (async () => new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("use05 member key v1"))))();

export const NO_PRF = "This passkey cannot keep your console's records private (it lacks the PRF feature). Use iCloud Keychain on iOS 18 or later, Google Password Manager, a recent Chrome, 1Password, or a YubiKey 5.";

function prfResult(cred: PublicKeyCredential): Uint8Array<ArrayBuffer> {
  const first = (cred.getClientExtensionResults() as any)?.prf?.results?.first as ArrayBuffer | undefined;
  if (!first) throw new Error(NO_PRF);
  return new Uint8Array(first.slice(0));
}

/// A passkey's PRF secret: one more tap, nothing sent to the console. `id` picks the passkey;
/// without it the person chooses one of theirs.
export async function prfOf(id?: string): Promise<{ id: string; prf: Uint8Array<ArrayBuffer> }> {
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: id ? [{ type: "public-key", id: fromB64url(id) }] : [],
      userVerification: "required",
      timeout: 120000,
      extensions: { prf: { eval: { first: await PRF_SALT } } } as any,
    },
  })) as PublicKeyCredential;
  return { id: cred.id, prf: prfResult(cred) };
}

export async function create(options: any) {
  const publicKey = {
    ...options,
    extensions: { prf: {} },
    challenge: fromB64url(options.challenge),
    user: { ...options.user, id: fromB64url(options.user.id) },
    excludeCredentials: (options.excludeCredentials ?? []).map((c: any) => ({ ...c, id: fromB64url(c.id) })),
  };
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential;
  const r = cred.response as AuthenticatorAttestationResponse;
  const spki = r.getPublicKey();
  if (!spki) throw new Error("This browser cannot report the passkey's public key. Use Safari 16, Chrome 85, Firefox 119 or newer.");
  return { id: cred.id, clientDataJSON: toB64(r.clientDataJSON, true), authenticatorData: toB64(r.getAuthenticatorData(), true), publicKey: toB64(spki, true) };
}

async function get(challenge: Uint8Array<ArrayBuffer>, rpId: string | undefined, ids: string[]) {
  const cred = (await navigator.credentials.get({
    publicKey: { challenge, rpId, allowCredentials: ids.map((id) => ({ type: "public-key" as const, id: fromB64url(id) })), userVerification: "required", timeout: 120000, extensions: { prf: { eval: { first: await PRF_SALT } } } as any },
  })) as PublicKeyCredential;
  return { cred, r: cred.response as AuthenticatorAssertionResponse };
}

/// Sign in, and with the same tap get the passkey's PRF secret (kept here, never sent).
export async function signIn(options: any) {
  const { cred, r } = await get(fromB64url(options.challenge), options.rpId, (options.allowCredentials ?? []).map((c: any) => c.id));
  const prf = (cred.getClientExtensionResults() as any)?.prf?.results?.first as ArrayBuffer | undefined;
  // Two halves: the assertion goes to the console; the PRF secret never does.
  return {
    credential: { id: cred.id, clientDataJSON: toB64(r.clientDataJSON, true), authenticatorData: toB64(r.authenticatorData, true), signature: toB64(r.signature, true) },
    prf: prf ? new Uint8Array(prf.slice(0)) : undefined,
  };
}

/// The DSSE pre-authentication encoding the challenge is the SHA-256 of.
async function statementChallenge(payloadType: string, payloadB64: string) {
  const body = Uint8Array.from(atob(payloadB64), (c) => c.charCodeAt(0));
  const type = new TextEncoder().encode(payloadType);
  const head = new TextEncoder().encode(`DSSEv1 ${type.length} ${payloadType} ${body.length} `);
  const pae = new Uint8Array(head.length + body.length);
  pae.set(head);
  pae.set(body, head.length);
  return toB64(await crypto.subtle.digest("SHA-256", pae), true);
}

type Unsigned = { payload: string; payload_type: string; challenge: string; cosignature?: { keyid?: string; sig: string } | null };

/// What the person asked to sign. The statement the machine hands back must be exactly that: the
/// machine and the console both pass it on, and a passkey signs whatever it is shown.
export type Want =
  | { type: "approval"; scope?: "intent" | "outcome"; tree?: string; task?: string; decision?: "approve" | "reject" }
  | { type: "testing"; tree: string; outcome: "tested" | "skipped"; note: string; task?: string }
  | { type: "discard"; task: string };

/// Read the statement itself and refuse anything but what the person asked for.
export function checkStatement(unsigned: Unsigned, want: Want) {
  let s: any = null;
  try {
    s = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(unsigned.payload), (c) => c.charCodeAt(0))));
  } catch {}
  const p = s?.predicate;
  const tree = s?.subject?.[0]?.digest?.gitTree;
  const ok =
    want.type === "discard"
      ? s?.predicateType === "https://use05.dev/discard/v0" && p?.task === want.task && s?.subject?.[0]?.name === "work" && s?.subject?.[0]?.digest?.task === want.task
      : want.type === "testing"
      ? s?.predicateType === "https://use05.dev/testing/v0" && tree === want.tree && p?.outcome === want.outcome && p?.note === want.note && (want.task === undefined || p?.task === want.task)
      : s?.predicateType === "https://use05.dev/approval/v0" && p?.decision === (want.decision ?? "approve") && (want.scope === undefined || p?.scope === want.scope) && (want.tree === undefined || tree === want.tree) && (want.task === undefined || p?.task === want.task);
  if (!ok) {
    throw new Error(
      want.type === "discard"
        ? "What the machine prepared is not a discard of this work. Nothing was signed; do not continue, and check the machine."
        : want.type === "testing"
          ? "What the machine prepared is not the sign-off you asked for. Nothing was signed; do not continue, and check the machine."
          : "What you would sign is not an approval of this work. Nothing was signed; do not continue, and check the machine.",
    );
  }
}

/// Sign the exact statement the machine prepared, once it is what the person asked for. The
/// challenge is the SHA-256 of the statement's DSSE encoding, so the signature covers the
/// statement and nothing else; it is checked here before the passkey is asked.
export async function signStatement(unsigned: Unsigned, want: Want, rpId: string, credentials: string[]) {
  checkStatement(unsigned, want);
  // The machine that prepared the statement signed it too; without that, a passkey's signature counts nowhere.
  if (!unsigned.cosignature?.sig) throw new Error("The machine did not co-sign this, so a passkey's signature on it would count nowhere. Its use05 may be older than 0.0.7, or it could not read its own key; check it, then ask again.");
  if ((await statementChallenge(unsigned.payload_type, unsigned.payload)) !== unsigned.challenge.replace(/=+$/, "")) {
    throw new Error("What you would sign is not the statement shown. Nothing was signed; tell the machine to prepare it again.");
  }
  const { r } = await get(fromB64url(unsigned.challenge), rpId, credentials);
  return {
    payload: unsigned.payload,
    payloadType: unsigned.payload_type,
    signatures: [unsigned.cosignature, { sig: toB64(r.signature), webauthn: { authenticatorData: toB64(r.authenticatorData), clientDataJSON: toB64(r.clientDataJSON) } }],
  };
}

/// Sign a statement of your own (no machine prepared it): the team's new key for your machines.
export async function signOwn(statement: unknown, rpId: string, credentials: string[]) {
  const payload = toB64(new TextEncoder().encode(JSON.stringify(statement)));
  const payloadType = "application/vnd.in-toto+json";
  const { r } = await get(fromB64url(await statementChallenge(payloadType, payload)), rpId, credentials);
  return { payload, payloadType, signatures: [{ sig: toB64(r.signature), webauthn: { authenticatorData: toB64(r.authenticatorData), clientDataJSON: toB64(r.clientDataJSON) } }] };
}

export function friendly(e: unknown): string {
  const name = (e as any)?.name;
  if (name === "NotAllowedError") return "The passkey prompt was closed or timed out. Nothing was signed.";
  if (name === "InvalidStateError") return "This passkey is already added.";
  return (e as Error)?.message ?? "Something went wrong.";
}
