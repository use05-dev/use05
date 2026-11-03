// Sealing in the browser, the same as the helper's (crates/cloud/src/seal.rs), with WebCrypto
// only. What machines send can be read only by the team; what the team sends a machine only by
// that machine. One format, versioned by its first byte.
//
//   seal: 0x01 ‖ ephemeral X25519 public (32) ‖ nonce (12) ‖ AES-256-GCM(key, nonce, plaintext, aad)
//         key = HKDF-SHA256(X25519(eph, recipient), salt = eph_pub ‖ recipient_pub, "use05 seal v1")
//   wrap: 0x01 ‖ nonce (12) ‖ AES-256-GCM(key, nonce, plaintext, aad)

type Bytes = Uint8Array<ArrayBuffer>;

const subtle = globalThis.crypto.subtle;
const V1 = 1;
const enc = (s: string) => new TextEncoder().encode(s) as Bytes;

const bytes = (b: ArrayBuffer | Uint8Array): Bytes => {
  const out = new Uint8Array(new ArrayBuffer(b.byteLength));
  out.set(b instanceof Uint8Array ? b : new Uint8Array(b));
  return out;
};

const concat = (...parts: Uint8Array[]): Bytes => {
  const out = new Uint8Array(new ArrayBuffer(parts.reduce((n, p) => n + p.length, 0)));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};

export const random = (n: number): Bytes => globalThis.crypto.getRandomValues(new Uint8Array(new ArrayBuffer(n)));

// An X25519 private key in PKCS#8: this fixed prefix, then the 32 secret bytes.
const PKCS8_X25519 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);

/// A usable private key from 32 secret bytes. Not extractable: once imported, script cannot read it back.
export async function privateKey(secret: Uint8Array, extractable = false): Promise<CryptoKey> {
  return subtle.importKey("pkcs8", concat(PKCS8_X25519, secret), { name: "X25519" }, extractable, ["deriveBits"]);
}

export async function publicOf(secret: Uint8Array): Promise<Bytes> {
  const jwk = await subtle.exportKey("jwk", await privateKey(secret, true));
  return fromB64url(jwk.x!);
}

export function newSecret(): Bytes {
  return random(32);
}

const fromB64url = (s: string): Bytes => {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return bytes(Uint8Array.from(b, (c) => c.charCodeAt(0)));
};

async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: string): Promise<Bytes> {
  const key = await subtle.importKey("raw", bytes(ikm), "HKDF", false, ["deriveBits"]);
  return bytes(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: bytes(salt), info: enc(info) }, key, 256));
}

/// 32 bytes from input key material, for one purpose.
export function derive(ikm: Uint8Array, info: string): Promise<Bytes> {
  return hkdf(ikm, new Uint8Array(32), info);
}

const aes = (key: Uint8Array, usage: KeyUsage) => subtle.importKey("raw", bytes(key), "AES-GCM", false, [usage]);

async function sharedWith(secret: CryptoKey, peer: Uint8Array): Promise<Bytes> {
  const pub = await subtle.importKey("raw", bytes(peer), { name: "X25519" }, true, []);
  return bytes(await subtle.deriveBits({ name: "X25519", public: pub }, secret, 256));
}

/// Seal for the holder of `recipient`'s secret.
export async function seal(recipient: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<Bytes> {
  const eph = (await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const ephPub = bytes(await subtle.exportKey("raw", eph.publicKey));
  const key = await hkdf(await sharedWith(eph.privateKey, recipient), concat(ephPub, recipient), "use05 seal v1");
  const nonce = random(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: bytes(aad) }, await aes(key, "encrypt"), bytes(plaintext));
  return concat(Uint8Array.of(V1), ephPub, nonce, new Uint8Array(ct));
}

/// Open what was sealed to `recipientPub`, with its private key.
export async function open(secret: CryptoKey, recipientPub: Uint8Array, sealed: Uint8Array, aad: Uint8Array): Promise<Bytes> {
  if (sealed.length < 1 + 32 + 12 + 16 || sealed[0] !== V1) throw new Error("malformed");
  const ephPub = sealed.slice(1, 33);
  const key = await hkdf(await sharedWith(secret, ephPub), concat(ephPub, recipientPub), "use05 seal v1");
  return bytes(await subtle.decrypt({ name: "AES-GCM", iv: sealed.slice(33, 45), additionalData: bytes(aad) }, await aes(key, "decrypt"), sealed.slice(45)));
}

/// Encrypt with a key both sides hold.
export async function wrap(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<Bytes> {
  const nonce = random(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: bytes(aad) }, await aes(key, "encrypt"), bytes(plaintext));
  return concat(Uint8Array.of(V1), nonce, new Uint8Array(ct));
}

export async function unwrap(key: Uint8Array, wrapped: Uint8Array, aad: Uint8Array): Promise<Bytes> {
  if (wrapped.length < 1 + 12 + 16 || wrapped[0] !== V1) throw new Error("malformed");
  return bytes(await subtle.decrypt({ name: "AES-GCM", iv: wrapped.slice(1, 13), additionalData: bytes(aad) }, await aes(key, "decrypt"), wrapped.slice(13)));
}

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

const codeOf = (d: Uint8Array) => {
  const bits = (((d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3]) >>> 2) >>> 0;
  const c = Array.from({ length: 6 }, (_, i) => ALPHABET[(bits >>> (25 - 5 * i)) & 31]);
  return `${c.slice(0, 3).join("")}-${c.slice(3).join("")}`;
};

/// What the machine committed to before it saw this browser's nonce (crates/cloud/src/seal.rs).
export async function pairCommit(xPub: Uint8Array, edPub: Uint8Array, machineNonce: Uint8Array): Promise<Bytes> {
  return bytes(await subtle.digest("SHA-256", concat(enc("use05 pair commit v1"), xPub, edPub, machineNonce)));
}

/// The code a person compares at pairing, worked out here from the keys the console relayed, the
/// team's version, and both nonces. The terminal works out its own; a console that swapped a key
/// or the version cannot make the two agree.
export async function pairingCode(teamPub: Uint8Array, version: number, xPub: Uint8Array, edPub: Uint8Array, machineNonce: Uint8Array, browserNonce: Uint8Array): Promise<string> {
  const v = new Uint8Array(4);
  new DataView(v.buffer).setUint32(0, version);
  return codeOf(new Uint8Array(await subtle.digest("SHA-256", concat(enc("use05 pair v2"), teamPub, v, xPub, edPub, machineNonce, browserNonce))));
}

/// A key the team and one machine share (X25519 of the team's secret and the machine's public key):
/// what the team sends under it is known to come from the team.
export async function linkKey(secret: CryptoKey, peer: Uint8Array, teamPub: Uint8Array, xPub: Uint8Array): Promise<Bytes> {
  return hkdf(await sharedWith(secret, peer), concat(teamPub, xPub), "use05 link v1");
}

/// A reference the server can route by but not read: HMAC of a name under the team's id key.
export async function hmacRef(idKey: Uint8Array, what: string, value: string): Promise<string> {
  const key = await subtle.importKey("raw", bytes(idKey), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await subtle.sign("HMAC", key, concat(enc(what), Uint8Array.of(0), enc(value))));
  return Array.from(mac.slice(0, 16), (b) => b.toString(16).padStart(2, "0")).join("");
}

/// A key for pinning (HMAC), from 32 secret bytes. Not extractable.
export async function pinKey(secret: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey("raw", bytes(await derive(secret, "use05 pin v1")), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

/// A pin: what the team vouches for (a machine's keys, a member's key), under its pin key.
export async function pinWith(key: CryptoKey, what: string, value: string): Promise<string> {
  const mac = new Uint8Array(await subtle.sign("HMAC", key, concat(enc(what), Uint8Array.of(0), enc(value))));
  return Array.from(mac.slice(0, 16), (b) => b.toString(16).padStart(2, "0")).join("");
}
