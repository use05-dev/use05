"""Run: python -m venv v && v/bin/pip install "securesystemslib[crypto]" && USE05_BIN=target/release/use05 v/bin/python tools/interop.py

Cross-check use05 receipts against securesystemslib, an independent DSSE implementation.

Direction 1: a receipt made by use05 must verify in securesystemslib.
Direction 2: an envelope signed by securesystemslib must verify in use05.
Negative controls: tampered or wrongly-keyed envelopes must fail in BOTH.
"""
import base64, json, os, subprocess, sys, tempfile, pathlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from securesystemslib.dsse import Envelope
from securesystemslib.signer import CryptoSigner, Key

U = os.environ.get("USE05_BIN", "target/release/use05")


def sh(args, cwd):
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def key_from_files(work, name):
    secret = pathlib.Path(work, name).read_text().strip().split(":", 1)[1]
    public = pathlib.Path(work, name + ".pub").read_text().strip().split(":", 1)[1]
    seed = base64.b64decode(secret)
    pub = base64.b64decode(public)
    return seed, pub


def ss_key(pub_raw, keyid):
    return Key.from_dict(keyid, {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": pub_raw.hex()}})


def ss_verifies(envelope_dict, pub_raw, keyid):
    try:
        # from_dict consumes (mutates) its input, so always hand it a copy.
        Envelope.from_dict(json.loads(json.dumps(envelope_dict))).verify([ss_key(pub_raw, keyid)], 1)
        return True
    except Exception as e:  # any failure to verify is a failure
        return False


work = tempfile.mkdtemp()
sh(["git", "init", "-q", "."], work)
sh(["git", "config", "user.email", "t@t"], work)
sh(["git", "config", "user.name", "t"], work)
pathlib.Path(work, "a.txt").write_text("hello\n")
sh(["git", "add", "-A"], work)

assert sh([U, "key", "new", "me.key"], work)[0] == 0
assert sh([U, "key", "new", "other.key"], work)[0] == 0
rc, out = sh([U, "prove", "--key", "me.key", "--out", "r.json", "--", "true"], work)
assert rc == 0, out

seed, pub = key_from_files(work, "me.key")
_, other_pub = key_from_files(work, "other.key")
receipt = json.loads(pathlib.Path(work, "r.json").read_text())
keyid = receipt["signatures"][0]["keyid"]
results = []


def check(name, ok, expected=True):
    status = "PASS" if ok == expected else "FAIL"
    results.append(status == "PASS")
    print(f"{status}  {name}")


# Direction 1: use05 -> securesystemslib
check("use05 receipt verifies in securesystemslib", ss_verifies(receipt, pub, keyid))
check("...and securesystemslib rejects it under a different key", ss_verifies(receipt, other_pub, keyid), expected=False)

tampered = json.loads(json.dumps(receipt))
raw = bytearray(base64.b64decode(tampered["payload"]))
raw[30] ^= 1
tampered["payload"] = base64.b64encode(bytes(raw)).decode()
check("securesystemslib rejects a payload-tampered use05 receipt", ss_verifies(tampered, pub, keyid), expected=False)
rc, _ = sh([U, "verify", "r.json", "--key", "me.key.pub"], work)
pathlib.Path(work, "t.json").write_text(json.dumps(tampered))
rc_t, _ = sh([U, "verify", "t.json", "--key", "me.key.pub"], work)
check("use05 agrees: the same tampered envelope is rejected (exit 2)", rc_t == 2)
check("use05 accepts the untampered one (exit 0)", rc == 0)

# Direction 2: securesystemslib -> use05, signing OUR statement bytes with THEIR signer
payload = base64.b64decode(receipt["payload"])
priv = Ed25519PrivateKey.from_private_bytes(seed)
signer = CryptoSigner(priv)
foreign = Envelope(payload, "application/vnd.in-toto+json", {})
foreign.sign(signer)
foreign_dict = foreign.to_dict()
# Their signer derives its own keyid; use05 ignores the hint, which is exactly the point.
check("securesystemslib's envelope verifies in securesystemslib (sanity)", ss_verifies(foreign_dict, pub, signer.public_key.keyid))
pathlib.Path(work, "foreign.json").write_text(json.dumps(foreign_dict))
rc_f, out_f = sh([U, "verify", "foreign.json", "--key", "me.key.pub"], work)
check("an envelope signed by securesystemslib verifies in use05 (exit 0)", rc_f == 0)
print("      use05 said:", out_f.splitlines()[0] if out_f else "(nothing)")

foreign_bad = json.loads(json.dumps(foreign_dict))
foreign_bad["payloadType"] = "application/vnd.in-toto+json "
pathlib.Path(work, "foreign_bad.json").write_text(json.dumps(foreign_bad))
rc_b, _ = sh([U, "verify", "foreign_bad.json", "--key", "me.key.pub"], work)
check("changing payloadType on their envelope is rejected by use05 (exit 2)", rc_b == 2)
check("...and by securesystemslib", ss_verifies(foreign_bad, pub, signer.public_key.keyid), expected=False)

# Unpadded / url-safe base64: DSSE says verifiers must accept both.
urlsafe = json.loads(json.dumps(receipt))
urlsafe["payload"] = base64.urlsafe_b64encode(payload).decode().rstrip("=")
urlsafe["signatures"][0]["sig"] = base64.urlsafe_b64encode(base64.b64decode(receipt["signatures"][0]["sig"])).decode().rstrip("=")
pathlib.Path(work, "urlsafe.json").write_text(json.dumps(urlsafe))
rc_u, _ = sh([U, "verify", "urlsafe.json", "--key", "me.key.pub"], work)
check("use05 accepts url-safe unpadded base64 as DSSE requires", rc_u == 0)

print()
print(f"{sum(results)}/{len(results)} interoperability checks passed")
sys.exit(0 if all(results) else 1)
