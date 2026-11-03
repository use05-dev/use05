import { useEffect, useState } from "react";
import { get, post } from "../api";
import { setUpTeam, unlockWith } from "../keys";
import { create, friendly, prfOf, signIn, supported } from "../passkey";
import { RecoveryCode } from "./Recovery";

export function Gate({ setup, onDone }: { setup: boolean; onDone: () => void }) {
  // Claimed at a terminal (use05 cloud login): the one-time link carries it, in the fragment. The
  // link may be opened in a tab already showing the console, which changes only the fragment.
  const fromLink = () => new URLSearchParams(window.location.hash.slice(1)).get("claim");
  const [claimed, setClaimed] = useState(fromLink);
  const [secret, setSecret] = useState(claimed ?? "");
  useEffect(() => {
    const read = () => {
      const c = fromLink();
      if (c) {
        setClaimed(c);
        setSecret(c);
      }
    };
    window.addEventListener("hashchange", read);
    return () => window.removeEventListener("hashchange", read);
  }, []);
  const [person, setPerson] = useState("");
  const [name, setName] = useState(guessDevice());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recovery, setRecovery] = useState<string | null>(null);

  const run = async (work: () => Promise<boolean | void>) => {
    setBusy(true);
    setError(null);
    try {
      if ((await work()) === false) return;
      onDone();
    } catch (e) {
      setError(friendly(e));
    } finally {
      setBusy(false);
    }
  };

  const register = () =>
    run(async () => {
      const start = await post("/auth/register/start", { setup_secret: secret, name: person });
      const credential = await create(start.options);
      // The team's keys are made here, by this browser, opened by this passkey; one without PRF
      // stops here, before the console knows it.
      const { prf } = await prfOf(credential.id);
      await post("/auth/register/finish", { challenge_id: start.challenge_id, name, credential });
      setRecovery(await setUpTeam(credential.id, prf));
      if (claimed) history.replaceState(null, "", window.location.pathname);
      return false;
    });

  const login = () =>
    run(async () => {
      const start = await post("/auth/login/start");
      const { credential, prf } = await signIn(start.options);
      await post("/auth/login/finish", { challenge_id: start.challenge_id, credential });
      if (!prf) return;
      const me = await get("/me");
      // If this passkey cannot unlock here, the unlock page takes over and says why.
      const r = await unlockWith(credential.id, prf, me.member?.role === "admin").catch((e) => {
        sessionStorage.setItem("use05-unlock-problem", friendly(e));
        return "unlocked" as const;
      });
      if (r !== "unlocked") {
        setRecovery(r.recovery);
        return false;
      }
    });

  if (recovery) return <RecoveryCode code={recovery} onDone={onDone} />;
  return (
    <div className="gate-page">
      <div className="gate-card stack-lg">
        <div>
          <img className="logo" src="/logo.svg" alt="05" />
          <h1>{setup ? "Set up your console" : "Your 05 console"}</h1>
          <p className="muted" style={{ marginTop: 8 }}>
            {setup
              ? "Make the passkey that signs you in and signs your approvals. It stays on your device; the console only ever sees its signatures."
              : "Sign in with your passkey: Face ID, a fingerprint, or a security key."}
          </p>
        </div>
        {!supported() && <p className="error">This browser cannot use passkeys.</p>}
        {setup ? (
          <div className="panel stack">
            {claimed ? (
              <p className="small muted">Claimed from your terminal.</p>
            ) : (
              <label className="stack">
                <span className="small">Claim code (run <code>use05 cloud login {window.location.origin}</code> in a terminal, or copy it from the console's log)</span>
                <input type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} />
              </label>
            )}
            <label className="stack">
              <span className="small">Your name</span>
              <input type="text" autoComplete="name" value={person} onChange={(e) => setPerson(e.target.value)} />
            </label>
            <label className="stack">
              <span className="small">Name this passkey</span>
              <input type="text" value={name} onChange={(e) => setName(e.target.value)} />
            </label>
            <button className="btn primary" disabled={busy || !secret.trim() || !person.trim()} onClick={register}>Create passkey and sign in</button>
          </div>
        ) : (
          <button className="btn primary" style={{ width: "100%" }} disabled={busy} onClick={login}>Sign in with passkey</button>
        )}
        {error && <p className="error">{error}</p>}
        <p className="small muted">Only you, and anyone you invite, can sign in. There are no passwords.</p>
      </div>
    </div>
  );
}

function guessDevice() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return "iPhone";
  if (/iPad/.test(ua)) return "iPad";
  if (/Android/.test(ua)) return "Android phone";
  if (/Mac/.test(ua)) return "Mac";
  return "My passkey";
}
