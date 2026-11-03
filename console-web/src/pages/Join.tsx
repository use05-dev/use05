import { useEffect, useState } from "react";
import { get, post } from "../api";
import { joinTeam } from "../keys";
import { create, friendly, prfOf, supported } from "../passkey";
import { go } from "../ui";
import { RecoveryCode } from "./Recovery";

export function Join({ token, onDone }: { token: string; onDone: () => void }) {
  const [who, setWho] = useState<string | null>(null);
  const [bundle, setBundle] = useState<string | null>(null);
  const [recovery, setRecovery] = useState<string | null>(null);
  const fragment = typeof window !== "undefined" ? window.location.hash.slice(1) : "";
  const [problem, setProblem] = useState<string | null>(null);
  const [device, setDevice] = useState("My passkey");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    get(`/join/${token}`).then((r) => { setWho(r.name); setBundle(r.sealed_bundle); }).catch((e) => setProblem(e.message));
  }, [token]);

  const join = async () => {
    setBusy(true);
    setProblem(null);
    try {
      const start = await post("/auth/register/start", { invite: token });
      if (!bundle || !fragment) throw new Error("This link is incomplete: it lacks the part that carries the console's key. Ask for a new one, and open it whole.");
      const credential = await create(start.options);
      // Before the console knows this passkey: a passkey without PRF cannot hold the key.
      const { prf } = await prfOf(credential.id);
      await post("/auth/register/finish", { challenge_id: start.challenge_id, name: device, credential });
      setRecovery(await joinTeam(credential.id, prf, bundle, fragment));
    } catch (e) {
      setProblem(friendly(e));
    } finally {
      setBusy(false);
    }
  };

  if (recovery) return <RecoveryCode code={recovery} onDone={() => { go("/"); onDone(); }} />;
  return (
    <div className="gate-page">
      <div className="gate-card stack-lg">
        <div>
          <img className="logo" src="/logo.svg" alt="05" />
          <h1>{who ? `Join as ${who}` : "Join this console"}</h1>
          <p className="muted" style={{ marginTop: 8 }}>Make the passkey that signs you in and signs your approvals. It stays on your device; the console only ever sees its signatures.</p>
        </div>
        {!supported() && <p className="error">This browser cannot use passkeys.</p>}
        {who && (
          <div className="panel stack">
            <label className="stack">
              <span className="small">Name this passkey</span>
              <input type="text" value={device} onChange={(e) => setDevice(e.target.value)} />
            </label>
            <button className="btn primary" disabled={busy} onClick={join}>Create passkey and join</button>
          </div>
        )}
        {problem && <p className="error">{problem}</p>}
      </div>
    </div>
  );
}
