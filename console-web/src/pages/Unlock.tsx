import { useState } from "react";
import { post } from "../api";
import { unlockWith, unlockWithRecovery, lock } from "../keys";
import { friendly, prfOf } from "../passkey";
import { RecoveryCode } from "./Recovery";

/// Signed in, but this browser does not hold your key yet (a new browser, or after signing out).
export function Unlock({ admin, onDone }: { admin: boolean; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(() => {
    const said = sessionStorage.getItem("use05-unlock-problem");
    sessionStorage.removeItem("use05-unlock-problem");
    return said;
  });
  const [byCode, setByCode] = useState(false);
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState<string | null>(null);
  if (recovery) return <RecoveryCode code={recovery} onDone={onDone} />;

  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setProblem(null);
    try {
      await work();
    } catch (e) {
      setProblem(friendly(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="gate-page">
      <div className="gate-card stack-lg">
        <div>
          <img className="logo" src="/logo.svg" alt="05" />
          <h1>Unlock your console</h1>
          <p className="muted" style={{ marginTop: 8 }}>What your machines report is encrypted; your passkey opens it in this browser until you sign out.</p>
        </div>
        {!byCode ? (
          <button className="btn primary" disabled={busy} onClick={() => run(async () => {
            const { id, prf } = await prfOf();
            const r = await unlockWith(id, prf, admin);
            if (r === "unlocked") onDone(); else setRecovery(r.recovery);
          })}>Unlock with passkey</button>
        ) : (
          <div className="panel stack">
            <label className="stack"><span className="small">Recovery code</span><input type="text" autoComplete="off" value={code} onChange={(e) => setCode(e.target.value)} /></label>
            <button className="btn primary" disabled={busy || !code.trim()} onClick={() => run(async () => { await unlockWithRecovery(code); onDone(); })}>Unlock</button>
          </div>
        )}
        <button className="btn quiet" onClick={() => setByCode(!byCode)}>{byCode ? "Use a passkey" : "Use my recovery code"}</button>
        {problem && <p className="error">{problem}</p>}
        <button className="btn quiet small" onClick={async () => { await lock(); await post("/auth/logout"); window.location.href = "/"; }}>Sign out</button>
      </div>
    </div>
  );
}
