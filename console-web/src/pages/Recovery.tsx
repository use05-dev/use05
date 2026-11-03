import { useState } from "react";

/// A recovery code, shown once. Without it and every passkey, nobody can open your key again.
export function RecoveryCode({ code, onDone }: { code: string; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  return (
    <div className="gate-page">
      <div className="gate-card stack-lg">
        <div>
          <img className="logo" src="/logo.svg" alt="05" />
          <h1>Your recovery code</h1>
          <p className="muted" style={{ marginTop: 8 }}>Your console's records are encrypted: only your passkeys, and this code, can open them. Keep the code somewhere safe, apart from your devices. It is shown once. If you lose every passkey and this code, nobody can open them again, not even the server.</p>
        </div>
        <div className="panel"><code className="recovery" data-recovery-code>{code}</code></div>
        <label className="row"><input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} /> <span>I saved it</span></label>
        <button className="btn primary" disabled={!saved} onClick={onDone}>Continue</button>
      </div>
    </div>
  );
}
