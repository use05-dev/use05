import { useState } from "react";
import { ago, post } from "../api";
import { Link, Loading, useData } from "../ui";
import { lock, replaceRecovery } from "../keys";
import { friendly, prfOf } from "../passkey";

export function Settings() {
  const { data, error, reload } = useData<any>("/settings");
  const me = useData<any>("/me");
  const [sent, setSent] = useState(false);
  const [name, setName] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [email, setEmail] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [newCode, setNewCode] = useState<string | null>(null);
  if (!data || !me.data) return <Loading error={error ?? me.error} />;
  const current = name ?? me.data.member?.name ?? "";
  return (
    <div className="stack-lg">
      <div className="hd"><div><h1>Settings</h1></div><Link to="/team" className="btn quiet">Team</Link></div>
      <section className="panel stack">
        <h2>You</h2>
        <p className="small muted">Your work is recorded under your name in git (<code>git config user.name</code>). Use the same name here, so approvals from your phone match your own sessions in CI.</p>
        <div className="row">
          <input type="text" style={{ maxWidth: 300 }} aria-label="Your name" value={current} onChange={(e) => { setName(e.target.value); setSaved(false); }} />
          <button className="btn quiet" disabled={!current.trim()} onClick={async () => { await post("/me/name", { name: current }); setSaved(true); me.reload(); }}>Save name</button>
          {saved && <span className="small muted">Saved.</span>}
        </div>
      </section>
      <section className="panel stack">
        <h2>Email</h2>
        {!data.email && <p className="muted">Email is off for this console. Whoever hosts it sets <code>CLOUDFLARE_ACCOUNT_ID</code> and <code>CLOUDFLARE_API_TOKEN</code>, or <code>SMTP_URL</code>. Until then alerts show on Home only. <Link to="/guide/email">How</Link></p>}
        {data.my_email && data.verified && <p>Alerts go to <strong>{data.my_email}</strong>: an approval of your work waiting, your policy edit stuck, your machine refusing a request. Nothing else.</p>}
        {data.my_email && !data.verified && <p className="note">Not confirmed yet. Open the link sent to <strong>{data.my_email}</strong>; nothing else goes there until you do.</p>}
        <div className="row">
          <input type="email" style={{ maxWidth: 300 }} aria-label="Your email" placeholder="you@example.com" value={email ?? data.my_email ?? ""} onChange={(e) => setEmail(e.target.value)} />
          <button className="btn quiet" disabled={!(email ?? "").trim()} onClick={async () => { setProblem(null); try { await post("/me/email", { email }); setEmail(null); reload(); } catch (e) { setProblem((e as Error).message); } }}>Send confirmation</button>
        </div>
        {problem && <p className="error">{problem}</p>}
        {data.verified && <div className="row"><button className="btn quiet" onClick={async () => { await post("/settings/test-email"); setSent(true); setTimeout(reload, 6000); }}>Send a test email</button>{sent && <span className="small muted">Queued.</span>}</div>}
        {data.alerts.length > 0 && (
          <div className="list">
            {data.alerts.map((a: any, i: number) => <div key={i} className="item"><div className="grow"><div className="title">{a.subject}</div><div className="sub">{a.sent ? "sent" : a.error ?? "waiting"}, {ago(a.at)}</div></div></div>)}
          </div>
        )}
      </section>
      <section className="panel stack">
        <h2>This console</h2>
        <dl className="kv"><dt>Address</dt><dd>{data.origin}</dd><dt>Passkeys belong to</dt><dd>{data.rp_id}</dd></dl>
        <p className="small muted">Passkeys are tied to this address. Moving the console to another domain means adding passkeys again.</p>
      </section>
      <section className="panel stack">
        <h2>Recovery code</h2>
        <p className="small muted">Your recovery code opens your console's records when the passkey you signed in with cannot. Signing in always takes a passkey, so keep a second one under Machines. Making a new code replaces the old.</p>
        {newCode ? <div className="note stack"><span>Your new recovery code, shown once:</span><code className="recovery" data-recovery-code>{newCode}</code></div> : <div><button className="btn quiet" onClick={async () => { setProblem(null); try { const { id, prf } = await prfOf(); setNewCode(await replaceRecovery(id, prf)); } catch (e) { setProblem(friendly(e)); } }}>Make a new recovery code</button></div>}
      </section>
      <button className="btn quiet" onClick={async () => { await lock(); await post("/auth/logout"); window.location.href = "/"; }}>Sign out</button>
    </div>
  );
}
