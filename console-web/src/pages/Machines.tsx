import { useView } from "../records";
import { useState } from "react";
import { ago, post } from "../api";
import { makeReporter, wrapForPasskey } from "../keys";
import { create, friendly, prfOf, signIn } from "../passkey";
import { Crumbs, Link, Loading, Online, useData } from "../ui";
import { Pairing } from "./Home";

export function Machines() {
  const { data, error, reload } = useData<any>("/machines", 4000);
  const keys = useData<any>("/passkeys");
  const seen = useView<any>("/overview", 8000);
  const [name, setName] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  if (!data || !keys.data) return <Loading error={error ?? keys.error} />;

  const addPasskey = async () => {
    setProblem(null);
    try {
      // Confirm with a passkey you already have: a session alone cannot add one.
      const check = await post("/auth/recheck/start", {});
      const signed = await signIn(check.options);
      const proof = { challenge_id: check.challenge_id, credential: signed.credential };
      const start = await post("/auth/register/start", { proof });
      const credential = await create(start.options);
      await post("/auth/register/finish", { challenge_id: start.challenge_id, name: name || "Another passkey", credential });
      // The new passkey opens your key too, when the one you confirmed with can open it.
      try {
        if (!signed.prf) throw new Error("no PRF");
        const fresh = await prfOf(credential.id);
        await wrapForPasskey({ passkeyId: signed.credential.id, prf: signed.prf }, { passkeyId: credential.id, prf: fresh.prf });
      } catch {
        setProblem("The passkey is added. It cannot unlock your console yet: sign in with it once and unlock with your recovery code.");
      }
      setName("");
      keys.reload();
    } catch (e) {
      setProblem(friendly(e));
    }
  };

  return (
    <div className="stack-lg">
      <div className="hd"><div><Crumbs trail={[["Home", "/"], ["Machines and passkeys", null]]} /><h1>Machines and passkeys</h1><p className="muted">Machines report to the console. Passkeys sign you in and sign approvals.</p></div><Link to="/team" className="btn quiet">Team</Link></div>

      {data.pairings.map((p: any) => <Pairing key={p.id} p={p} done={reload} />)}

      {data.waiting.map((w: any) => (
        <div key={`${w.machine_id}-${w.repo_id}`} className="panel attention stack">
          <h2>Let “{w.machine}” report {w.repo}?</h2>
          <p className="small muted">Another machine already reports {w.repo}. Until you allow this one, it cannot send its tasks or ask you to approve anything there. Allow it only if it is your machine and has that repository checked out.</p>
          {data.admin ? <div className="row"><button className="btn" onClick={async () => { await post(`/machines/${w.machine_id}/repos/${w.repo_id}/allow`); reload(); }}>Allow</button></div> : <p className="small muted">An admin can allow it.</p>}
        </div>
      ))}

      <Reporters repos={seen.data?.repos ?? []} />

      <section>
        <div className="section-title"><h2>Machines</h2></div>
        <div className="list">
          {data.machines.length === 0 && <div className="item empty">None yet. Run <code>use05 cloud login {window.location.origin}</code> on your Mac.</div>}
          {data.machines.map((m: any) => (
            <div key={m.id} className="item">
              <Online on={m.online && !m.revoked} />
              <div className="grow">
                <div className="title">{m.name}{m.person && <span className="muted" style={{ fontWeight: 400 }}>, {m.person}'s</span>}{m.revoked && <span className="muted"> (revoked)</span>}</div>
                {m.stale && !m.revoked && <div className="sub">Made before your console's key changed, so the console refuses it. Make a new token and revoke this one.</div>}
                <div className="sub">{m.online ? "online" : `last heard ${ago(m.last_seen)}`}, {m.repos} repositor{m.repos === "1" || m.repos === 1 ? "y" : "ies"}{m.use05_version ? `, use05 ${m.use05_version}` : ""}</div>
              </div>
              {!m.revoked && m.yours && <button className="btn small danger" onClick={async () => { if (confirm(`Revoke ${m.name}${m.person ? `, ${m.person}'s` : ""} (${m.online ? "online now" : `last heard ${ago(m.last_seen)}`})? It stops reporting until paired again.`)) { await post(`/machines/${m.id}/revoke`); reload(); } }}>Revoke</button>}
            </div>
          ))}
        </div>
      </section>

      <section>
        <div className="section-title"><h2>Passkeys</h2></div>
        <div className="list">
          {keys.data.passkeys.map((k: any) => (
            <div key={k.id} className="item">
              <div className="grow">
                <div className="title">{k.name}{k.this_session && <span className="muted" style={{ fontWeight: 400 }}> (signed in with this one)</span>}</div>
                <div className="sub">key id <code>{k.key_id}</code>, added {ago(k.created_at)}, last used {ago(k.last_used)}</div>
              </div>
              {keys.data.passkeys.length > 1 && <button className="btn small quiet" onClick={async () => { if (confirm(`Remove ${k.name}? Approvals it signed stay valid; it can no longer sign in.`)) { await post(`/passkeys/${encodeURIComponent(k.id)}/delete`); keys.reload(); } }}>Remove</button>}
            </div>
          ))}
        </div>
        <div className="panel stack" style={{ marginTop: 12 }}>
          <h3>Add a passkey</h3>
          <p className="small muted">A second one is your way back in if a phone is lost: an Android phone, a security key, your Mac. Then pin it on each machine with <code>use05 cloud enrol</code>.</p>
          <div className="row"><input type="text" style={{ maxWidth: 260 }} placeholder="Name, e.g. YubiKey" value={name} onChange={(e) => setName(e.target.value)} /><button className="btn" onClick={addPasskey}>Add passkey</button></div>
          {problem && <p className="error">{problem}</p>}
        </div>
      </section>

      {(seen.data?.refusals ?? []).length > 0 && (
        <section>
          <div className="section-title"><h2>What machines refused</h2><Link to="/guide/security" className="small">What this means</Link></div>
          <div className="list">
            {seen.data.refusals.map((r: any, i: number) => (
              <div key={i} className="item"><div className="grow"><div className="title">{r.detail.what}</div><div className="sub">{r.actor.replace("machine:", "")}: {r.detail.why}, {ago(r.at)}</div></div></div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

/// Tokens for cloud agent sessions and CI (D86): they report as you, for one repository.
function Reporters({ repos }: { repos: any[] }) {
  const [repo, setRepo] = useState("");
  const [kind, setKind] = useState<"session" | "ci">("session");
  const [token, setToken] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const make = async () => {
    setProblem(null);
    try {
      // The console keeps only "Cloud session" or "CI": which repository is for this browser to say.
      setToken(await makeReporter(kind, repo, kind === "ci" ? "CI" : "Cloud session"));
    } catch (e) {
      setProblem(friendly(e));
    }
  };
  return (
    <section className="panel stack">
      <h2>Cloud sessions and CI</h2>
      <p className="small muted">A token lets a cloud agent session (Claude Code, Codex) or a CI job report here, as you, for one repository. It runs nothing it is sent. Store it as a secret where it runs: <code>USE05_SESSION</code> for a session, <code>USE05_CI</code> for CI. Anything the agent can read there, it can read too; what it reports shows as coming from that token.</p>
      <div className="row" style={{ flexWrap: "wrap" }}>
        <select value={repo} onChange={(e) => setRepo(e.target.value)} aria-label="Repository" style={{ maxWidth: 260 }}>
          <option value="">Repository…</option>
          {repos.map((r: any) => <option key={r.id} value={r.id}>{r.name}</option>)}
        </select>
        <select value={kind} onChange={(e) => setKind(e.target.value as "session" | "ci")} aria-label="For" style={{ maxWidth: 200 }}>
          <option value="session">A cloud session</option>
          <option value="ci">CI</option>
        </select>
        <button className="btn" disabled={!repo} onClick={make}>Make a token</button>
      </div>
      {token && <div className="note stack"><span>Shown once. Copy it now:</span><code className="recovery" data-reporter-token style={{ wordBreak: "break-all" }}>{token}</code></div>}
      {problem && <p className="error">{problem}</p>}
    </section>
  );
}
