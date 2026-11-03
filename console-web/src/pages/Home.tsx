import { useView } from "../records";
import { useEffect, useState } from "react";
import { ago, post } from "../api";
import { linkKey, pairCommit, pairingCode, random, wrap } from "../crypto";
import { machinePin } from "../opened";
import { b64, confirmMachines, unb64, unlocked } from "../keys";
import { friendly } from "../passkey";
import { Link, Loading, Online, Verdict } from "../ui";

/// Someone left and the team's key changed; these machines of yours still seal to the old one.
function OldKey({ machines, reload }: { machines: any[]; reload: () => void }) {
  const [busy, setBusy] = useState(false);
  const [said, setSaid] = useState<string | null>(null);
  const confirm = async () => {
    setBusy(true);
    setSaid(null);
    try {
      await confirmMachines(machines);
      setSaid("Sent. Each machine takes the new key when it next hears from the console.");
      reload();
    } catch (e) {
      setSaid(friendly(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="panel attention">
      <h2>Your machines still use your console's old key</h2>
      <p className="muted">Someone you had invited was removed, so your console has a new key. {machines.map((m) => m.name).join(", ")} will keep sealing to the old one, which they could still open, until you confirm with your passkey.</p>
      <div className="row" style={{ marginTop: 12 }}>
        <button className="btn primary" disabled={busy} onClick={confirm}>Confirm the new key</button>
      </div>
      {said && <p className="small" style={{ marginTop: 8 }}>{said}</p>}
    </section>
  );
}

export function Home() {
  const { data, error, reload } = useView<any>("/overview", 6000);
  if (!data) return <Loading error={error} />;
  const waiting = data.approvals.filter((a: any) => a.status === "waiting" && a.mine !== false);
  // Signed and on its way, or waiting for a teammate: shown, but not yours to act on.
  const inFlight = data.approvals.filter((a: any) => a.status !== "waiting" || a.mine === false);
  const edits = data.edits;
  const held: any[] = data.held ?? [];
  const nothing = !waiting.length && !held.length && !inFlight.length && !edits.length && !data.pairings.length && !data.refusals.length;
  const active = data.tasks.filter((t: any) => t.status === "active");
  const online = data.machines.filter((m: any) => m.online).length;

  return (
    <div className="stack-lg">
      {data.old_key?.length > 0 && <OldKey machines={data.old_key} reload={reload} />}
      {data.unverified > 0 && <p className="error">{data.unverified} record{data.unverified === 1 ? "" : "s"} could not be verified and {data.unverified === 1 ? "is" : "are"} not shown. A machine you did not pair, something changed them on the way, or the console sent an older copy of something you have seen.</p>}
      <div className="hd">
        <div>
          <h1>{data.needs_you ? `${data.needs_you} need${data.needs_you === 1 ? "s" : ""} you` : "Nothing needs you"}</h1>
          <p className="muted">
            {data.machines.length === 0 ? "No machine is paired yet." : `${online} of ${data.machines.length} machine${data.machines.length === 1 ? "" : "s"} online`}
            {active.length > 0 && `, ${active.length} agent task${active.length === 1 ? "" : "s"} working`}
          </p>
        </div>
      </div>

      {data.machines.length === 0 && (
        <div className="panel stack">
          <h2>Connect your first machine</h2>
          <p className="muted">On your Mac, in a repository that uses 05:</p>
          <pre className="toml">use05 cloud login {window.location.origin}</pre>
          <p className="small muted">The terminal shows a word to type here, then a code to compare. <Link to="/guide/setup">The guide</Link> walks through every step.</p>
        </div>
      )}

      {data.pairings.map((p: any) => <Pairing key={p.id} p={p} done={reload} />)}

      {waiting.map((a: any) => (
        <Link key={a.id} to={`/tasks/${a.repo_id}/${a.task_id}`} className="panel attention" style={{ display: "block", color: "inherit", textDecoration: "none" }}>
          <div className="row between">
            <span className="verdict v-approval_required">{a.scope === "intent" ? "Approve the plan" : "Approve the change"}</span>
            <span className="small muted">{ago(a.created_at)}</span>
          </div>
          <h2 style={{ marginTop: 10 }}>{a.title || `Task ${a.task_id}`}</h2>
          <p className="muted small" style={{ marginTop: 4 }}>{a.repo}</p>
        </Link>
      ))}

      {held.map((t: any) => (
        <Link key={`${t.repo_id}/${t.id}`} to={`/tasks/${t.repo_id}/${t.id}`} className="panel attention" style={{ display: "block", color: "inherit", textDecoration: "none" }}>
          <div className="row between">
            <span className="verdict v-approval_required">Held for you</span>
            <span className="small muted">{ago(t.updated_at)}</span>
          </div>
          <h2 style={{ marginTop: 10 }}>{t.title || `Task ${t.id}`}</h2>
          <p className="muted small" style={{ marginTop: 4 }}>{t.repo} on {t.machine ?? "a machine"}: it cannot go on until you approve it or discard it{t.abandoned ? "; it looks abandoned" : ""}.</p>
        </Link>
      ))}

      {inFlight.map((a: any) => (
        <div key={a.id} className="panel">
          <div className="row between">
            <strong>{a.title || a.task_id}</strong>
            <span className="small muted">{a.status === "waiting" ? `Waiting for ${a.driver}` : a.status === "signed" ? "Signed; waiting for the machine to file it" : "The machine could not file it"}</span>
          </div>
        </div>
      ))}

      {edits.map((e: any) => (
        <Link key={e.id} to={`/edits/${e.id}`} className={`panel${e.status === "stuck" || e.status === "ready" ? " attention" : ""}`} style={{ display: "block", color: "inherit", textDecoration: "none" }}>
          <strong>Policy edit for {e.repo}</strong>
          <p className="small muted" style={{ marginTop: 4 }}>{EDIT_WORDS[e.status] ?? e.status}{e.reason ? `: ${e.reason}` : ""}</p>
        </Link>
      ))}

      {data.refusals.map((r: any, i: number) => (
        <div key={i} className="panel attention">
          <strong>{r.actor.replace("machine:", "")} refused a request from the console</strong>
          <p className="small" style={{ marginTop: 4 }}>{r.detail.what}: {r.detail.why}</p>
          <p className="small muted" style={{ marginTop: 4 }}>{ago(r.at)}. If you did not ask for this, see <Link to="/guide/security">what a refusal means</Link>.</p>
        </div>
      ))}

      {nothing && data.machines.length > 0 && <p className="muted">When an agent waits for your approval it shows up here, and you get an email.</p>}

      <div>
        <div className="section-title"><h2>Recent work</h2><Link to="/activity" className="small">Everything that happened</Link></div>
        {data.tasks.length === 0 ? (
          <div className="list"><div className="item empty">No tasks yet. They appear when an agent declares a plan with use05 start.</div></div>
        ) : (
          <div className="list">
            {data.tasks.slice(0, 12).map((t: any) => (
              <Link key={`${t.repo_id}/${t.id}`} to={`/tasks/${t.repo_id}/${t.id}`} className="item">
                <div className="grow">
                  <div className="title">{t.title || `Task ${t.id}`}</div>
                  <div className="sub">{t.repo} on {t.machine ?? "a machine"}, {t.agent ?? "a person"}{t.model ? ` (${t.model})` : ""}, {ago(t.updated_at)}{t.abandoned ? ", looks abandoned" : ""}</div>
                </div>
                <Verdict decision={t.decision} />
              </Link>
            ))}
          </div>
        )}
      </div>

      {data.machines.length > 0 && (
        <div>
          <div className="section-title"><h2>Machines</h2><Link to="/machines" className="small">Manage</Link></div>
          <div className="list">
            {data.machines.map((m: any) => (
              <div key={m.id} className="item">
                <Online on={m.online} />
                <div className="grow"><div className="title">{m.name}</div><div className="sub">{m.online ? "online" : `last heard ${ago(m.last_seen)}`}{m.use05_version ? `, use05 ${m.use05_version}` : ""}</div></div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export const EDIT_WORDS: Record<string, string> = {
  waiting: "Waiting for a machine",
  preparing: "Being prepared on your machine",
  ready: "Ready for your passkey",
  signed: "Signed; being applied",
  applied: "Applied",
  stuck: "Stuck",
  cancelled: "Cancelled",
};

export function Pairing({ p, done }: { p: any; done: () => void }) {
  const [word, setWord] = useState("");
  const [code, setCode] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  // What this browser saw before it sent its nonce: the machine's commitment. Kept for this tab.
  const mineKey = `use05-pairing-${p.id}`;
  const held = JSON.parse(sessionStorage.getItem(mineKey) ?? "null") as { commit: string; nonce: string } | null;

  useEffect(() => {
    if (!held || !p.mine || !p.machine_nonce || code) return;
    (async () => {
      const keys = await unlocked();
      if (!keys) return setProblem("Unlock your console first.");
      // The machine revealed its keys: they must be what it committed to before it saw our nonce.
      const reveal = await pairCommit(unb64(p.x_pub), unb64(p.ed_pub), unb64(p.machine_nonce));
      if (b64(reveal) !== held.commit) return setProblem("The machine's keys are not what it committed to: this console may be tampered with. Do not pair.");
      setCode(await pairingCode(keys.teamPub, keys.version, unb64(p.x_pub), unb64(p.ed_pub), unb64(p.machine_nonce), unb64(held.nonce)));
    })().catch((e) => setProblem((e as Error).message));
  }, [p.machine_nonce, p.mine]);

  const act = async (what: "claim" | "approve" | "deny") => {
    setProblem(null);
    try {
      if (what === "deny") {
        await post(`/pairings/${p.id}/deny`);
        return done();
      }
      if (what === "claim") {
        const nonce = random(16);
        sessionStorage.setItem(mineKey, JSON.stringify({ commit: p.commit_hash, nonce: b64(nonce) }));
        await post(`/pairings/${p.id}/claim`, { word, nonce: b64(nonce) });
        return done();
      }
      const keys = await unlocked();
      if (!keys?.pinKey) throw new Error("Unlock your console first.");
      const pin = await machinePin(keys.pinKey, { x_pub: p.x_pub, ed_pub: p.ed_pub });
      // The team's id key, wrapped under a key only the team and this machine can make.
      const link = await linkKey(keys.team, unb64(p.x_pub), keys.teamPub, unb64(p.x_pub));
      const sealedIdKey = b64(await wrap(link, keys.idKey, new TextEncoder().encode("use05 id key")));
      await post(`/pairings/${p.id}/approve`, { pin, sealed_id_key: sealedIdKey, team_version: keys.version });
      sessionStorage.removeItem(mineKey);
      done();
    } catch (e) {
      setProblem((e as Error).message);
    }
  };

  if (p.claimed && !p.mine) {
    return (
      <div className="panel stack">
        <h2>Someone is pairing “{p.machine_name}”</h2>
        <p className="small muted">Whoever typed the word on that machine's terminal is pairing it. If that was not you, deny it.</p>
        <div className="row"><button className="btn quiet" onClick={() => act("deny")}>Deny</button></div>
        {problem && <p className="error">{problem}</p>}
      </div>
    );
  }
  return (
    <div className="panel attention stack">
      <h2>Pair “{p.machine_name}”?</h2>
      {!p.mine && (
        <>
          <p className="small muted">Type the word your terminal shows. The machine becomes yours: only you approve the work done on it. A paired machine can report activity and file approvals you sign; it can never approve for you.</p>
          <label className="stack"><span className="small">Word on your terminal</span><input type="text" autoComplete="off" autoCapitalize="characters" style={{ maxWidth: 200 }} value={word} onChange={(e) => setWord(e.target.value)} /></label>
          <div className="row"><button className="btn primary" disabled={!word.trim()} onClick={() => act("claim")}>Continue</button><button className="btn quiet" onClick={() => act("deny")}>Deny</button></div>
        </>
      )}
      {p.mine && !code && !problem && <p className="small muted">Waiting for the machine to show its code…</p>}
      {p.mine && !code && <div className="row"><button className="btn quiet" onClick={() => act("deny")}>Deny</button></div>}
      {p.mine && code && (
        <>
          <p className="small muted">Your terminal now shows a code. Pair only if it is this one.</p>
          <code className="recovery" data-pairing-code>{code}</code>
          <div className="row"><button className="btn primary" onClick={() => act("approve")}>It matches: pair this machine</button><button className="btn quiet" onClick={() => act("deny")}>Deny</button></div>
        </>
      )}
      {p.mine && !held && <p className="error">This browser did not start this pairing. Deny it and pair again from here.</p>}
      {problem && <p className="error">{problem}</p>}
    </div>
  );
}
