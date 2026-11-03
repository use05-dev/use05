import { useView } from "../records";
import { useEffect, useState, type ReactNode } from "react";
import { post } from "../api";
import { linkKey, pairCommit, pairingCode, random, wrap } from "../crypto";
import { machinePin } from "../opened";
import { b64, confirmMachines, unb64, unlocked } from "../keys";
import { friendly } from "../passkey";
import { Link, Loading, Online, Verdict, When } from "../ui";

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

/// One row of the pane: what it is, where, who, and when it really happened.
function Row({ to, chip, title, sub, at, attention }: { to: string; chip: ReactNode; title: string; sub: string; at?: string | null; attention?: boolean }) {
  return (
    <Link to={to} className={`item${attention ? " attention-row" : ""}`}>
      <div className="grow"><div className="title">{title}</div><div className="sub">{sub}</div></div>
      {chip}
      <When at={at} />
    </Link>
  );
}

const who = (t: any) => `${t.agent ?? "a person"}${t.model ? ` (${t.model})` : ""}`;

export function Home() {
  const { data, error, reload } = useView<any>("/overview", 6000);
  if (!data) return <Loading error={error} />;
  const waiting = data.approvals.filter((a: any) => a.status === "waiting" && a.mine !== false);
  // Signed and on its way, or waiting for a teammate: shown, but not yours to act on.
  const inFlight = data.approvals.filter((a: any) => a.status !== "waiting" || a.mine === false);
  const edits = data.edits;
  const held: any[] = data.held ?? [];
  const heldIds = new Set(held.map((t: any) => `${t.repo_id}/${t.id}`));
  const askedIds = new Set(waiting.map((a: any) => `${a.repo_id}/${a.task_id}`));
  const others = data.tasks.filter((t: any) => !heldIds.has(`${t.repo_id}/${t.id}`) && !askedIds.has(`${t.repo_id}/${t.id}`));
  const working = others.filter((t: any) => t.status === "active" && !t.landed);
  const finished = others.filter((t: any) => !(t.status === "active" && !t.landed));
  const online = data.machines.filter((m: any) => m.online).length;
  const needsAny = waiting.length > 0 || held.length > 0 || edits.some((e: any) => e.status === "ready" || e.status === "stuck") || data.refusals.length > 0;
  const perRepo = (id: string) => ({
    needs: waiting.filter((a: any) => a.repo_id === id).length + held.filter((t: any) => t.repo_id === id).length,
    working: working.filter((t: any) => t.repo_id === id).length,
  });

  return (
    <div className="pane">
      {data.old_key?.length > 0 && <OldKey machines={data.old_key} reload={reload} />}
      {data.unverified > 0 && <p className="error">{data.unverified} record{data.unverified === 1 ? "" : "s"} could not be verified and {data.unverified === 1 ? "is" : "are"} not shown. A machine you did not pair, something changed them on the way, or the console sent an older copy of something you have seen.</p>}
      <div className="hd" style={{ marginBottom: 0 }}>
        <div>
          <h1>{data.needs_you ? `${data.needs_you} need${data.needs_you === 1 ? "s" : ""} you` : "Nothing needs you"}</h1>
          <p className="muted">
            {data.machines.length === 0 ? "No machine is paired yet." : `${online} of ${data.machines.length} machine${data.machines.length === 1 ? "" : "s"} online`}
            {working.length > 0 && `, ${working.length} agent task${working.length === 1 ? "" : "s"} working`}
          </p>
        </div>
        {data.repos.length > 0 && (
          <div className="chips" aria-label="Repositories">
            {data.repos.map((r: any) => {
              const c = perRepo(r.id);
              return (
                <Link key={r.id} to={`/repos/${r.id}`}>
                  {r.name}
                  {c.needs > 0 && <span className="n">{c.needs} need you</span>}
                  {c.working > 0 && <span className="w">{c.working} working</span>}
                </Link>
              );
            })}
          </div>
        )}
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

      {needsAny && (
        <section>
          <div className="section-title"><h2>Needs you<span className="count-pill">{data.needs_you}</span></h2></div>
          <div className="list tight attention">
            {waiting.map((a: any) => (
              <Row key={a.id} to={`/tasks/${a.repo_id}/${a.task_id}`} attention
                chip={<span className="verdict v-approval_required">{a.scope === "intent" ? "Approve the plan" : "Approve the change"}</span>}
                title={a.title || `Task ${a.task_id}`} sub={a.repo} at={a.created_at} />
            ))}
            {held.map((t: any) => (
              <Row key={`${t.repo_id}/${t.id}`} to={`/tasks/${t.repo_id}/${t.id}`} attention
                chip={<span className="verdict v-approval_required">Held for you</span>}
                title={t.title || `Task ${t.id}`} sub={`${t.repo}, ${who(t)} on ${t.machine ?? "a machine"}${t.abandoned ? ", looks abandoned" : ""}`} at={t.updated_at} />
            ))}
            {edits.filter((e: any) => e.status === "ready" || e.status === "stuck").map((e: any) => (
              <Row key={e.id} to={`/edits/${e.id}`} attention chip={<span className="verdict v-approval_required">Policy edit</span>}
                title={`Policy edit for ${e.repo}`} sub={`${EDIT_WORDS[e.status] ?? e.status}${e.reason ? `: ${e.reason}` : ""}`} at={e.updated_at ?? e.created_at} />
            ))}
            {data.refusals.map((r: any, i: number) => (
              <div key={i} className="item">
                <div className="grow"><div className="title">{r.actor.replace("machine:", "")} refused a request from the console</div><div className="sub">{r.detail.what}: {r.detail.why}. If you did not ask for this, see <Link to="/guide/security">what a refusal means</Link>.</div></div>
                <When at={r.at} />
              </div>
            ))}
          </div>
        </section>
      )}

      {inFlight.length > 0 && (
        <section>
          <div className="section-title"><h2>On its way<span className="count-pill">{inFlight.length}</span></h2></div>
          <div className="list tight">
            {inFlight.map((a: any) => (
              <div key={a.id} className="item">
                <div className="grow"><div className="title">{a.title || a.task_id}</div><div className="sub">{a.status === "waiting" ? `Waiting for ${a.driver}` : a.status === "signed" ? "Signed; waiting for the machine to file it" : "The machine could not file it"}</div></div>
              </div>
            ))}
          </div>
        </section>
      )}

      {working.length > 0 && (
        <section>
          <div className="section-title"><h2>Working now<span className="count-pill">{working.length}</span></h2></div>
          <div className="list tight">
            {working.map((t: any) => (
              <Row key={`${t.repo_id}/${t.id}`} to={`/tasks/${t.repo_id}/${t.id}`} chip={<span className="verdict v-none">Working</span>}
                title={t.title || `Task ${t.id}`} sub={`${t.repo}, ${who(t)} on ${t.machine ?? "a machine"}${t.abandoned ? ", looks abandoned" : ""}`} at={t.updated_at} />
            ))}
          </div>
        </section>
      )}

      <section>
        <div className="section-title"><h2>Recently finished</h2><Link to="/activity" className="small">Everything that happened</Link></div>
        {data.tasks.length === 0 ? (
          <div className="list"><div className="item empty">No tasks yet. They appear when an agent declares a plan with use05 start.</div></div>
        ) : finished.length === 0 ? (
          <p className="muted small">Nothing finished lately.</p>
        ) : (
          <div className="list tight">
            {finished.slice(0, 10).map((t: any) => (
              <Row key={`${t.repo_id}/${t.id}`} to={`/tasks/${t.repo_id}/${t.id}`} chip={<Verdict decision={t.decision} />}
                title={t.title || `Task ${t.id}`} sub={`${t.repo}, ${who(t)} on ${t.machine ?? "a machine"}`} at={t.updated_at} />
            ))}
          </div>
        )}
      </section>

      {data.machines.length > 0 && (
        <section>
          <div className="section-title"><h2>Machines</h2><Link to="/machines" className="small">Manage</Link></div>
          <div className="list tight">
            {data.machines.map((m: any) => (
              <div key={m.id} className="item">
                <Online on={m.online} />
                <div className="grow"><div className="title">{m.name}</div></div>
                <span className="sub">{m.use05_version ? `use05 ${m.use05_version}` : ""}</span>
                {m.online ? <span className="when">online</span> : <When at={m.last_seen} />}
              </div>
            ))}
          </div>
        </section>
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
