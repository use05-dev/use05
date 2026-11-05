import { openResult, sealTo, useView, view } from "../records";
import { Fragment, useEffect, useState } from "react";
import { checksLine, get, post, storyRows } from "../api";
import { friendly, signStatement } from "../passkey";
import { Crumbs, Link, Loading, Paths, Seal, Verdict, When, go } from "../ui";

export function ApprovalRedirect({ id }: { id: string }) {
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    view(`/approvals/${id}`).then((d) => go(`/tasks/${d.request.repo_id}/${d.request.task_id}`)).catch((e) => setError(e.message));
  }, [id]);
  return <Loading error={error} />;
}

export function Task({ repo, id }: { repo: string; id: string }) {
  const { data, error, reload } = useView<any>(`/tasks/${repo}/${id}`, 5000);
  if (!data) return <Loading error={error} />;
  const t = data.task;
  const d = t.detail ?? {};
  const gate = d.gate ?? {};
  const findings: any[] = gate.findings ?? [];
  const request = data.approvals.find((a: any) => a.status !== "dismissed");
  const checks = checksLine(d);
  const story = storyRows(d);

  return (
    <div className="stack-lg">
      <div className="hd">
        <div>
          <Crumbs trail={[["Home", "/"], [t.repo, `/repos/${repo}`], [t.title || `Task ${t.id}`, null]]} />
          <h1>{t.title || `Task ${t.id}`}</h1>
          <p className="muted">
            {t.agent ?? "A person"}{t.model ? ` (${t.model})` : ""} on {t.machine ?? "a machine"}, {t.landed ? "landed" : t.status === "active" ? "working" : t.status}, last activity <When at={t.updated_at} />
          </p>
        </div>
        <Verdict decision={t.decision} />
      </div>

      {checks && <p className="small muted">{checks}</p>}

      {story.length > 0 && (
        <section className="panel stack">
          <h2>What we know</h2>
          <dl className="story">
            {story.map((r, i) => (
              <Fragment key={i}>
                <dt className="small">{r.label}</dt>
                <dd className={r.attention ? "attention-text" : ""}>{r.text}</dd>
              </Fragment>
            ))}
          </dl>
        </section>
      )}

      {t.abandoned && <p className="small muted">Looks abandoned: nothing has happened here for over a week.</p>}

      {t.landed && (
        <section className="panel verified stack">
          <h2>Landed</h2>
          <p className="muted">This work is already in {d.lands_on ?? "the landing branch"}, so nothing waits for you. What follows is the record of it.</p>
        </section>
      )}

      {!request && !t.landed && t.decision === "approval_required" && data.mine && (
        <section className="panel attention stack">
          <h2>Held for you</h2>
          <p className="muted">A person must approve this before it goes, and {t.machine ?? "the machine"} has not asked here yet. Ask it to, then approve with your passkey right here. Or, if the work was left behind, discard it below.</p>
          <AskForApproval task={t} repo={repo} scope={findings.some((f: any) => f.code === "INTENT_NOT_APPROVED") ? "intent" : "outcome"} />
        </section>
      )}

      {request && <Approval request={request} task={t} mine={!request.driver_id || request.driver_id === data.me} done={reload} />}

      {(gate.testing?.length > 0 || findings.some((f: any) => String(f.code).startsWith("TESTING_"))) && <Tested task={t} repo={repo} tree={d.tree} gate={gate} policy={data.testing} mine={data.mine} done={reload} />}

      <section className="panel stack">
        <h2>The plan</h2>
        {d.goal && <p>{d.goal}</p>}
        <dl className="kv">
          <dt>May touch</dt><dd><Paths items={d.scope?.include} /></dd>
          {d.scope?.exclude?.length > 0 && <><dt>Not</dt><dd><Paths items={d.scope.exclude} /></dd></>}
          {d.out_of_scope?.length > 0 && <><dt>Out of scope</dt><dd>{d.out_of_scope.join("; ")}</dd></>}
          <dt>Risk</dt><dd>{d.risk ?? t.risk ?? "not known yet"}</dd>
          {d.lands_on && <><dt>Lands on</dt><dd>{d.lands_on}</dd></>}
        </dl>
      </section>

      {findings.length > 0 && (
        <section className="panel stack">
          <h2>What 05 found</h2>
          {findings.map((f, i) => (
            <div key={i} className="stack" style={{ borderTop: i ? "1px solid var(--line)" : 0, paddingTop: i ? 12 : 0 }}>
              <div className="row"><strong>{f.message}</strong></div>
              {f.paths?.length > 0 && <Paths items={f.paths} max={8} />}
              <p className="small muted">{f.effect === "approval" ? "A person must approve this." : f.effect === "deny" ? "This is refused." : f.effect === "warn" ? "A warning." : ""}{f.next ? ` At a terminal: ${f.next}` : ""}</p>
            </div>
          ))}
        </section>
      )}

      <section className="panel stack">
        <div className="row between"><h2>What changed</h2>{(d.added != null) && <span className="small muted">+{d.added} −{d.removed} lines</span>}</div>
        {(d.areas ?? []).length > 0 ? (
          <div className="stack">
            {d.areas.map((a: any) => {
              const total = Math.max(1, a.added + a.removed);
              return (
                <div key={a.name}>
                  <div className="row between small"><span className="path">{a.name}</span><span className="muted">{a.files} file{a.files === 1 ? "" : "s"}, +{a.added} −{a.removed}</span></div>
                  <div className="bar" style={{ marginTop: 6 }}><span className="add" style={{ width: `${(100 * a.added) / total}%` }} /><span className="del" style={{ width: `${(100 * a.removed) / total}%` }} /></div>
                </div>
              );
            })}
          </div>
        ) : <p className="muted">Nothing yet.</p>}
        {d.outside_scope?.length > 0 && <div className="note">Outside the plan: <Paths items={d.outside_scope} max={12} /></div>}
        {(gate.changed ?? []).length > 0 && (
          <details>
            <summary>{gate.changed.length} file{gate.changed.length === 1 ? "" : "s"}</summary>
            <div className="stack" style={{ marginTop: 10 }}>
              {gate.changed.map((c: any) => <div key={c.path} className="row between small"><span className="path">{c.path}</span><span className="muted">{c.status} +{c.added} −{c.removed}</span></div>)}
            </div>
          </details>
        )}
        <p className="small muted">File names only. The code itself never leaves your machine.</p>
      </section>

      {(gate.checks ?? []).length > 0 && (
        <section className="panel stack">
          <h2>Checks</h2>
          {gate.checks.map((c: any) => (
            <div key={c.name} className="row between">
              <span><strong>{c.name}</strong>{c.required ? "" : <span className="muted small"> optional</span>}</span>
              <span className="small">{String(c.state ?? c.status ?? "not run").replace(/_/g, " ")}</span>
            </div>
          ))}
        </section>
      )}

      {d.session && (d.session.tool_calls > 0 || d.session.turns > 0) && (
        <section className="panel">
          <h2>The session</h2>
          <dl className="kv" style={{ marginTop: 12 }}>
            {d.session.minutes != null && <><dt>Ran for</dt><dd>{d.session.minutes < 1 ? "under a minute" : `${d.session.minutes} min`}, {d.session.turns ?? 0} turns, {d.session.tool_calls ?? 0} tool calls</dd></>}
            {d.session.files_touched != null && <><dt>Edited</dt><dd>{d.session.files_touched} files</dd></>}
            {d.session.refused?.length > 0 && <><dt>05 refused</dt><dd>{d.session.refused.map((r: any) => (Array.isArray(r) ? `${r[0]} (${r[1]})` : String(r))).join(", ")}</dd></>}
            {d.session.subagents?.length > 0 && <><dt>Subagents</dt><dd>{d.session.subagents.map((s: any) => (Array.isArray(s) ? `${s[1]} ${s[0]}` : String(s))).join(", ")}</dd></>}
          </dl>
        </section>
      )}

      {data.events.length > 0 && (
        <section>
          <div className="section-title"><h2>Timeline</h2></div>
          <div className="list">
            {data.events.map((e: any, i: number) => (
              <div key={i} className="item"><div className="grow"><div className="title">{e.kind.replace("_", " ")}</div><div className="sub">{e.machine}, <When at={e.at} />{e.data?.decision ? `, ${e.data.decision.replace("_", " ")}` : ""}{e.data?.note ? `: "${e.data.note}"` : ""}</div></div></div>
            ))}
          </div>
        </section>
      )}

      {data.mine && t.status !== "held by CI" && <Discard task={t} repo={repo} abandoned={!!t.abandoned} />}
    </div>
  );
}

function Approval({ request, task, mine, done }: { request: any; task: any; mine: boolean; done: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const sealed = request.status === "signed" || request.status === "filed";
  const counts = request.result?.counts;

  // What is signed, read from the statement itself rather than from what the console says about it.
  const statement = (() => {
    try { return JSON.parse(atob(request.unsigned?.payload ?? "")); } catch { return null; }
  })();
  const signs = statement?.predicate;
  const signedTree: string | undefined = statement?.subject?.[0]?.digest?.gitTree;

  const rejecting = signs?.decision === "reject";
  const approve = async () => {
    setBusy(true);
    setError(null);
    try {
      const info = await view(`/approvals/${request.id}`);
      if (info.request.unsigned?.payload !== request.unsigned?.payload) throw new Error("The request changed while you were reading it. Look again before approving.");
      const scope = request.scope === "intent" ? "intent" : "outcome";
      const envelope = await signStatement(info.request.unsigned, { type: "approval", scope, tree: scope === "outcome" ? request.tree : undefined, decision: rejecting ? "reject" : "approve" }, info.rp_id, info.credentials);
      // Sealed to the machine that asked: the console passes it on and cannot read it.
      await post(`/approvals/${request.id}/sign`, { sealed: await sealTo(info.request.machine_id, "file_approval", { request: request.id, repo: info.request.repo_id, envelope }) });
      done();
    } catch (e) {
      setError(friendly(e));
    } finally {
      setBusy(false);
    }
  };

  const what = request.scope === "intent" ? "the plan" : "this change";
  return (
    <section className={`panel ${sealed ? "verified" : "attention"}`}>
      <Seal sealed={sealed}>
        {request.status === "waiting" && !mine && (
          <>
            <h2>Waiting for {request.driver}</h2>
            <p className="muted">This is {request.driver}'s session, so it is theirs to approve with their passkey. They have been told.</p>
          </>
        )}
        {request.status === "waiting" && mine && (
          <>
            <h2>{rejecting ? "Reject" : "Approve"} {what}?</h2>
            <p className="muted">Your passkey signs exactly what {task.machine ?? "the machine"} prepared: {request.scope === "intent" ? "this plan" : `the tree ${(signedTree ?? request.tree).slice(0, 12)}`} under today's policy. {rejecting ? "A rejection stands until the work changes." : "If the work changes, the approval stops counting."}</p>
            {signs && (
              <dl className="kv">
                <dt>You {rejecting ? "reject" : "approve"}</dt><dd>{signs.scope === "intent" ? "the plan" : "the finished change"} of task {signs.task}</dd>
                {rejecting && signs.rationale && <><dt>Because</dt><dd>{signs.rationale}</dd></>}
                <dt>Until</dt><dd>{new Date(signs.expires).toLocaleString()}</dd>
              </dl>
            )}
            {!signs && <p className="error">This request carries no readable statement. Do not sign it.</p>}
            <div className="row">
              <button className={`btn ${rejecting ? "danger" : "primary"}`} disabled={busy || !signs} onClick={approve}>{busy ? "Waiting for your passkey…" : rejecting ? "Reject with passkey" : "Approve with passkey"}</button>
              <button className="btn quiet" disabled={busy} onClick={async () => { await post(`/approvals/${request.id}/dismiss`); done(); }}>Not now</button>
            </div>
            {!rejecting && <RejectInstead task={task} repo={request.repo_id} scope={request.scope === "intent" ? "intent" : "outcome"} />}
          </>
        )}
        {request.status === "signed" && (<><h2>Signed</h2><p className="muted">Waiting for {task.machine ?? "the machine"} to file it.</p></>)}
        {request.status === "filed" && (
          <>
            <h2>{counts === false ? "Filed, but it will not count" : "Approved"}</h2>
            <p className="muted">{counts === false ? `${request.result?.void ?? "The work moved on"}. Ask the agent to finish again for a fresh request.` : `On ${task.machine ?? "the machine"}. Tell the agent to carry on.`}</p>
          </>
        )}
        {request.status === "failed" && (<><h2>The machine could not file it</h2><p className="error">{request.result?.reason ?? "No reason given."}</p></>)}
        {error && <p className="error">{error}</p>}
      </Seal>
    </section>
  );
}

/// The machine did not ask for an approval (the session ended first, say): ask it to prepare one,
/// and it appears on this page to sign, with no terminal.
function AskForApproval({ task, repo, scope }: { task: any; repo: string; scope: "intent" | "outcome" }) {
  const [asked, setAsked] = useState(false);
  const [slow, setSlow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  useEffect(() => {
    if (!asked) return;
    const t = setTimeout(() => setSlow(true), 90_000);
    return () => clearTimeout(t);
  }, [asked]);
  const ask = async () => {
    setBusy(true);
    setProblem(null);
    try {
      const id = crypto.randomUUID();
      const sealed = await sealTo(task.machine_id, "ask_approval", { ask: id, repo, task: task.id, scope });
      await post(`/repos/${repo}/ask-approval`, { id, machine: task.machine_id, sealed });
      setAsked(true);
    } catch (e) {
      setProblem(friendly(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      {!asked ? (
        <div className="row"><button className="btn primary" disabled={busy} onClick={ask}>{busy ? "Asking…" : scope === "intent" ? "Ask for my approval of the plan" : "Ask for my approval of the change"}</button></div>
      ) : (
        <p className="small muted">Asked {task.machine ?? "your machine"}. The approval appears here to sign; this page updates itself.{slow && <> Still nothing? {task.machine ?? "The machine"} may be asleep or offline: see <Link to="/machines">Machines</Link>.</>}</p>
      )}
      {problem && <p className="error">{problem}</p>}
      {!asked && <RejectInstead task={task} repo={repo} scope={scope} />}
    </>
  );
}

/// Say no, with a reason, from here: the machine prepares the rejection and a passkey signs it, as for an approval.
function RejectInstead({ task, repo, scope }: { task: any; repo: string; scope: "intent" | "outcome" }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [asked, setAsked] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const send = async () => {
    setBusy(true);
    setProblem(null);
    try {
      const id = crypto.randomUUID();
      const sealed = await sealTo(task.machine_id, "ask_approval", { ask: id, repo, task: task.id, scope, reject: true, reason: reason.trim() });
      await post(`/repos/${repo}/ask-approval`, { id, machine: task.machine_id, sealed });
      setAsked(true);
    } catch (e) {
      setProblem(friendly(e));
    } finally {
      setBusy(false);
    }
  };
  if (asked) return <p className="small muted">Asked {task.machine ?? "your machine"} to prepare the rejection. It appears here to sign.</p>;
  if (!open) return <div className="row"><button className="btn small quiet" onClick={() => setOpen(true)}>Reject it instead…</button></div>;
  return (
    <div className="stack">
      <label className="stack"><span className="small">Why are you rejecting it? The agent and your record both keep this.</span><input type="text" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={300} /></label>
      <div className="row"><button className="btn danger" disabled={busy || !reason.trim()} onClick={send}>{busy ? "Asking…" : "Ask to reject"}</button><button className="btn quiet" disabled={busy} onClick={() => setOpen(false)}>Cancel</button></div>
      {problem && <p className="error">{problem}</p>}
    </div>
  );
}

/// Throw this work away (D89): the machine that holds it says what would go and what would be
/// lost (commits that exist nowhere else, files never committed); the passkey signs that; the
/// machine removes the worktree and the branch, here and on origin. Nothing comes back.
function Discard({ task, repo, abandoned }: { task: any; repo: string; abandoned: boolean }) {
  const [id, setId] = useState<string | null>(null);
  const [state, setState] = useState<string | null>(null);
  const [plan, setPlan] = useState<any>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!id) return;
    const tick = setInterval(async () => {
      const d = (await get(`/discards/${id}`).catch(() => null))?.discard;
      if (!d) return;
      setState(d.status);
      try {
        if (d.status === "ready" && !plan) setPlan((await openResult(d.machine_id, repo, id, d.prepared))?.result ?? null);
      } catch {
        clearInterval(tick);
        setProblem("The machine's answer could not be checked, so nothing was done. Try again.");
        setId(null);
        setState(null);
        return;
      }
      if (d.status === "done") {
        clearInterval(tick);
        go("/");
      }
      if (d.status === "stuck") {
        clearInterval(tick);
        // No answer at all (the console gave up waiting) or the machine said why it could not.
        const why = d.prepared ? (await openResult(d.machine_id, repo, id, d.prepared).catch(() => null))?.result?.reason : null;
        setProblem(why ?? `${task.machine ?? "Your machine"} did not answer in time. Check that it is awake and online under Machines, then try again.`);
        setId(null);
        setState(null);
      }
    }, 2000);
    return () => clearInterval(tick);
  }, [id, plan]);

  const start = async () => {
    setBusy(true);
    setProblem(null);
    try {
      const next = crypto.randomUUID();
      const sealed = await sealTo(task.machine_id, "prepare_discard", { discard: next, repo, task: task.id });
      await post(`/repos/${repo}/discard`, { id: next, machine: task.machine_id, sealed });
      setId(next);
      setState("preparing");
    } catch (e) {
      setProblem(friendly(e));
    } finally {
      setBusy(false);
    }
  };

  const sign = async () => {
    setBusy(true);
    setProblem(null);
    try {
      const info = await get(`/discards/${id}`);
      const prepared = await openResult(info.discard.machine_id, repo, id!, info.discard.prepared);
      if (!prepared?.ok) throw new Error("The machine's answer could not be checked.");
      const envelope = await signStatement(prepared.result.unsigned, { type: "discard", task: task.id }, info.rp_id, info.credentials);
      await post(`/discards/${id}/sign`, { sealed: await sealTo(task.machine_id, "discard", { discard: id, repo, envelope }) });
      setState("signed");
    } catch (e) {
      setProblem(friendly(e));
    } finally {
      setBusy(false);
    }
  };

  const rows: [string, string][] = plan?.rows ?? [];
  return (
    <section className={`panel stack${abandoned ? " attention" : ""}`}>
      <h2>Discard this work</h2>
      {!id && (
        <>
          <p className="muted">Removes its worktree and its branch on {task.machine ?? "your machine"} and on origin, and clears it from here. You see what would be lost before anything goes.</p>
          <div className="row"><button className="btn quiet" disabled={busy} onClick={start}>Discard this work…</button></div>
        </>
      )}
      {id && state === "preparing" && (
        <div className="row between">
          <p className="small muted">{task.machine ?? "Your machine"} is working out what would go. The console gives up after two minutes.</p>
          <button className="btn small quiet" onClick={() => { setId(null); setState(null); }}>Stop waiting</button>
        </div>
      )}
      {id && state === "ready" && plan && (
        <>
          <dl className="kv">{rows.map(([k, v]) => <Fragment key={k}><dt>{k[0].toUpperCase() + k.slice(1)}</dt><dd>{v}</dd></Fragment>)}</dl>
          <p className="small">This cannot be undone.</p>
          <div className="row"><button className="btn danger" disabled={busy} onClick={sign}>{busy ? "Waiting for your passkey…" : "Discard with passkey"}</button></div>
        </>
      )}
      {id && state === "signed" && <p className="small muted">Signed. {task.machine ?? "Your machine"} is discarding it…</p>}
      {problem && <p className="error">{problem}</p>}
    </section>
  );
}

/// Testing before a push (D87): who tried it, in their words; and for the person driving the work,
/// signing off from here. Their machine prepares the statement with the note typed here (sealed to
/// it), their passkey signs it, and the machine files it.
function Tested({ task, repo, tree, gate, policy, mine, done }: { task: any; repo: string; tree?: string; gate: any; policy: any; mine: boolean; done: () => void }) {
  const [note, setNote] = useState("");
  const [signoff, setSignoff] = useState<string | null>(null);
  // What the person asked for: the machine's statement must say exactly this before it is signed.
  const [asked, setAsked] = useState<{ outcome: "tested" | "skipped"; note: string; tree: string } | null>(null);
  const [state, setState] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const signed: any[] = gate.testing ?? [];
  const counts = signed.some((t) => t.counts);
  const skippable = policy?.local === "skippable";

  // Follow the sign-off as the machine prepares it, then as it files it.
  useEffect(() => {
    if (!signoff) return;
    const tick = setInterval(async () => {
      const s = (await get(`/signoffs/${signoff}`).catch(() => null))?.signoff;
      if (!s) return;
      setState(s.status);
      if (s.status === "filed") {
        clearInterval(tick);
        done();
      }
      if (s.status === "stuck") {
        clearInterval(tick);
        const why = await openResult(s.machine_id, repo, signoff, s.prepared);
        setProblem(why?.result?.reason ?? "The machine could not do it.");
      }
    }, 2000);
    return () => clearInterval(tick);
  }, [signoff]);

  const start = async (outcome: "tested" | "skipped") => {
    setBusy(true);
    setProblem(null);
    try {
      if (!tree) throw new Error("The machine has not reported which code this is yet.");
      const id = crypto.randomUUID();
      // The code as it was when they asked: newer records may arrive before they sign.
      setAsked({ outcome, note: note.trim(), tree });
      const sealed = await sealTo(task.machine_id, "prepare_testing", { signoff: id, repo, task: task.id, tree, outcome, note: note.trim() });
      await post(`/repos/${repo}/testing`, { id, machine: task.machine_id, sealed });
      setSignoff(id);
      setState("preparing");
    } catch (e) {
      setProblem(friendly(e));
    } finally {
      setBusy(false);
    }
  };

  const sign = async () => {
    setBusy(true);
    setProblem(null);
    try {
      const info = await get(`/signoffs/${signoff}`);
      const prepared = await openResult(info.signoff.machine_id, repo, signoff!, info.signoff.prepared);
      if (!prepared?.ok || !asked) throw new Error("The machine's answer could not be checked.");
      const envelope = await signStatement(prepared.result.unsigned, { type: "testing", task: task.id && task.id !== "-" ? task.id : undefined, ...asked }, info.rp_id, info.credentials);
      await post(`/signoffs/${signoff}/sign`, { sealed: await sealTo(task.machine_id, "file_testing", { signoff, repo, envelope }) });
      setState("signed");
    } catch (e) {
      setProblem(friendly(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className={`panel stack ${counts ? "verified" : "attention"}`}>
      <h2>Tested before a push</h2>
      {signed.length > 0 ? (
        <div className="stack">
          {signed.map((t, i) => (
            <p key={i} className={t.counts ? "" : "muted"}>
              {t.by?.name ?? "Someone"} {t.outcome === "tested" ? "tried it" : "skipped testing"}: “{t.note}”{t.void ? ` (does not count: ${t.void})` : ""}
            </p>
          ))}
        </div>
      ) : (
        <p className="muted">Before this is pushed{policy?.branches?.length ? ` to ${policy.branches.join(", ")}` : ""}, the person driving the work tries it in their own environment and signs off.</p>
      )}
      {!counts && mine && !signoff && (
        <>
          <label className="stack"><span className="small">What you tried</span><textarea rows={3} maxLength={500} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Signed up, paid an invoice, checked the receipt email" /></label>
          <div className="row">
            <button className="btn primary" disabled={busy || !note.trim()} onClick={() => start("tested")}>I tried it: sign off</button>
            {skippable && <button className="btn quiet" disabled={busy || !note.trim()} onClick={() => start("skipped")}>Skip, saying why</button>}
          </div>
        </>
      )}
      {signoff && state === "preparing" && <p className="small muted">Your machine is preparing the sign-off…</p>}
      {signoff && state === "ready" && <div className="row"><button className="btn primary" disabled={busy} onClick={sign}>Sign with passkey</button></div>}
      {signoff && state === "signed" && <p className="small muted">Signed. Your machine is filing it…</p>}
      {signoff && state === "filed" && <p className="small">Signed off. The push can go.</p>}
      {!counts && !mine && <p className="small muted">It is for the person driving this work to sign off.</p>}
      {problem && <p className="error">{problem}</p>}
    </section>
  );
}
