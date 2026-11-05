// A repository's environments (D93): which commit each branch holds, the newest promotion and
// deployment records, and what waits to come up. A person can sign off on a promotion from here:
// their own machine prepares the statement and files it once their passkey signed. The console
// never makes a machine push; the promotion itself runs on a machine or in CI.
import { useEffect, useState } from "react";
import { deployWords, get, post, waitingWords } from "../api";
import { openResult, sealTo } from "../records";
import { friendly, signStatement } from "../passkey";
import { When } from "../ui";

const short = (c?: string | null) => (c ? c.slice(0, 10) : "none");

export function Environments({ repo, envs, machines }: { repo: string; envs: any[]; machines: any[] }) {
  if (!Array.isArray(envs) || envs.length === 0) return null;
  const mine = machines.find((m) => m.mine && m.online) ?? machines.find((m) => m.mine);
  return (
    <div>
      <div className="section-title"><h2>Environments</h2></div>
      <div className="list tight">
        {envs.map((e) => (
          <div key={e.name} className="item stack">
            <div>
              <div className="title">{e.name}{e.level && e.level !== e.name ? ` (${e.level})` : ""}</div>
              <div className="sub"><code>{e.branch}</code> at {short(e.head)}; {deployWords(e)}{e.deployed?.created && <>, <When at={e.deployed.created} /></>}</div>
              {e.promoted && <div className="sub">last {e.promoted.direction === "back" ? "merged back" : e.promoted.direction === "hotfix" ? "hotfix" : "promoted"} from {e.promoted.from} by {e.promoted.by}, <When at={e.promoted.created} /></div>}
              {/* Under the facts, not beside them: beside, a phone squeezes both into slivers. */}
              {waitingWords(e) && <div className="small">{waitingWords(e)}</div>}
            </div>
            {waitingWords(e) && <SignOff repo={repo} env={e} machine={mine} />}
          </div>
        ))}
      </div>
    </div>
  );
}

function SignOff({ repo, env, machine }: { repo: string; env: any; machine: any }) {
  const [open, setOpen] = useState(false);
  const [note, setNote] = useState("");
  const [answers, setAnswers] = useState<string[]>([]);
  const [confirmed, setConfirmed] = useState<string[]>([]);
  const [signoff, setSignoff] = useState<string | null>(null);
  const [state, setState] = useState<string>("");
  const [asked, setAsked] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const questions: string[] = env.sign_off?.questions ?? [];
  const confirm: string[] = env.confirm ?? [];
  const min: number = env.sign_off?.min_length ?? 0;
  const ready = note.trim().length >= Math.max(1, min) && questions.every((_, i) => (answers[i] ?? "").trim()) && confirm.every((c) => confirmed.includes(c));

  useEffect(() => {
    if (!signoff) return;
    const tick = setInterval(async () => {
      const s = (await get(`/signoffs/${signoff}`).catch(() => null))?.signoff;
      if (!s) return;
      setState(s.status);
      if (s.status === "filed") clearInterval(tick);
      if (s.status === "stuck") {
        clearInterval(tick);
        const why = await openResult(s.machine_id, repo, signoff, s.prepared);
        setProblem(why?.result?.reason ?? "The machine could not do it.");
      }
    }, 2000);
    return () => clearInterval(tick);
  }, [signoff]);

  if (!machine) return <p className="small muted">To sign off on promoting into {env.name} from here, pair one of your own machines with this repository.</p>;
  if (!open) return <div className="row"><button className="btn quiet" onClick={() => setOpen(true)}>Sign off on promoting {env.from} into {env.name}</button></div>;

  const start = async () => {
    setBusy(true);
    setProblem(null);
    try {
      const id = crypto.randomUUID();
      const text = note.trim();
      setAsked(text);
      const sealed = await sealTo(machine.id, "prepare_testing", { signoff: id, repo, promote: env.name, note: text, answers: answers.map((a) => a.trim()), confirmations: confirmed });
      await post(`/repos/${repo}/testing`, { id, machine: machine.id, sealed });
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
      if (!prepared?.ok || asked === null) throw new Error("The machine's answer could not be checked.");
      const envelope = await signStatement(prepared.result.unsigned, { type: "signoff", env: env.name, text: asked, decision: "approve" }, info.rp_id, info.credentials);
      await post(`/signoffs/${signoff}/sign`, { sealed: await sealTo(machine.id, "file_testing", { signoff, repo, envelope }) });
      setState("signed");
    } catch (e) {
      setProblem(friendly(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      {!signoff && (
        <>
          <label className="stack">
            <span className="small">In your own words, what did you check?{min > 0 ? ` (at least ${min} characters, ${note.trim().length} so far)` : ""}</span>
            <textarea rows={3} maxLength={1000} value={note} onChange={(ev) => setNote(ev.target.value)} />
          </label>
          {questions.map((q, i) => (
            <label key={q} className="stack">
              <span className="small">{q}</span>
              <input value={answers[i] ?? ""} onChange={(ev) => setAnswers((a) => Object.assign([...a], { [i]: ev.target.value }))} />
            </label>
          ))}
          {confirm.map((c) => (
            <label key={c} className="row small">
              <input type="checkbox" checked={confirmed.includes(c)} onChange={(ev) => setConfirmed((x) => (ev.target.checked ? [...x, c] : x.filter((y) => y !== c)))} /> {c}
            </label>
          ))}
          <div className="row"><button className="btn primary" disabled={busy || !ready} onClick={start}>Ask my machine to prepare it</button></div>
        </>
      )}
      {signoff && state === "preparing" && <p className="small muted">{machine.name} is preparing the sign-off…</p>}
      {signoff && state === "ready" && <div className="row"><button className="btn primary" disabled={busy} onClick={sign}>Sign with passkey</button></div>}
      {signoff && state === "signed" && <p className="small muted">Signed. {machine.name} is filing it…</p>}
      {signoff && state === "filed" && <p className="small">Signed off. It counts when a machine promotes it: <code>use05 promote {env.name}</code>.</p>}
      {problem && <p className="error">{problem}</p>}
    </div>
  );
}
