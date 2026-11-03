import { useEffect, useState } from "react";
import { openResult, sealTo, useView } from "../records";
import { ago, get, post } from "../api";
import { friendly, signStatement } from "../passkey";
import { Crumbs, Loading, Seal } from "../ui";

const ORDER = ["preparing", "ready", "signed", "applied"];

// The settings by the names the editor uses for them.
const NAMES: Record<string, string> = {
  "intent.mode": "When a plan is needed", "testing": "Testing before a push", "testing.local": "Testing before a push", "testing.branches": "Branches that need testing", "protect.paths": "Needs approval", "protect.locked": "Locked", "protect.append_only": "Add only",
  "protect.no_delete": "Never deleted", "protect.no_read": "Agents may not read", "drift.scope": "Work outside the plan",
  "drift.dependencies": "New dependencies", "drift.overlap": "Another agent's area", "drift.claims": "Claims without evidence",
  "drift.tests": "Weakened tests", "drift.reservation_idle_hours": "Reservations expire after", "evidence.stop_budget_secs": "Time for checks at stop",
  "evidence.prove_at_push": "Run checks before a push", "approvals.expire_days": "Approvals expire after", "record.middle": "Record what agents do",
  "risk.rules": "Risk categories", "risk.exempt": "Not risky after all", "branches.keep": "Never deleted branches", "branches.work": "Work branches",
  "branches.target": "Changes land on", "branches.land": "Landing", "branches.fresh_base": "Starting from old code", environment: "Environments",
  require: "Files that change together", check: "Checks",
};
export const settingName = (path: string) => NAMES[path] ?? NAMES[path.split(".").slice(0, 2).join(".")] ?? NAMES[path.split(".")[0]] ?? path;

export function Edit({ id }: { id: string }) {
  const { data, error, reload } = useView<any>(`/edits/${id}`, 2500);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [opened, setOpened] = useState<any>(null);
  const sealed = data?.edit?.prepared?.sealed;
  useEffect(() => {
    if (data?.edit) openResult(data.edit.machine_id, data.edit.repo_id, id, data.edit.prepared).then(setOpened);
  }, [sealed]);
  if (!data) return <Loading error={error} />;
  const e = { ...data.edit, prepared: opened?.ok ? opened.result : null, reason: opened && !opened.ok ? opened.result?.reason ?? "The machine did not say why." : null };
  const step = e.status === "stuck" ? -1 : ORDER.indexOf(e.status);
  const state = (i: number) => (e.status === "stuck" && i === Math.max(0, ORDER.indexOf(e.prepared ? "ready" : "preparing")) ? "bad" : step > i || e.status === "applied" ? "done" : step === i ? "now" : "");
  const machine = e.machine ?? "your machine";
  const result = e.prepared;

  const sign = async () => {
    setBusy(true);
    setProblem(null);
    try {
      const info = await get(`/edits/${id}`);
      const envelope = await signStatement(e.prepared.unsigned, { type: "approval", scope: "outcome" }, info.rp_id, info.credentials);
      // The envelope and the commit it approves, sealed to the machine that prepared them.
      await post(`/edits/${id}/sign`, { sealed: await sealTo(e.machine_id, "apply_policy_edit", { edit: id, repo: e.repo_id, envelope, commit: e.prepared.commit, base: e.prepared.base }) });
      reload();
    } catch (err) {
      setProblem(friendly(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack-lg">
      <div className="hd">
        <div>
          <Crumbs trail={[["Home", "/"], [e.repo, `/repos/${e.repo_id}`], ["Policy edit", null]]} />
          <h1>Policy edit</h1>
          <p className="muted">Started {ago(e.created_at)}</p>
        </div>
      </div>

      <section className="panel">
        <h2>Changes</h2>
        <div className="paths" style={{ marginTop: 10 }}>{[...new Set<string>((result?.changed ?? []).map(settingName))].map((s) => <span key={s} className="verdict v-none" style={{ fontWeight: 600 }}>{s}</span>)}</div>
      </section>

      <section className={`panel ${e.status === "applied" ? "verified" : e.status === "ready" || e.status === "stuck" ? "attention" : ""}`}>
        <Seal sealed={e.status === "signed" || e.status === "applied"}>
          <ol className="steps">
            <li className={state(0)}>
              <div><strong>Prepared on {machine}</strong><p className="small muted">It builds the commit on origin's latest {"landing branch"}, and checks the edit changes nothing only a terminal may change.</p></div>
            </li>
            <li className={state(1)}>
              <div>
                <strong>Signed with your passkey</strong>
                {e.status === "ready" && (
                  <div className="stack" style={{ marginTop: 8 }}>
                    <p className="small muted">You approve the exact commit {result?.commit?.slice(0, 12)}, on top of {result?.base?.slice(0, 12)}.</p>
                    <button className="btn primary" disabled={busy} onClick={sign}>{busy ? "Waiting for your passkey…" : "Sign with passkey"}</button>
                  </div>
                )}
              </div>
            </li>
            <li className={state(2)}><div><strong>Applied</strong><p className="small muted">{machine} files your approval, pushes the commit, and moves its own branch when nothing would be lost. Other machines get it with their next pull.</p></div></li>
          </ol>
          {e.status === "stuck" && <p className="error">{e.reason}</p>}
          {e.status === "applied" && <p className="muted">Done. New agent work follows the new rules.</p>}
          {problem && <p className="error">{problem}</p>}
          {["preparing", "ready", "stuck"].includes(e.status) && <div><button className="btn small quiet" onClick={async () => { await post(`/edits/${id}/cancel`); reload(); }}>Cancel this edit</button></div>}
        </Seal>
      </section>

      <details>
        <summary>The file it writes</summary>
        <pre className="toml" style={{ marginTop: 10 }}>{result?.toml ?? "The machine has not prepared it yet."}</pre>
      </details>
    </div>
  );
}
