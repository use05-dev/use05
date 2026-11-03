import { useView } from "../records";
import { Crumbs, Link, Loading, When } from "../ui";

const WORDS: Record<string, (d: any) => string> = {
  sealed: () => "declared a plan",
  finished: () => "said it was done",
  gate: (d) => `gate at ${d.where ?? "push"}: ${(d.decision ?? "").replace("_", " ")}`,
  landed: (d) => `landed on ${d.target ?? "the target"}`,
  approval_needed: (d) => (d.scope === "intent" ? "is waiting for you to approve the plan" : "is waiting for you to approve the change"),
};

export function Activity() {
  const { data, error } = useView<any[]>("/activity", 8000);
  if (!data) return <Loading error={error} />;
  return (
    <div className="stack-lg">
      <div className="hd"><div><Crumbs trail={[["Home", "/"], ["Activity", null]]} /><h1>Activity</h1><p className="muted">Everything 05 heard from your machines, newest first.</p></div></div>
      {data.length === 0 ? (
        <div className="list"><div className="item empty">Nothing yet. Events arrive as agents declare plans, finish, push and land.</div></div>
      ) : (
        <div className="list tight">
          {data.map((e) => (
            <Link key={e.id} to={e.task_id ? `/tasks/${e.repo_id}/${e.task_id}` : `/repos/${e.repo_id}`} className="item">
              <div className="grow">
                <div className="title">{e.title || (e.task_id ? `Task ${e.task_id}` : e.repo)} <span className="muted" style={{ fontWeight: 400 }}>{(WORDS[e.kind] ?? (() => e.kind))(e.data)}</span></div>
                <div className="sub">{e.repo} on {e.machine ?? "a machine"}</div>
              </div>
              {e.data?.findings?.length > 0 && <span className="small muted">{e.data.findings.length} finding{e.data.findings.length === 1 ? "" : "s"}</span>}
              <When at={e.at} />
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
