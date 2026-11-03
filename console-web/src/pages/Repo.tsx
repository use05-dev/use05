import { useView } from "../records";
import { ago } from "../api";
import { Crumbs, Link, Loading, Online, Verdict, When } from "../ui";
import { EDIT_WORDS } from "./Home";
import { settingName } from "./Edit";

export function Repos() {
  const { data, error } = useView<any>("/overview", 15000);
  if (!data) return <Loading error={error} />;
  return (
    <div className="stack-lg">
      <div className="hd">
        <div><Crumbs trail={[["Home", "/"], ["Repositories", null]]} /><h1>Repositories</h1><p className="muted">Each repository a paired machine reports, with its policy.</p></div>
        <Link to="/base" className="btn quiet">Base policy</Link>
      </div>
      {data.repos.length === 0 ? (
        <div className="list"><div className="item empty">None yet. On your Mac, inside a repository: <code>use05 cloud add</code></div></div>
      ) : (
        <div className="list tight">
          {data.repos.map((r: any) => (
            <Link key={r.id} to={`/repos/${r.id}`} className="item">
              <div className="grow"><div className="title">{r.name}</div><div className="sub">lands on {r.landing}, last task <When at={r.last_task} /></div></div>
              {r.active > 0 && <span className="small">{r.active} working</span>}
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

export function Repo({ id }: { id: string }) {
  const { data, error } = useView<any>(`/repos/${id}`, 10000);
  if (!data) return <Loading error={error} />;
  const r = data.repo;
  return (
    <div className="stack-lg">
      <div className="hd">
        <div>
          <Crumbs trail={[["Home", "/"], ["Repositories", "/repos"], [r.name, null]]} />
          <h1>{r.name}</h1>
          <p className="muted">{r.remote ?? "no remote"}; changes land on <code>{r.landing}</code></p>
        </div>
        <Link to={`/repos/${id}/policy`} className="btn dark">Edit policy</Link>
      </div>

      {!data.policy.ok && <p className="error">The policy file does not parse: {data.policy.error}</p>}

      {data.ci ? (
        <p className="small">CI gate: <strong>{String(data.ci.decision ?? "?").replace("_", " ")}</strong>{data.ci.branch ? ` for ${data.ci.branch}` : ""}, {ago(data.ci.at)}{data.ci.run && <> (<a href={data.ci.run} target="_blank" rel="noreferrer">the run</a>)</>}</p>
      ) : (
        <p className="small muted">CI gate not seen. Until CI reports here, nothing shows that work reaching {r.landing} went through 05; see <Link to="/guide/ci">the guide</Link>.</p>
      )}

      <div className="row">
        {data.machines.map((m: any) => <span key={m.id} className="row small"><Online on={m.online} /> {m.name}</span>)}
      </div>

      {data.edits.length > 0 && (
        <div>
          <div className="section-title"><h2>Policy edits</h2></div>
          <div className="list tight">
            {data.edits.map((e: any) => (
              <Link key={e.id} to={`/edits/${e.id}`} className="item">
                <div className="grow"><div className="title">{[...new Set<string>((e.summary ?? []).map(settingName))].slice(0, 3).join(", ") || "Policy edit"}</div><div className="sub"><When at={e.created_at} /></div></div>
                <span className="small">{EDIT_WORDS[e.status] ?? e.status}</span>
              </Link>
            ))}
          </div>
        </div>
      )}

      <div>
        <div className="section-title"><h2>Tasks</h2></div>
        {data.tasks.length === 0 ? (
          <div className="list"><div className="item empty">No tasks in the last two weeks.</div></div>
        ) : (
          <div className="list tight">
            {data.tasks.map((t: any) => (
              <Link key={t.id} to={`/tasks/${id}/${t.id}`} className="item">
                <div className="grow"><div className="title">{t.title || `Task ${t.id}`}</div><div className="sub">{t.landed ? "landed" : t.status === "active" ? "working" : t.status}, {t.agent ?? "a person"}{t.model ? ` (${t.model})` : ""}</div></div>
                <Verdict decision={t.decision} />
                <When at={t.updated_at} />
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
