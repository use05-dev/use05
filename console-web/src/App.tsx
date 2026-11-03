import { useView } from "./records";
import { useEffect, useState } from "react";
import { get } from "./api";
import { Icons, Link, Loading, usePath } from "./ui";
import { Gate } from "./pages/Gate";
import { Home } from "./pages/Home";
import { Activity } from "./pages/Activity";
import { Repos, Repo } from "./pages/Repo";
import { Task, ApprovalRedirect } from "./pages/Task";
import { PolicyEditor } from "./pages/Policy";
import { Edit } from "./pages/Edit";
import { Machines } from "./pages/Machines";
import { Guide } from "./pages/Guide";
import { Settings } from "./pages/Settings";
import { Team } from "./pages/Team";
import { Join } from "./pages/Join";
import { Verify } from "./pages/Verify";
import { Unlock } from "./pages/Unlock";
import { current } from "./keys";

type Me = { signed_in: boolean; setup_needed: boolean; rp_id: string; email: boolean; member?: { id: string; name: string; role: string } };

function route(path: string) {
  const p = path.split("/").filter(Boolean);
  switch (p[0]) {
    case undefined: return <Home />;
    case "activity": return <Activity />;
    case "repos":
      if (!p[1]) return <Repos />;
      if (p[2] === "policy") return <PolicyEditor repo={p[1]} />;
      return <Repo id={p[1]} />;
    case "tasks": return <Task repo={p[1]} id={p[2]} />;
    case "approvals": return <ApprovalRedirect id={p[1]} />;
    case "edits": return <Edit id={p[1]} />;
    case "base": return <PolicyEditor />;
    case "machines": return <Machines />;
    case "guide": return <Guide anchor={p[1]} />;
    case "settings": return <Settings />;
    case "team": return <Team />;
    default: return <div className="panel"><h2>Nothing here</h2><p className="muted">That page does not exist. <Link to="/">Go home</Link>.</p></div>;
  }
}

const NAV = [
  { to: "/", label: "Home", long: "", icon: Icons.home },
  { to: "/activity", label: "Activity", long: "", icon: Icons.activity },
  { to: "/repos", label: "Repos", long: "itories", icon: Icons.repos },
  { to: "/machines", label: "Machines", long: "", icon: Icons.machines },
  { to: "/guide", label: "Guide", long: "", icon: Icons.guide },
];

function Shell({ path }: { path: string }) {
  const { data } = useView<any>("/overview", 15000);
  const waiting = data?.needs_you ?? 0;
  const current = (to: string) => (to === "/" ? path === "/" : path.startsWith(to)) || (to === "/repos" && (path.startsWith("/tasks") || path.startsWith("/base")));
  return (
    <div className="shell">
      <nav className="rail" aria-label="Main">
        <Link to="/" className="brand"><img src="/logo.svg" alt="" /> 05 console</Link>
        <div className="nav">
          {NAV.map((n) => (
            <Link key={n.to} to={n.to} aria-current={current(n.to) ? "page" : undefined}>
              <n.icon />
              <span>{n.label}<span className="label-long">{n.long}</span></span>
              {n.to === "/" && waiting > 0 && <span className="count" aria-label={`${waiting} need you`}>{waiting}</span>}
            </Link>
          ))}
        </div>
        <div className="foot row"><Link to="/team">Team</Link><Link to="/settings">Settings</Link></div>
      </nav>
      <main>{route(path)}</main>
    </div>
  );
}

export function App() {
  const path = usePath();
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<boolean | null>(null);
  const check = () => get<Me>("/me").then(async (m) => { setOpen(m.signed_in ? !!(await current()) : null); setMe(m); }).catch((e) => setError(e.message));
  useEffect(() => {
    void check();
    const out = () => void check();
    window.addEventListener("use05-signed-out", out);
    return () => window.removeEventListener("use05-signed-out", out);
  }, []);
  if (!me) return <div className="gate-page"><Loading error={error} /></div>;
  const confirming = path.match(/^\/verify\/([^/]+)/);
  if (confirming) return <Verify token={confirming[1]} />;
  const joining = path.match(/^\/join\/([^/]+)/);
  if (!me.signed_in && joining) return <Join token={joining[1]} onDone={check} />;
  if (!me.signed_in) return <Gate setup={me.setup_needed} onDone={check} />;
  if (open === false) return <Unlock admin={me.member?.role === "admin"} onDone={check} />;
  return <Shell path={path} />;
}
