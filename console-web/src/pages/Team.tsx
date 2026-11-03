import { useEffect, useState } from "react";
import { ago, post } from "../api";
import { inviteBundle, noteMemberKeys, rotate, rotateNeeded } from "../keys";
import { friendly, prfOf } from "../passkey";
import { Link, Loading, useData } from "../ui";

export function Team() {
  const { data, error, reload } = useData<any>("/team");
  const [name, setName] = useState("");
  const [role, setRole] = useState("member");
  const [link, setLink] = useState<string | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [keyNote, setKeyNote] = useState<string | null>(null);
  const [needsKey, setNeedsKey] = useState(false);
  useEffect(() => {
    if (data?.me.role !== "admin") return;
    rotateNeeded().then(setNeedsKey, () => undefined);
    noteMemberKeys().catch(() => undefined);
  }, [data]);
  if (!data) return <Loading error={error} />;
  const admin = data.me.role === "admin";

  const act = async (work: () => Promise<unknown>) => {
    setProblem(null);
    try {
      await work();
      reload();
    } catch (e) {
      setProblem(friendly(e));
    }
  };

  // Whoever left still holds the team's key: make a new one (one passkey tap), sealed to those who stay.
  const changeKey = async () => {
    try {
      const { id, prf } = await prfOf();
      const to = await rotate(id, prf);
      setNeedsKey(false);
      setKeyNote(`The team has a new key, for ${to.join(", ")}. Each of you confirms it for your own machines from Home.`);
    } catch (e) {
      setNeedsKey(true);
      setKeyNote(`The team's key has not changed yet: ${friendly(e)}`);
    }
  };

  return (
    <div className="stack-lg">
      {needsKey && (
        <section className="panel attention">
          <h2>Someone left; the team's key has not changed</h2>
          <p className="muted">They can still open what machines send. Change the key: it goes to everyone who stays, and the team still reads what came before.</p>
          <div className="row" style={{ marginTop: 12 }}><button className="btn primary" onClick={changeKey}>Change the team key</button></div>
        </section>
      )}
      {keyNote && <p className={keyNote.startsWith("The team has") ? "small" : "error"}>{keyNote}</p>}
      <div className="hd">
        <div><h1>Team</h1><p className="muted">Everyone here sees the team's work. Each person approves their own sessions' work with their own passkey.</p></div>
        <Link to="/machines" className="btn quiet">Machines</Link>
      </div>

      <section>
        <div className="section-title"><h2>People</h2></div>
        <div className="list">
          {data.members.map((m: any) => (
            <div key={m.id} className="item">
              <div className="grow">
                <div className="title">{m.name}{m.id === data.me.id && <span className="muted" style={{ fontWeight: 400 }}> (you)</span>}</div>
                <div className="sub">{m.role === "admin" ? "Admin" : "Member"}, {m.passkeys} passkey{Number(m.passkeys) === 1 ? "" : "s"}, joined {ago(m.created_at)}</div>
              </div>
              {admin && removing !== m.id && (
                <div className="row">
                  <button className="btn small quiet" onClick={() => act(() => post(`/team/members/${m.id}/role`, { role: m.role === "admin" ? "member" : "admin" }))}>{m.role === "admin" ? "Make member" : "Make admin"}</button>
                  <button className="btn small danger" onClick={() => setRemoving(m.id)}>Remove</button>
                </div>
              )}
              {admin && removing === m.id && (
                <div className="row">
                  <button className="btn small danger" onClick={() => act(async () => { await post(`/team/members/${m.id}/remove`); setRemoving(null); await changeKey(); })}>Remove {m.name}</button>
                  <button className="btn small quiet" onClick={() => setRemoving(null)}>Keep</button>
                </div>
              )}
            </div>
          ))}
        </div>
        {problem && <p className="error" style={{ marginTop: 12 }}>{problem}</p>}
      </section>

      {admin && (
        <section className="panel stack">
          <h2>Invite someone</h2>
          <p className="small muted">They get a link that works once, for 48 hours. Opening it, they make their own passkey. Removing someone ends their sessions and cuts off their machines at once.</p>
          <div className="row">
            <input type="text" style={{ maxWidth: 260 }} placeholder="Their name" value={name} onChange={(e) => setName(e.target.value)} />
            <select style={{ maxWidth: 160 }} value={role} onChange={(e) => setRole(e.target.value)} aria-label="Role">
              <option value="member">Member</option>
              <option value="admin">Admin</option>
            </select>
            <button className="btn" disabled={!name.trim()} onClick={() => act(async () => {
              // The link carries the team's key, wrapped; opening it takes a tap of your passkey.
              const { id, prf } = await prfOf();
              const b = await inviteBundle(id, prf);
              const r = await post("/team/invites", { name, role, sealed_bundle: b.sealed });
              setLink(`${r.link}#${b.fragment}`);
              setName("");
            })}>Invite</button>
          </div>
          {link && (
            <div className="note stack">
              <span>Send this link to them yourself. It is shown once.</span>
              <code data-invite-link>{link}</code>
              <div><button className="btn small quiet" onClick={() => navigator.clipboard?.writeText(link)}>Copy link</button></div>
            </div>
          )}
          {data.invites.length > 0 && (
            <div className="list">
              {data.invites.map((i: any) => <div key={i.id} className="item"><div className="grow"><div className="title">{i.name}</div><div className="sub">invited as {i.role}, {ago(i.created_at)}</div></div><button className="btn small quiet" onClick={() => act(() => post(`/team/invites/${i.id}/cancel`))}>Cancel invite</button></div>)}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
