import { useEffect, useState } from "react";
import { get } from "../api";
import { Link } from "../ui";

/// The link from a confirmation email: works signed in or not.
export function Verify({ token }: { token: string }) {
  const [email, setEmail] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  useEffect(() => {
    get(`/verify/${token}`).then((r) => setEmail(r.email)).catch((e) => setProblem(e.message));
  }, [token]);
  return (
    <div className="gate-page">
      <div className="gate-card stack-lg">
        <img className="logo" src="/logo.svg" alt="05" />
        {email && <div className="stack"><h1>Confirmed</h1><p className="muted">05 alerts now go to <strong>{email}</strong>.</p><Link to="/" className="btn primary">Open the console</Link></div>}
        {problem && <p className="error">{problem}</p>}
      </div>
    </div>
  );
}
