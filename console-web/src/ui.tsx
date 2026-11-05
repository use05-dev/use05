import { useCallback, useEffect, useState, type ReactNode, type MouseEvent } from "react";
import { ago, get, stamp } from "./api";

// A router small enough to read: the path is the state.
const listeners = new Set<() => void>();
export function go(to: string) {
  window.history.pushState({}, "", to);
  listeners.forEach((l) => l());
  window.scrollTo(0, 0);
}
window.addEventListener("popstate", () => listeners.forEach((l) => l()));
export function usePath() {
  const [path, setPath] = useState(window.location.pathname);
  useEffect(() => {
    const l = () => setPath(window.location.pathname);
    listeners.add(l);
    return () => void listeners.delete(l);
  }, []);
  return path;
}
export function Link({ to, children, className, ...rest }: { to: string; children: ReactNode; className?: string; [k: string]: any }) {
  const click = (e: MouseEvent) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    go(to);
  };
  return <a href={to} onClick={click} className={className} {...rest}>{children}</a>;
}

/// Load JSON and keep it fresh while the page is open.
export function useData<T = any>(path: string | null, every = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => {
    if (!path) return;
    try {
      setData(await get<T>(path));
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }, [path]);
  useEffect(() => {
    setData(null);
    load();
    if (!every) return;
    const t = setInterval(() => document.visibilityState === "visible" && load(), every);
    return () => clearInterval(t);
  }, [load, every]);
  return { data, error, reload: load };
}

export function Loading({ error }: { error?: string | null }) {
  return error ? <p className="error">{error}</p> : <p className="muted">Loading…</p>;
}

const DECISION_WORDS: Record<string, string> = { allow: "Allowed", approval_required: "Needs you", deny: "Refused", wait: "Waiting", landed: "Landed" };
export function Verdict({ decision }: { decision?: string | null }) {
  if (!decision) return <span className="verdict v-none">No decision yet</span>;
  return <span className={`verdict v-${decision}`}>{DECISION_WORDS[decision] ?? decision}</span>;
}

/// A moment as people say it, with the exact time on hover and for screen readers.
export function When({ at }: { at?: string | null }) {
  return <time className="when" dateTime={at ?? undefined} title={stamp(at)}>{ago(at)}</time>;
}

/// Where this page sits, each step a way back. The last step is the page itself.
export function Crumbs({ trail }: { trail: [string, string | null][] }) {
  return (
    <nav className="crumbs" aria-label="Breadcrumb">
      {trail.map(([label, to], i) => (
        <span key={i}>{to ? <Link to={to}>{label}</Link> : <span aria-current="page">{label}</span>}{i < trail.length - 1 && <span className="sep" aria-hidden="true"> / </span>}</span>
      ))}
    </nav>
  );
}

export function Online({ on }: { on: boolean }) {
  return <span className={`dot${on ? " on" : ""}`} role="img" aria-label={on ? "online" : "offline"} />;
}

/// The zero from the 05 logo, striped. Unsealed, the red dot waits outside; sealed, it sits in the counter.
const ZERO = "M60 0H108A60 60 0 0 1 168 60V140A60 60 0 0 1 108 200H60A60 60 0 0 1 0 140V60A60 60 0 0 1 60 0Z" +
  "M62 37H106A14 14 0 0 1 120 51V149A14 14 0 0 1 106 163H62A14 14 0 0 1 48 149V51A14 14 0 0 1 62 37Z";
const BARS = [0, 42, 84, 126, 168];
export function Seal({ sealed, children }: { sealed: boolean; children: ReactNode }) {
  return (
    <div className={`seal${sealed ? " sealed" : ""}`}>
      <svg viewBox="0 0 128 128" aria-hidden="true">
        <defs><clipPath id="seal-bars">{BARS.map((y) => <rect key={y} x="-1" y={y} width="170" height="32" />)}</clipPath></defs>
        <g transform="translate(22 14) scale(0.5)">
          <path className="zero" fillRule="evenodd" clipPath="url(#seal-bars)" d={ZERO} />
          <circle className="dot-mark" cx="84" cy="100" r="21" />
        </g>
      </svg>
      <div className="stack">{children}</div>
    </div>
  );
}

export function Paths({ items, max = 30 }: { items?: string[]; max?: number }) {
  const [all, setAll] = useState(false);
  if (!items?.length) return <span className="muted">none</span>;
  const shown = all ? items : items.slice(0, max);
  return (
    <div className="paths">
      {shown.map((p) => <span key={p} className="path">{p}</span>)}
      {items.length > max && !all && <button className="btn small quiet" onClick={() => setAll(true)}>Show {items.length - max} more</button>}
    </div>
  );
}

const icon = (d: string) => () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={d} /></svg>
);
export const Icons = {
  home: icon("M3 11.5 12 4l9 7.5M5.5 9.5V20h13V9.5"),
  activity: icon("M3 12h4l3-8 4 16 3-8h4"),
  repos: icon("M4 5h7l2 2h7v12H4zM4 9h16"),
  machines: icon("M4 5h16v11H4zM9 20h6M12 16v4"),
  guide: icon("M5 4h10a4 4 0 0 1 4 4v12H9a4 4 0 0 1-4-4zM9 8h6M9 12h6"),
  settings: icon("M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM4 12h2M18 12h2M12 4v2M12 18v2M6.3 6.3l1.4 1.4M16.3 16.3l1.4 1.4M6.3 17.7l1.4-1.4M16.3 7.7l1.4-1.4"),
};
