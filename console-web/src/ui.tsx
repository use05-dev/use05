import { useCallback, useEffect, useState, type ReactNode, type MouseEvent } from "react";
import { get } from "./api";

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

const DECISION_WORDS: Record<string, string> = { allow: "Allowed", approval_required: "Needs you", deny: "Refused", wait: "Waiting" };
export function Verdict({ decision }: { decision?: string | null }) {
  if (!decision) return <span className="verdict v-none">No decision yet</span>;
  return <span className={`verdict v-${decision}`}>{DECISION_WORDS[decision] ?? decision}</span>;
}

export function Online({ on }: { on: boolean }) {
  return <span className={`dot${on ? " on" : ""}`} role="img" aria-label={on ? "online" : "offline"} />;
}

/// The 05 ring with its gap. Unsealed, the dot waits outside; sealed, it closes the gap.
export function Seal({ sealed, children }: { sealed: boolean; children: ReactNode }) {
  const rings = [40, 46, 52, 58];
  return (
    <div className={`seal${sealed ? " sealed" : ""}`}>
      <svg viewBox="0 0 128 128" aria-hidden="true">
        {rings.map((r) => <circle key={r} className="engraving" cx="64" cy="64" r={r} />)}
        <path className="ring" d="M 98.3 41.7 A 41 41 0 1 1 86.3 29.6" />
        <circle className="dot-mark" cx="94" cy="34" r="9" />
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
