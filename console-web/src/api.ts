// Every call carries x-05, which the server requires on changes: a page on another site cannot
// send it without the browser asking the server first, and the server never agrees.
export class ApiError extends Error {}

// A session lasts an hour from when the person last did something here. Pages also ask on their
// own, to stay current; those requests say whether the person was active lately, so an open tab
// nobody looks at does not keep anyone signed in.
let lastActive = Date.now();
if (typeof window !== "undefined") {
  for (const e of ["pointerdown", "keydown", "wheel", "touchstart"]) window.addEventListener(e, () => (lastActive = Date.now()), { capture: true, passive: true });
  document.addEventListener("visibilitychange", () => document.visibilityState === "visible" && (lastActive = Date.now()));
}
const ACTIVE_MS = 2 * 60 * 1000;

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const active: Record<string, string> = Date.now() - lastActive < ACTIVE_MS ? { "x-05-active": "1" } : {};
  const res = await fetch(`/api${path}`, {
    method,
    credentials: "same-origin",
    headers: { "x-05": "1", ...active, ...(body === undefined ? {} : { "content-type": "application/json" }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  // The session ended (an hour unused, or signed out elsewhere): back to the sign-in page.
  if (res.status === 401 && path !== "/me") window.dispatchEvent(new Event("use05-signed-out"));
  if (!res.ok) throw new ApiError(data.error ?? `The console answered ${res.status}.`);
  return data as T;
}

export const get = <T = any>(path: string) => call<T>("GET", path);
export const post = <T = any>(path: string, body: unknown = {}) => call<T>("POST", path, body);
export const put = <T = any>(path: string, body: unknown = {}) => call<T>("PUT", path, body);

export type Change = { path: string; value: unknown };

/// How long ago, in the words a person would use. Past a week it is the date, because "12 d ago"
/// says nothing about which day.
export function ago(when?: string | null): string {
  if (!when) return "never";
  const t = new Date(when).getTime();
  if (Number.isNaN(t)) return "unknown";
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 50) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  if (s < 172800) return "yesterday";
  if (s < 7 * 86400) return `${Math.round(s / 86400)} d ago`;
  return new Date(t).toLocaleDateString(undefined, { day: "numeric", month: "short", ...(s > 300 * 86400 ? { year: "numeric" } : {}) });
}

/// The line under a task's verdict saying how much it rests on (D101): the machine's own words from
/// the task's sealed record, or nothing when the record has none. Never worked out here.
export function checksLine(detail?: { assurance?: { summary?: unknown } } | null): string | null {
  const summary = detail?.assurance?.summary;
  return typeof summary === "string" && summary ? `Checks: ${summary}` : null;
}

/// The task's story (D102) as the machine sent it, in rows labelled by where each comes from. The
/// person's request and the agent's own words stay on its machine, so the agent's row only counts
/// its claims. Nothing here is worked out by the browser.
export function storyRows(detail?: { story?: any } | null): { label: string; text: string; attention?: boolean }[] {
  const s = detail?.story;
  if (!s || typeof s !== "object") return [];
  const words = (v: unknown) => (Array.isArray(v) ? v.filter((x) => typeof x === "string") : []);
  const rows: { label: string; text: string; attention?: boolean }[] = [];
  const c = s.claim_counts ?? {};
  const n = (k: string) => (typeof c[k] === "number" ? c[k] : 0);
  const parts = [n("contradicted") && `${n("contradicted")} contradicted by a check`, n("supported") && `${n("supported")} backed by a check`, n("unsupported") && `${n("unsupported")} with no check of its kind`].filter(Boolean);
  rows.push({ label: "Agent says", text: parts.length ? `its claims: ${parts.join(", ")} (its words stay on its machine)` : "its words stay on its machine", attention: n("contradicted") > 0 });
  for (const o of words(s.observed)) rows.push({ label: "05 saw", text: o });
  if (typeof s.checked === "string" && s.checked) rows.push({ label: "Checked", text: s.checked });
  for (const x of words(s.needs_you)) rows.push({ label: "Needs you", text: x, attention: true });
  const unknown = words(s.not_known);
  if (unknown.length) rows.push({ label: "Not known", text: unknown.join("; ") });
  return rows;
}

/// What an environment's newest deployment record says (D93), in the machine's terms: never more
/// than the record. No record, or one with no probes, says 05 cannot tell what runs there.
export function deployWords(env?: { deployed?: { confirmed?: unknown; probes?: unknown; action?: unknown } | null } | null): string {
  const d = env?.deployed;
  if (!d) return "no deploy record";
  if (d.probes === 0) return "no probes: 05 cannot tell what it runs";
  if (d.confirmed === true) return "deploy confirmed";
  if (d.action === "reverted") return "not confirmed, reverted";
  if (d.action === "rollback-command") return "not confirmed, rollback command run";
  return "deploy not confirmed";
}

/// How many commits wait to come up from the environment below, or nothing.
export function waitingWords(env?: { waiting?: unknown; from?: unknown } | null): string | null {
  const n = env?.waiting;
  if (typeof n !== "number" || n <= 0 || typeof env?.from !== "string") return null;
  return `${n} commit${n === 1 ? "" : "s"} from ${env.from} can come up`;
}

/// The exact moment, in the person's own time zone: what a tooltip shows beside "3 h ago".
export function stamp(when?: string | null): string {
  if (!when) return "";
  const d = new Date(when);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString(undefined, { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
}
