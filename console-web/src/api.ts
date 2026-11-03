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

export function ago(when?: string | null): string {
  if (!when) return "never";
  const s = Math.max(0, (Date.now() - new Date(when).getTime()) / 1000);
  if (s < 50) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}
