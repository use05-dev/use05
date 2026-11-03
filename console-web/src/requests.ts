// Which approval requests are still the person's to answer. The machine asks again each time the
// work changes (a new tree is a new ask) and every ask stays in the console, so a long task piles
// up old ones. One per piece of work is current: the newest. The rest were superseded by it.

type Ask = { repo_id: string; task_id?: string; tree?: string; from?: string; created_at?: string };

const keyOf = (a: Ask) => `${a.repo_id}/${a.from === "ci" ? `ci:${a.tree}` : a.task_id}`;

/// The asks that are not superseded by a newer one for the same work.
export function currentRequests<T extends Ask>(asks: T[]): Set<T> {
  const newest = new Map<string, T>();
  for (const a of asks) {
    const c = newest.get(keyOf(a));
    if (!c || String(a.created_at) > String(c.created_at)) newest.set(keyOf(a), a);
  }
  return new Set(newest.values());
}
