// The team's work, as this browser sees it: the console relays sealed, signed records; here they
// are verified, opened and put back together into the views the pages show (D86). The console
// itself only knows who must approve what, and which machines and repositories exist.

import { useCallback, useEffect, useState } from "react";
import { get, post } from "./api";
import { b64, lock, openBaseWith, reread, sealBaseWith, unb64, unlocked } from "./keys";
import { seal } from "./crypto";
import { readPolicy } from "./policyWasm";
import { latestGates, machineKeys, madeAt, notRolledBack, openRecords, openSigned, trusted, type Opened } from "./opened";

type World = { overview: any; records: Opened[]; unverified: number; approvals: any[]; version: number };

let last: { at: number; world: Promise<World> } | null = null;

/// Everything, fetched and opened at most every couple of seconds however many views ask.
export function world(fresh = false): Promise<World> {
  if (!fresh && last && Date.now() - last.at < 2000) return last.world;
  const w = (async () => {
    let keys = await unlocked();
    if (!keys) throw new Error("Unlock your console first.");
    const [overview, rows] = await Promise.all([get("/overview"), get("/records")]);
    // The team's key changed since this tab unlocked (someone left). Another tab may have the new
    // one already; if not, unlock again for it.
    if ((overview.team_version ?? 0) > keys.version) {
      keys = await reread();
      if (!keys || (overview.team_version ?? 0) > keys.version) {
        await lock();
        window.location.reload();
        throw new Error("Your console has a new key; unlock again.");
      }
    }
    const opened = await openRecords(rows, overview.machines, keys);
    // Older copies of what this browser has seen newer are counted, not shown.
    const seen = JSON.parse(localStorage.getItem("use05-seen") ?? "{}");
    const fresh = notRolledBack(opened.records, seen);
    localStorage.setItem("use05-seen", JSON.stringify(seen));
    opened.records = fresh.kept;
    opened.unverified += fresh.rolledBack;
    // Approval requests are sealed and signed the same way; open each for the page.
    const signers = await machineKeys(overview.machines, keys);
    const approvals: any[] = [];
    for (const a of overview.approvals) {
      const signer = a.machine_id ? signers.get(a.machine_id) : undefined;
      const body = signer && a.sealed ? await openSigned("approval", a.repo_id, a.ref_key, a.sealed, a.sig, signer, keys).catch(() => null) : null;
      if (!body) {
        opened.unverified += 1;
        continue;
      }
      // What the machine said when filing it comes back sealed and signed too.
      const result = signer && a.result?.sealed ? await openSigned("result", a.repo_id, a.id, a.result.sealed, a.result.sig, signer, keys).catch(() => null) : null;
      approvals.push({ ...a, ...body, task_id: body.task, result: result ? (result.ok ? result.result : { reason: result.result?.reason }) : null });
    }
    // Work its person threw away (D89): the machine keeps only a marker; nothing of it is shown,
    // and what this browser can tell belongs to it (it can read the records) the console forgets.
    const gone = new Set(opened.records.filter((r) => r.kind === "task" && r.body?.status === "discarded").map((r) => `${r.repo}/${r.body.id}`));
    const of = (repo: string, task: unknown) => typeof task === "string" && gone.has(`${repo}/${task}`);
    const leftovers = opened.records.filter((r) => r.kind !== "task" && of(r.repo, r.body?.task));
    const stale = approvals.filter((a) => of(a.repo_id, a.task_id));
    if (leftovers.length || stale.length) void forgetFor(overview, leftovers, stale);
    const records = opened.records.filter((r) => !(r.kind === "task" && gone.has(`${r.repo}/${r.body?.id}`)) && !of(r.repo, r.body?.task));
    return { overview, records, unverified: opened.unverified, approvals: approvals.filter((a) => !of(a.repo_id, a.task_id)), version: keys.version };
  })();
  last = { at: Date.now(), world: w };
  return w;
}

/// Ask the console to forget what belongs to discarded work: what this person's own machines
/// reported, once per record.
const forgotten = new Set<string>();
async function forgetFor(overview: any, records: Opened[], approvals: any[]) {
  const mine = new Set(overview.machines.filter((m: any) => m.member_id === overview.me).map((m: any) => m.id));
  const byRepo = new Map<string, { records: { kind: string; ref: string }[]; approvals: string[] }>();
  const add = (repo: string) => byRepo.get(repo) ?? byRepo.set(repo, { records: [], approvals: [] }).get(repo)!;
  for (const r of records.filter((r) => mine.has(r.machine) && !forgotten.has(`${r.kind}/${r.repo}/${r.ref}`))) {
    forgotten.add(`${r.kind}/${r.repo}/${r.ref}`);
    add(r.repo).records.push({ kind: r.kind, ref: r.ref });
  }
  for (const a of approvals.filter((a) => mine.has(a.machine_id) && !forgotten.has(`approval/${a.id}`))) {
    forgotten.add(`approval/${a.id}`);
    add(a.repo_id).approvals.push(a.id);
  }
  for (const [repo, what] of byRepo) await post("/forget", { repo, ...what }).catch(() => undefined);
}

/// A machine's sealed, signed answer (a prepared policy edit, a reason it could not apply one).
export async function openResult(machineId: string | null, repo: string, ref: string, result: any): Promise<any | null> {
  if (!machineId || !result?.sealed) return null;
  const keys = await unlocked();
  if (!keys) return null;
  const signer = (await machineKeys((await world()).overview.machines, keys)).get(machineId);
  if (!signer) return null;
  return openSigned("result", repo, ref, result.sealed, result.sig, signer, keys).catch(() => null);
}

/// Seal something for one machine only: what it alone should read (a signed approval, the commit to
/// apply), for one kind of instruction. The body names the repository and the request or edit it is
/// for; the machine refuses it routed as anything else.
export async function sealTo(machineId: string, kind: "file_approval" | "prepare_policy_edit" | "apply_policy_edit" | "prepare_testing" | "file_testing" | "prepare_discard" | "discard", body: Record<string, unknown>): Promise<string> {
  const m = (await world(true)).overview.machines.find((x: any) => x.id === machineId);
  const keys = await unlocked();
  // Only to keys the team pinned: a key the console swapped in gets nothing.
  if (!m?.x_pub || !keys || !(await trusted(m, keys))) throw new Error("That machine's keys are not the ones you paired. Do not continue; pair it again.");
  return b64(await seal(unb64(m.x_pub), new TextEncoder().encode(JSON.stringify(body)), new TextEncoder().encode(`use05 instruction ${kind}`)));
}


/// The base template, sealed and vouched for under the team's current keys, for storing.
export async function sealBase(toml: string): Promise<string> {
  const keys = await unlocked();
  if (!keys?.pinKey) throw new Error("Unlock your console first.");
  return sealBaseWith(keys.teamPub, keys.pinKey, toml);
}

const machineName = (w: World, id?: string | null) => {
  const m = w.overview.machines.find((x: any) => x.id === id);
  if (!m) return null;
  // A cloud session or CI token speaks for one repository; its name says which, worked out here.
  return m.repo_only ? `${m.name} (${repoName(w, m.repo_only)})` : m.name;
};
const repoBody = (w: World, id: string) => w.records.find((r) => r.kind === "repo" && r.repo === id)?.body;
const repoName = (w: World, id: string) => repoBody(w, id)?.name ?? "a repository";

const ABANDONED_MS = 7 * 24 * 3600 * 1000;

function tasks(w: World, repo?: string) {
  // The latest gate a machine reported for a task is its verdict, once newer than the task record.
  const gate = latestGates(w.records);
  return w.records
    .filter((r) => r.kind === "task" && (!repo || r.repo === repo))
    .map((r) => {
      const t = r.body;
      const g = gate.get(`${r.repo}/${t.id}`);
      return {
        ...t, repo_id: r.repo, repo: repoName(w, r.repo), machine: machineName(w, r.machine), machine_id: r.machine, updated_at: r.at,
        created_at: t.created, finished_at: t.finished, ended_at: t.ended,
        decision: g && g.at >= madeAt(r) ? g.decision : t.decision,
        // Not touched for a week and not done: probably left behind (D89). Nothing is deleted for it.
        abandoned: (t.status === "active" || (g?.decision ?? t.decision) === "approval_required") && Date.now() - new Date(r.at).getTime() > ABANDONED_MS,
      };
    })
    .sort((a, b) => (a.updated_at < b.updated_at ? 1 : -1));
}

/// The views the pages read, by the paths they used to fetch.
export async function view(path: string): Promise<any> {
  const w = await world();
  const p = path.split("?")[0].split("/").filter(Boolean);
  const titleOf = (repo: string, task: string) => w.records.find((r) => r.kind === "task" && r.repo === repo && r.body.id === task)?.body.title;
  const approvals = w.approvals.map((a) => ({ ...a, repo: repoName(w, a.repo_id), title: titleOf(a.repo_id, a.task_id) ?? (a.from === "ci" ? "Work CI holds for a person" : undefined) }));
  if (p[0] === "overview") {
    const all = tasks(w);
    const repos = w.records.filter((r) => r.kind === "repo").map((r) => ({
      id: r.repo, name: r.body.name, landing: r.body.landing, updated_at: r.at,
      active: all.filter((t) => t.repo_id === r.repo && t.status === "active").length,
      last_task: all.find((t) => t.repo_id === r.repo)?.updated_at ?? null,
    }));
    const open = approvals.filter((a) => ["waiting", "signed", "failed"].includes(a.status));
    const yours = (t: any) => w.overview.machines.some((m: any) => m.id === t.machine_id && m.member_id === w.overview.me);
    // Work whose last check says a person must approve it, but whose machine has not asked here
    // (the session ended before it finished, say): it needs you all the same.
    const held = all.filter((t) => t.decision === "approval_required" && yours(t) && !open.some((a) => a.task_id === t.id && a.repo_id === t.repo_id));
    const edits = w.overview.edits.map((e: any) => ({ ...e, repo: repoName(w, e.repo_id) }));
    // One count for the page's headline and the menu: everything waiting on you to act.
    const needs_you = open.filter((a) => a.status === "waiting" && a.mine !== false).length + held.length + w.overview.pairings.length + edits.filter((e: any) => e.status === "ready" || e.status === "stuck").length;
    return {
      ...w.overview, approvals: open, edits, held, needs_you,
      repos, tasks: all.slice(0, 30), unverified: w.unverified,
      // Your machines still sealing to the team's key from before someone left: by what the
      // console says, and by what their newest record opened with, which it cannot fake.
      old_key: w.overview.machines.filter((m: any) => {
        if (m.member_id !== w.overview.me || !m.ed_pub || (m.kind ?? "machine") !== "machine") return false;
        const newest = w.records.filter((r) => r.machine === m.id).sort((a, b) => (a.at < b.at ? 1 : -1))[0];
        return (m.team_version ?? 0) < w.version || !!newest?.old;
      }),
      // What machines refused, in their own words, opened here; the console kept only that it happened.
      refusals: w.records.filter((r) => r.kind === "refusal").map((r) => ({ at: r.at, actor: `machine:${machineName(w, r.machine) ?? "a machine"}`, detail: { what: r.body.what, why: r.body.why } })).sort((a, b) => (a.at < b.at ? 1 : -1)).slice(0, 20),
    };
  }
  if (p[0] === "activity") {
    return w.records
      .filter((r) => r.kind === "event")
      .map((r) => ({ id: `${r.repo}/${r.ref}`, kind: r.body.kind, task_id: r.body.task, data: r.body.data ?? {}, at: r.at, repo: repoName(w, r.repo), repo_id: r.repo, machine: machineName(w, r.machine), title: r.body.task ? titleOf(r.repo, r.body.task) : null }))
      .sort((a, b) => (a.at < b.at ? 1 : -1))
      .slice(0, 200);
  }
  if (p[0] === "repos" && p[2] === "tree") {
    const t = w.records.find((r) => r.kind === "tree" && r.repo === p[1]);
    return { tree: t?.body.paths ?? null, tree_at: t?.at ?? null };
  }
  if (p[0] === "repos") {
    const body = repoBody(w, p[1]);
    if (!body) throw new Error("No machine has reported this repository yet, or its records could not be verified.");
    const server = await get(`/repos/${p[1]}`);
    const policy = await readPolicy(body.policy_toml ?? "");
    // What each edit changes, as the machine that prepared it signed it.
    const edits = await Promise.all(server.edits.map(async (e: any) => ({ ...e, summary: (await openResult(e.machine_id, p[1], e.id, e.prepared))?.result?.changed ?? [] })));
    // The newest verdict CI sent, sealed like the rest (D86); none means CI was not seen.
    const ci = w.records.filter((r) => r.kind === "ci" && r.repo === p[1]).sort((a, b) => (madeAt(a) < madeAt(b) ? 1 : -1))[0];
    return { ...server, edits, repo: { ...body, id: p[1] }, policy, tasks: tasks(w, p[1]), ci: ci ? { ...ci.body, at: madeAt(ci) } : null };
  }
  if (p[0] === "tasks") {
    let t: any = tasks(w, p[1]).find((x) => x.id === p[2]);
    // Work CI holds that no 05 session did (D86): no task record, only CI's approval request.
    if (!t && approvals.some((a) => a.repo_id === p[1] && a.task_id === p[2])) {
      t = { id: p[2], title: "Work CI holds for a person", repo_id: p[1], repo: repoName(w, p[1]), status: "held by CI", detail: {}, agent: "No 05 session", updated_at: new Date().toISOString() };
    }
    if (!t) throw new Error("There is no such task, or its record could not be verified.");
    return {
      task: t,
      approvals: approvals.filter((a) => a.repo_id === p[1] && a.task_id === p[2]),
      events: w.records.filter((r) => r.kind === "event" && r.repo === p[1] && r.body.task === p[2]).map((r) => ({ kind: r.body.kind, data: r.body.data ?? {}, at: r.at, machine: machineName(w, r.machine) })).sort((a, b) => (a.at < b.at ? 1 : -1)),
      me: w.overview.me,
      // Whether this repository asks for testing before a push, and may skip it (D87).
      testing: (await readPolicy(repoBody(w, p[1])?.policy_toml ?? "")).policy?.testing ?? null,
      // Yours to sign off from here when one of your machines paired at a terminal did it: a
      // cloud session or CI takes no work, so its work is signed off at a terminal.
      mine: w.overview.machines.some((m: any) => m.id === t.machine_id && m.member_id === w.overview.me && (m.kind ?? "machine") === "machine"),
    };
  }
  if (p[0] === "edits") {
    const server = await get(path);
    const e = server.edit;
    return { ...server, edit: { ...e, repo: repoName(w, e.repo_id) } };
  }
  if (p[0] === "base") {
    const { sealed } = await get("/base");
    const keys = await unlocked();
    if (!keys?.pinKey) throw new Error("Unlock your console first.");
    const toml = (await openBaseWith(keys.team, keys.teamPub, keys.pinKey, sealed)) ?? "";
    return { toml, policy: await readPolicy(toml) };
  }
  if (p[0] === "approvals") {
    const a = approvals.find((x) => x.id === p[1]);
    if (!a) throw new Error("There is no such approval request, or it could not be verified.");
    const server = await get(`/approvals/${p[1]}`);
    return { ...server, request: { ...server.request, ...a } };
  }
  return get(path);
}

/// Like useData, for views put together from the team's records.
// Told by the console the moment anything changes, every open view looks again; polling stays as a
// fallback for when the stream is down.
const watchers = new Set<() => void>();
let stream: EventSource | null = null;
function live() {
  if (stream || typeof EventSource === "undefined") return;
  stream = new EventSource("/api/changes");
  stream.onmessage = () => {
    last = null;
    watchers.forEach((w) => w());
  };
  stream.onerror = () => {
    // It reconnects by itself after a network blip; refused (signed out), try again later.
    if (stream?.readyState === EventSource.CLOSED) {
      stream = null;
      setTimeout(() => watchers.size > 0 && live(), 10000);
    }
  };
}
if (typeof document !== "undefined") {
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState !== "visible") return;
    last = null;
    watchers.forEach((w) => w());
  });
}

export function useView<T = any>(path: string | null, every = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => {
    if (!path) return;
    try {
      setData(await view(path));
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }, [path]);
  useEffect(() => {
    setData(null);
    load();
    // A view that keeps itself current also follows changes as they happen; one that does not (an
    // editor, holding what the person is typing) is left alone.
    if (!every) return;
    live();
    watchers.add(load);
    const t = setInterval(() => document.visibilityState === "visible" && load(), every);
    return () => {
      watchers.delete(load);
      clearInterval(t);
    };
  }, [load, every]);
  return { data, error, reload: async () => { await world(true); await load(); } };
}
