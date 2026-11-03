import { createContext, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { post, put, type Change } from "../api";
import { Link, Loading, go } from "../ui";
import { sealBase, sealTo, useView, view, world } from "../records";
import { baseChanges, previewEdit } from "../policyWasm";
import { settingName } from "./Edit";

// What the console may change. Anything else is shown, and changed at a terminal.
const KEYS = [
  "intent.mode",
  "protect.paths", "protect.locked", "protect.append_only", "protect.no_delete", "protect.no_read",
  "drift.scope", "drift.dependencies", "drift.overlap", "drift.claims", "drift.tests", "drift.reservation_idle_hours",
  "evidence.stop_budget_secs", "evidence.prove_at_push",
  "approvals.expire_days",
  "record.middle",
  "risk.rules", "risk.exempt",
  "branches.keep", "branches.work", "branches.target", "branches.land", "branches.fresh_base",
  "environment", "require", "check",
  "testing.local", "testing.branches",
];

const at = (o: any, path: string) => path.split(".").reduce((v, k) => (v == null ? undefined : v[k]), o);
const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v));
function setAt(o: any, path: string, value: unknown) {
  const parts = path.split(".");
  const last = parts.pop()!;
  const parent = parts.reduce((v, k) => (v[k] ??= {}), o);
  parent[last] = value;
}

// 05 leaves settings out when they hold their defaults; the editor shows them all.
function withDefaults(p: any) {
  const n = clone(p);
  n.protect = { paths: [], locked: [], absolute: [], append_only: [], no_delete: [], no_read: [], bypass: true, ...n.protect };
  n.branches = { keep: [], work: [], target: null, land: "manual", fresh_base: "allow", ...n.branches };
  n.risk = { rules: [], exempt: [], locked: [], ...n.risk };
  n.trust = { key: [], ...n.trust };
  n.env = { allow: null, ...n.env };
  n.environment ??= [];
  n.require ??= [];
  n.check ??= [];
  n.testing = { local: "off", branches: [], ...n.testing };
  return n;
}

function changesBetween(a: any, b: any): Change[] {
  return KEYS.filter((k) => JSON.stringify(at(a, k) ?? null) !== JSON.stringify(at(b, k) ?? null)).map((k) => ({ path: k, value: at(b, k) ?? null }));
}

export function PolicyEditor({ repo }: { repo?: string }) {
  const repoView = useView<any>(repo ? `/repos/${repo}` : null);
  const baseData = useView<any>(repo ? null : "/base");
  const { data, error, reload } = repo ? repoView : baseData;
  const tree = useView<any>(repo ? `/repos/${repo}/tree` : null);
  const [draft, setDraft] = useState<any>(null);
  const [preview, setPreview] = useState<any>(null);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [showToml, setShowToml] = useState(false);

  const original = useMemo(() => (data?.policy?.policy ? withDefaults(data.policy.policy) : null), [data]);
  useEffect(() => { if (original) setDraft(clone(original)); }, [original]);
  const changes = useMemo(() => (original && draft ? changesBetween(original, draft) : []), [original, draft]);

  // Work out here what the file would become, after a short pause in typing: the console cannot read it.
  // The base policy is a template, not a repository's rules, so it may loosen.
  const timer = useRef<number>(0);
  useEffect(() => {
    window.clearTimeout(timer.current);
    if (!changes.length) return setPreview(null);
    timer.current = window.setTimeout(async () => {
      const p = await previewEdit(repo ? data?.repo?.policy_toml ?? "" : data?.toml ?? "", changes, repo ? data?.repo?.detected_checks ?? [] : []).catch((e) => ({ ok: false, error: e.message }));
      setPreview(repo ? p : { ...p, terminal_only: [], loosens: [] });
    }, 400);
  }, [JSON.stringify(changes)]);

  if (!data) return <Loading error={error} />;
  if (!data.policy.ok) return <div className="stack"><h1>Policy</h1><p className="error">{data.policy.error}</p><p className="muted">Fix the file at a terminal (<code>use05 policy</code> explains it), then come back.</p></div>;
  if (!draft) return <Loading />;

  const edit = (path: string, value: unknown) => setDraft((d: any) => { const n = clone(d); setAt(n, path, value); return n; });
  const changed = (path: string) => changes.some((c) => c.path === path || c.path.startsWith(path + "."));
  const paths: string[] = tree.data?.tree ?? [];
  const detected: any[] = data.repo?.detected_checks ?? [];

  // Save these changes only: all of them, or one rule's (D88). Each is its own signed edit.
  const submit = async (list: Change[]) => {
    setSaving(true);
    setMessage(null);
    try {
      const whole = list.length === changes.length;
      const p: any = whole ? preview : await previewEdit(repo ? data.repo.policy_toml ?? "" : data.toml ?? "", list, repo ? detected : []);
      if (!p?.ok) throw new Error(p?.error ?? "Wait for the preview.");
      if (repo && (p.loosens?.length || p.terminal_only?.length)) throw new Error("From here, rules can only get stricter; change this at a terminal.");
      if (repo) {
        // Your own machine with this repository prepares it: it trusts your passkeys.
        const { overview } = await world(true);
        const machine = overview.machines.find((m: any) => m.member_id === overview.me && !m.revoked && overview.repo_machines.some((r: any) => r.repo_id === repo && r.machine_id === m.id && r.allowed));
        if (!machine) throw new Error("None of your machines has this repository. Pair the machine you work on, then save again.");
        const edit = crypto.randomUUID();
        const r = await post(`/repos/${repo}/policy/save`, {
          id: edit,
          machine: machine.id,
          sealed: await sealTo(machine.id, "prepare_policy_edit", { edit, repo, toml: p.toml, base_rev: data.repo.policy_rev ?? null }),
        });
        go(`/edits/${r.edit}`);
      } else {
        await put("/base", { sealed: await sealBase(p.toml) });
        setMessage("Saved. New repositories can start from it; existing ones are not changed.");
        reload();
      }
    } catch (e) {
      setMessage((e as Error).message);
    } finally {
      setSaving(false);
    }
  };
  const save = () => submit(changes);
  const saveRule = (rules: string[]) => submit(changes.filter((c) => rules.some((r) => c.path === r || c.path.startsWith(r + ".") || r.startsWith(c.path + "."))));

  const applyBase = async () => {
    const text = (await view("/base")).toml;
    const r = await baseChanges(text);
    if (!r.ok) return setMessage(r.error);
    const base = r.changes;
    // A setting the template leaves out comes back as its default, as the page shows it.
    setDraft((d: any) => { const n = clone(d); for (const c of base) setAt(n, c.path, c.value); return withDefaults(n); });
  };

  const blocked = preview?.terminal_only?.length > 0 || preview?.loosens?.length > 0 || preview?.ok === false;

  return (
    <SaveRule.Provider value={{ save: saveRule, changed, saving, several: changes.length > 1 }}>
    <div className="stack-lg">
      <div className="hd">
        <div>
          <p className="small">{repo ? <Link to={`/repos/${repo}`}>{data.repo.name}</Link> : <Link to="/repos">Repositories</Link>}</p>
          <h1>{repo ? "Policy" : "Base policy"}</h1>
          <p className="muted">{repo ? <>The rules in <code>.05/policy.toml</code> on <code>{data.repo.landing}</code>. Saving prepares the change on your Mac; your passkey signs it, and it lands as a commit.</> : "Your starting template. Apply it to a repository from that repository's policy page; it copies these settings once and keeps the repository's checks and keys."}</p>
        </div>
        {repo && <button className="btn quiet" onClick={applyBase}>Use base policy</button>}
      </div>

      <Section title="Folders and files" rules={["protect"]} help="Pick folders or files from the repository, or type a pattern such as src/**/migrations/*.sql.">
        <PathRules draft={draft} edit={edit} changed={changed} paths={paths} refresh={repo ? async () => { await post(`/repos/${repo}/tree/refresh`); setTimeout(tree.reload, 2500); } : undefined} />
      </Section>

      <Section title="Plans" help="When an agent must declare what it will do and where, before it starts.">
        <Setting name="Ask for a plan" changed={changed("intent.mode")} rule="intent.mode" help="Inferred: 05 works it out from the first edits. Risky: risky changes need a declared plan. Always: every task does.">
          <Choice value={draft.intent.mode} options={[["inferred", "Inferred"], ["risky", "For risky work"], ["always", "Always"]]} onChange={(v) => edit("intent.mode", v)} />
        </Setting>
      </Section>

      <Section title="Testing before a push" help="A person tries the change in their own environment and signs off, with a note, before it is pushed to these branches. The push waits until they do, here and in CI.">
        <Setting name="Ask the developer to try it" changed={changed("testing.local")} rule="testing.local" help="Off. Skippable: they may skip it, saying why. Required: only a sign-off counts.">
          <Choice value={draft.testing.local} options={[["off", "Off"], ["skippable", "Skippable"], ["required", "Required"]]} onChange={(v) => edit("testing.local", v)} />
        </Setting>
        <Setting name="For pushes to" changed={changed("testing.branches")} rule="testing.branches" help="Branch patterns such as main or release/*. None: the branch changes land on.">
          <Chips items={draft.testing.branches} onChange={(v) => edit("testing.branches", v)} />
        </Setting>
      </Section>

      <Section title="How strict" help="For each kind of problem: let it through, warn, ask a person, or refuse.">
        {([
          ["drift.scope", "Work outside the plan", "Files changed outside the declared scope."],
          ["drift.dependencies", "New dependencies", "A change adds packages."],
          ["drift.overlap", "Another agent's area", "Two agents working on the same files."],
          ["drift.claims", "Claims without evidence", "The agent says something works that no check showed."],
          ["drift.tests", "Weakened tests", "Tests removed, skipped or loosened."],
          ["branches.fresh_base", "Starting from old code", "An agent works from a base behind origin."],
        ] as const).map(([k, name, help]) => (
          <Setting key={k} name={name} help={help} changed={changed(k)} rule={k}>
            <Strictness value={at(draft, k)} onChange={(v) => edit(k, v)} />
          </Setting>
        ))}
        <Setting name="Reservations expire after" help="How long a quiet agent keeps its declared area to itself." changed={changed("drift.reservation_idle_hours")} rule="drift.reservation_idle_hours" inline>
          <Number value={draft.drift.reservation_idle_hours} unit="hours" onChange={(v) => edit("drift.reservation_idle_hours", v)} />
        </Setting>
      </Section>

      <Section title="Files that change together" rules={["require"]} help="When a change touches one place, another must change too: docs with the API, a changelog with releases.">
        <Requires draft={draft} edit={edit} paths={paths} />
      </Section>

      {repo && (
        <Section title="Checks" help="The commands 05 runs and signs. A check can be made optional or removed here; a command is only ever added at a terminal, or picked from what your machine found.">
          <Checks draft={draft} edit={edit} detected={detected} />
          <Setting name="Time for checks when an agent stops" changed={changed("evidence.stop_budget_secs")} rule="evidence.stop_budget_secs" inline help="Checks that fit run as the agent finishes.">
            <Number value={draft.evidence.stop_budget_secs} unit="seconds" onChange={(v) => edit("evidence.stop_budget_secs", v)} />
          </Setting>
          <Setting name="Run checks before a push" changed={changed("evidence.prove_at_push")} rule="evidence.prove_at_push" inline help="The pre-push gate proves what is missing.">
            <Switch on={draft.evidence.prove_at_push} onChange={(v) => edit("evidence.prove_at_push", v)} />
          </Setting>
        </Section>
      )}

      <Section title="Branches" help="Where work lands, and which branches 05 never deletes.">
        <Setting name="Changes land on" changed={changed("branches.target")} rule="branches.target" inline>
          <input type="text" style={{ maxWidth: 220 }} value={draft.branches.target ?? ""} placeholder="main" onChange={(e) => edit("branches.target", e.target.value.trim() || null)} />
        </Setting>
        <Setting name="Landing" changed={changed("branches.land")} rule="branches.land" help="Manual: a person runs use05 land. Auto: a change the gate allows lands when its agent stops." inline>
          <Choice value={draft.branches.land} options={[["manual", "Manual"], ["auto", "Auto"]]} onChange={(v) => edit("branches.land", v)} />
        </Setting>
        <Setting name="Never deleted" changed={changed("branches.keep")} rule="branches.keep"><Chips items={draft.branches.keep} onChange={(v) => edit("branches.keep", v)} placeholder="release/*" /></Setting>
        <Setting name="Agents' work branches" changed={changed("branches.work")} rule="branches.work"><Chips items={draft.branches.work} onChange={(v) => edit("branches.work", v)} placeholder="agent/*" /></Setting>
      </Section>

      <Section title="Environments" help="Which branch is which environment, lowest first. Recorded and shown; promotion rules come later.">
        <Environments draft={draft} edit={edit} />
      </Section>

      <Section title="Risk" help="Extra risk categories, on top of 05's own (secrets, auth, migrations, CI and more).">
        <RiskRules draft={draft} edit={edit} />
        <Setting name="Not risky after all" changed={changed("risk.exempt")} rule="risk.exempt" help="Paths a category pattern catches by mistake."><Chips items={draft.risk.exempt} onChange={(v) => edit("risk.exempt", v)} placeholder="docs/**/secrets.md" /></Setting>
      </Section>

      <Section title="Approvals and recording">
        <Setting name="Approvals expire after" changed={changed("approvals.expire_days")} rule="approvals.expire_days" inline>
          <Number value={draft.approvals.expire_days} unit="days" onChange={(v) => edit("approvals.expire_days", v)} />
        </Setting>
        <Setting name="Record what agents do" changed={changed("record.middle")} rule="record.middle" help="Tool calls and file names, kept on your machine; never contents." inline>
          <Choice value={draft.record.middle} options={[["local", "On this machine"], ["off", "Off"]]} onChange={(v) => edit("record.middle", v)} />
        </Setting>
      </Section>

      <Section title="Set at a terminal" help="These decide what runs, what is trusted and what counts as proof, so a browser can never change them, even this one.">
        <dl className="kv">
          <dt>Approvals needed</dt><dd>{draft.approvals.min}</dd>
          <dt>Evidence accepted from</dt><dd>{draft.evidence.accept.join(", ")}</dd>
          <dt>If 05 itself fails</dt><dd>{draft.enforce.on_error === "open" ? "let work through (fail open)" : "stop work (fail closed)"}</dd>
          <dt>Locked for good</dt><dd>{draft.protect.absolute.length ? draft.protect.absolute.join(", ") : "nothing"}</dd>
          <dt>Break glass allowed</dt><dd>{draft.protect.bypass ? "yes" : "no"}</dd>
          <dt>Trusted keys</dt><dd>{draft.trust.key.length ? draft.trust.key.map((k: any) => `${k.name} (${k.role})`).join(", ") : "only this machine's"}</dd>
          <dt>Variables checks may see</dt><dd>{draft.env.allow ? draft.env.allow.join(", ") || "none" : "the default set"}</dd>
        </dl>
      </Section>

      {(changes.length > 0 || message) && (
        <div className="savebar" role="region" aria-label="Unsaved changes">
          <span>{changes.length ? `${preview?.changed?.length ?? changes.length} setting${(preview?.changed?.length ?? changes.length) === 1 ? "" : "s"} changed` : message}</span>
          {changes.length > 0 && <button className="btn small quiet" style={{ color: "var(--page)", borderColor: "rgba(255,255,255,.4)", background: "transparent" }} onClick={() => setShowToml((s) => !s)}>{showToml ? "Hide the file" : "Show the file"}</button>}
          {changes.length > 0 && <button className="btn small quiet" style={{ color: "var(--page)", borderColor: "rgba(255,255,255,.4)", background: "transparent" }} onClick={() => setDraft(clone(original))}>Discard</button>}
          {changes.length > 0 && <button className="btn primary small" disabled={saving || blocked || !preview} onClick={save}>{repo ? "Save and sign" : "Save template"}</button>}
          {preview?.ok === false && <p className="error" style={{ width: "100%" }}>{preview.error}</p>}
          {preview?.terminal_only?.length > 0 && <p className="error" style={{ width: "100%" }}>Only a terminal can change {preview.terminal_only.join(", ")}.</p>}
          {preview?.loosens?.length > 0 && <p className="error" style={{ width: "100%" }}>Loosen these at a terminal: {preview.loosens.map(settingName).join(", ")}. From here, rules can only get stricter.</p>}
          {message && changes.length > 0 && <p className="error" style={{ width: "100%" }}>{message}</p>}
        </div>
      )}
      {showToml && preview?.toml && <pre className="toml">{preview.toml}</pre>}
    </div>
    </SaveRule.Provider>
  );
}

function Section({ title, help, rules, children }: { title: string; help?: string; rules?: string[]; children: ReactNode }) {
  return (
    <section className="panel">
      <h2>{title} {rules && <SaveThis rules={rules} />}</h2>
      {help && <p className="muted small" style={{ marginTop: 4, maxWidth: "62ch" }}>{help}</p>}
      <div style={{ marginTop: 6 }}>{children}</div>
    </section>
  );
}

/// Saving one rule on its own (D88), from where it is edited.
const SaveRule = createContext<{ save: (rules: string[]) => void; changed: (path: string) => boolean; saving: boolean; several: boolean } | null>(null);

/// "Save this rule": shown beside a changed rule when other changes are waiting too.
function SaveThis({ rules }: { rules: string[] }) {
  const ctx = useContext(SaveRule);
  if (!ctx || !ctx.several || !rules.some((r) => ctx.changed(r))) return null;
  return <button type="button" className="btn small quiet" disabled={ctx.saving} onClick={() => ctx.save(rules)}>Save this rule</button>;
}

function Setting({ name, help, changed, inline, rule, children }: { name: string; help?: string; changed?: boolean; inline?: boolean; rule?: string; children: ReactNode }) {
  return (
    <div className={`setting${inline ? " inline" : ""}`}>
      <div className="text">
        <div className="name">{name} {changed && <span className="changed-mark">changed</span>} {rule && <SaveThis rules={[rule]} />}</div>
        {help && <div className="help">{help}</div>}
      </div>
      <div className="control">{children}</div>
    </div>
  );
}

const STEPS = [["allow", "Let it"], ["warn", "Warn"], ["approval", "Ask me"], ["deny", "Refuse"]] as const;
function Strictness({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <div className={`scale s-${value}`} role="group">
      {STEPS.map(([v, label]) => <button key={v} type="button" aria-pressed={value === v} onClick={() => onChange(v)}>{label}</button>)}
    </div>
  );
}

function Choice({ value, options, onChange }: { value: string; options: readonly (readonly [string, string])[]; onChange: (v: string) => void }) {
  return (
    <div className="scale" role="group" style={{ gridTemplateColumns: `repeat(${options.length}, minmax(0, 1fr))`, minWidth: 0 }}>
      {options.map(([v, label]) => <button key={v} type="button" aria-pressed={value === v} onClick={() => onChange(v)}>{label}</button>)}
    </div>
  );
}

function Switch({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) {
  return <button type="button" role="switch" aria-checked={on} className="switch" onClick={() => onChange(!on)} />;
}

function Number({ value, unit, onChange }: { value: number; unit: string; onChange: (v: number) => void }) {
  return <label className="row"><input type="number" min={0} style={{ width: 96 }} value={value} onChange={(e) => onChange(Math.max(0, parseInt(e.target.value || "0", 10)))} /> <span className="muted small">{unit}</span></label>;
}

function Chips({ items, onChange, placeholder }: { items: string[]; onChange: (v: string[]) => void; placeholder?: string }) {
  const [text, setText] = useState("");
  const add = () => { const t = text.trim(); if (t && !items.includes(t)) onChange([...items, t]); setText(""); };
  return (
    <div className="stack">
      {items.length > 0 && <div className="chips">{items.map((i) => <span key={i} className="chip">{i}<button aria-label={`Remove ${i}`} onClick={() => onChange(items.filter((x) => x !== i))}>×</button></span>)}</div>}
      <div className="row"><input type="text" className="grow" style={{ fontFamily: "var(--mono)", fontSize: 13, maxWidth: 360 }} value={text} placeholder={placeholder} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => e.key === "Enter" && add()} /><button className="btn small quiet" onClick={add} disabled={!text.trim()}>Add</button></div>
    </div>
  );
}

const RULES = [
  ["protect.paths", "Needs approval", "A person approves any change here."],
  ["protect.locked", "Locked", "Never changed; an approval does not unlock it."],
  ["protect.append_only", "Add only", "New files only; existing ones stay as they are (released migrations)."],
  ["protect.no_delete", "Never deleted", "Edits are fine; deleting or renaming is not."],
  ["protect.no_read", "Agents may not read", "Agents' hooks refuse to open these. Advisory."],
] as const;

function PathRules({ draft, edit, changed, paths, refresh }: { draft: any; edit: (p: string, v: unknown) => void; changed: (p: string) => boolean; paths: string[]; refresh?: () => void }) {
  const [rule, setRule] = useState<string>(RULES[0][0]);
  const list: string[] = at(draft, rule) ?? [];
  const current = RULES.find((r) => r[0] === rule)!;
  const toggle = (pattern: string) => edit(rule, list.includes(pattern) ? list.filter((p) => p !== pattern) : [...list, pattern]);
  return (
    <div className="stack">
      <div className="rule-tabs" role="group" aria-label="Which rule">
        {RULES.map(([k, label]) => (
          <button key={k} aria-pressed={rule === k} onClick={() => setRule(k)}>
            {label}{(at(draft, k) ?? []).length ? ` (${at(draft, k).length})` : ""}{changed(k) ? " •" : ""}
          </button>
        ))}
      </div>
      <p className="small muted">{current[2]}</p>
      <Chips items={list} onChange={(v) => edit(rule, v)} placeholder="a folder, file or pattern" />
      {paths.length > 0 ? <Tree paths={paths} picked={list} toggle={toggle} /> : (
        <p className="small muted">{refresh ? <>The folder tree has not arrived from your machine yet. <button className="btn small quiet" onClick={refresh}>Ask for it</button></> : "The base policy has no repository to pick folders from; type patterns instead."}</p>
      )}
    </div>
  );
}

type Node = { name: string; path: string; dir: boolean; children: Map<string, Node> };
function build(paths: string[]): Node {
  const root: Node = { name: "", path: "", dir: true, children: new Map() };
  for (const p of paths) {
    let node = root;
    const parts = p.split("/");
    parts.forEach((part, i) => {
      const path = parts.slice(0, i + 1).join("/");
      if (!node.children.has(part)) node.children.set(part, { name: part, path, dir: i < parts.length - 1, children: new Map() });
      node = node.children.get(part)!;
    });
  }
  return root;
}

function Tree({ paths, picked, toggle }: { paths: string[]; picked: string[]; toggle: (p: string) => void }) {
  const root = useMemo(() => build(paths), [paths]);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState("");
  const rows: { node: Node; depth: number }[] = [];
  const walk = (n: Node, depth: number) => {
    const kids = [...n.children.values()].sort((a, b) => (a.dir === b.dir ? a.name.localeCompare(b.name) : a.dir ? -1 : 1));
    for (const k of kids) {
      if (filter && !k.path.toLowerCase().includes(filter.toLowerCase()) && !(k.dir && [...paths].some((p) => p.startsWith(k.path + "/") && p.toLowerCase().includes(filter.toLowerCase())))) continue;
      rows.push({ node: k, depth });
      if (k.dir && (open.has(k.path) || filter)) walk(k, depth + 1);
      if (rows.length > 600) return;
    }
  };
  walk(root, 0);
  const pattern = (n: Node) => (n.dir ? `${n.path}/**` : n.path);
  return (
    <div className="stack">
      <input type="text" placeholder="Find a folder or file" value={filter} onChange={(e) => setFilter(e.target.value)} />
      <div className="tree" role="tree">
        {rows.map(({ node, depth }) => {
          const p = pattern(node);
          const on = picked.includes(p);
          return (
            <div key={node.path} className={`node${on ? " picked" : ""}`} style={{ paddingLeft: 10 + depth * 16 }} role="treeitem" aria-selected={on}>
              {node.dir ? <button className="toggle" aria-label={open.has(node.path) ? "Close" : "Open"} onClick={() => setOpen((s) => { const n = new Set(s); n.has(node.path) ? n.delete(node.path) : n.add(node.path); return n; })}>{open.has(node.path) || filter ? "▾" : "▸"}</button> : <span style={{ width: 18 }} />}
              <span className="label">{node.name}{node.dir ? "/" : ""}</span>
              <button className={`btn small ${on ? "dark" : "quiet"}`} onClick={() => toggle(p)}>{on ? "Picked" : "Pick"}</button>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function Requires({ draft, edit, paths }: { draft: any; edit: (p: string, v: unknown) => void; paths: string[] }) {
  const list: any[] = draft.require ?? [];
  const set = (i: number, patch: any) => edit("require", list.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  return (
    <div className="stack">
      {list.length === 0 && <p className="muted small">No rules yet.</p>}
      {list.map((r, i) => (
        <div key={i} className="panel stack" style={{ background: "var(--page)" }}>
          <div className="row between"><strong>Rule {i + 1}</strong><button className="btn small danger" onClick={() => edit("require", list.filter((_, j) => j !== i))}>Remove</button></div>
          <div><p className="small muted">When a change touches</p><Chips items={r.when ?? []} onChange={(v) => set(i, { when: v })} placeholder="src/api/**" /></div>
          <div><p className="small muted">it must also change</p><Chips items={r.also ?? []} onChange={(v) => set(i, { also: v })} placeholder="docs/api/**" /></div>
          <div className="row"><span className="small muted">Otherwise</span><Strictness value={r.severity ?? "approval"} onChange={(v) => set(i, { severity: v })} /></div>
          <input type="text" placeholder="Why (told to the agent)" value={r.why ?? ""} onChange={(e) => set(i, { why: e.target.value || null })} />
        </div>
      ))}
      <button className="btn quiet" onClick={() => edit("require", [...list, { when: [], also: [], severity: "approval", why: null }])}>Add a rule</button>
      {paths.length > 0 && <p className="small muted">Tip: folders are written as <code>folder/**</code>.</p>}
    </div>
  );
}

function Checks({ draft, edit, detected }: { draft: any; edit: (p: string, v: unknown) => void; detected: any[] }) {
  const list: any[] = draft.check ?? [];
  const missing = detected.filter((d) => !list.some((c) => c.name === d.name));
  return (
    <div className="stack" style={{ marginBottom: 6 }}>
      {list.length === 0 && <p className="muted small">No checks. Nothing is proved by running anything.</p>}
      {list.map((c, i) => (
        <div key={c.name} className="setting inline" style={{ borderTop: i ? undefined : 0 }}>
          <div className="text">
            <div className="name">{c.name}</div>
            <div className="help"><code>{c.run.join(" ")}</code></div>
          </div>
          <div className="control row">
            <span className="small muted">Required</span>
            <Switch on={c.required} onChange={(v) => edit("check", list.map((x, j) => (j === i ? { ...x, required: v } : x)))} />
            <button className="btn small danger" onClick={() => edit("check", list.filter((_, j) => j !== i))}>Remove</button>
          </div>
        </div>
      ))}
      {missing.length > 0 && (
        <div className="note stack">
          <span>Found on your machine:</span>
          {missing.map((d) => (
            <div key={d.name} className="row between"><span><strong>{d.name}</strong> <code>{d.run.join(" ")}</code></span><button className="btn small" onClick={() => edit("check", [...list, d])}>Add</button></div>
          ))}
        </div>
      )}
    </div>
  );
}

const LEVELS = ["dev", "uat", "pre-prod", "prod"];
function Environments({ draft, edit }: { draft: any; edit: (p: string, v: unknown) => void }) {
  const list: any[] = draft.environment ?? [];
  const set = (i: number, patch: any) => edit("environment", list.map((e, j) => (j === i ? { ...e, ...patch } : e)));
  return (
    <div className="stack">
      {list.map((e, i) => (
        <div key={i} className="row">
          <input type="text" style={{ maxWidth: 160 }} value={e.name} placeholder="name" onChange={(x) => set(i, { name: x.target.value })} />
          <input type="text" style={{ maxWidth: 180, fontFamily: "var(--mono)", fontSize: 13 }} value={e.branch} placeholder="branch" onChange={(x) => set(i, { branch: x.target.value })} />
          <select style={{ maxWidth: 140 }} value={e.level ?? ""} onChange={(x) => set(i, { level: x.target.value || null })}>
            <option value="">no level</option>
            {LEVELS.map((l) => <option key={l} value={l}>{l}</option>)}
          </select>
          <button className="btn small danger" onClick={() => edit("environment", list.filter((_, j) => j !== i))}>Remove</button>
        </div>
      ))}
      <button className="btn quiet" onClick={() => edit("environment", [...list, { name: "", branch: "", level: null }])}>Add an environment</button>
    </div>
  );
}

function RiskRules({ draft, edit }: { draft: any; edit: (p: string, v: unknown) => void }) {
  const list: any[] = draft.risk.rules ?? [];
  const set = (i: number, patch: any) => edit("risk.rules", list.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  return (
    <div className="stack" style={{ marginBottom: 6 }}>
      {list.map((r, i) => (
        <div key={i} className="panel stack" style={{ background: "var(--page)" }}>
          <div className="row">
            <input type="text" style={{ maxWidth: 200 }} value={r.category} placeholder="category, e.g. billing" onChange={(e) => set(i, { category: e.target.value })} />
            <Choice value={r.level} options={[["low", "Low"], ["medium", "Medium"], ["high", "High"]]} onChange={(v) => set(i, { level: v })} />
            <button className="btn small danger" onClick={() => edit("risk.rules", list.filter((_, j) => j !== i))}>Remove</button>
          </div>
          <Chips items={r.paths ?? []} onChange={(v) => set(i, { paths: v })} placeholder="src/billing/**" />
        </div>
      ))}
      <button className="btn quiet" onClick={() => edit("risk.rules", [...list, { category: "", level: "high", paths: [] }])}>Add a risk category</button>
    </div>
  );
}
