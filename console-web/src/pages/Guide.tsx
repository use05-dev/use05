import { Fragment, useEffect } from "react";
import { Link } from "../ui";

const TOPICS = [
  ["setup", "Set up a machine"],
  ["approve", "Approve from your phone"],
  ["policy", "Edit a policy"],
  ["base", "Your base policy"],
  ["email", "Email alerts"],
  ["security", "What is safe, and why"],
  ["trouble", "When something is stuck"],
  ["commands", "Commands"],
] as const;

export function Guide({ anchor }: { anchor?: string }) {
  useEffect(() => {
    if (anchor) document.getElementById(anchor)?.scrollIntoView({ block: "start" });
  }, [anchor]);
  const origin = window.location.origin;
  return (
    <div className="guide">
      <h1>Guide</h1>
      <p className="muted" style={{ marginTop: 8 }}>How the console works with 05 on your machines. This page is only here, in your console.</p>
      <nav className="toc" style={{ marginTop: 18 }} aria-label="Topics">
        {TOPICS.map(([id, label]) => <Link key={id} to={`/guide/${id}`} className="btn small quiet">{label}</Link>)}
      </nav>

      <h2 id="setup">Set up a machine</h2>
      <p>The console never reaches into your machines. A small helper on each Mac, <code>use05-cloud</code>, connects out to it, reports what 05 sees and picks up what you sign. Do this once per machine.</p>
      <ol>
        <li>
          <p>Install 05 0.0.7 or newer; the helper, <code>use05-cloud</code>, comes with it. From a source checkout of 05:</p>
          <pre><span className="comment"># use05 with passkey approvals</span>{"\ncargo install --path crates/cli\n"}<span className="comment"># the helper, use05-cloud</span>{"\ncargo install --path crates/cloud"}</pre>
          <p className="small muted">Phone approvals count only where use05 is 0.0.7 or newer. Check with <code>use05 --version</code>.</p>
        </li>
        <li>
          <p>Pair it. The terminal shows a word: type it on <Link to="/">Home</Link> or Machines. Then the terminal and this page each show a code; pair only if they are the same.</p>
          <pre>{`use05 cloud login ${origin}`}</pre>
        </li>
        <li>
          <p>In each repository you want to see:</p>
          <pre>{`cd ~/code/my-repo && use05 cloud add`}</pre>
        </li>
        <li>
          <p>Pin your passkeys as approvers on this machine. You are shown each one and confirm it at the terminal; an agent cannot, because it has no terminal.</p>
          <pre>use05 cloud enrol</pre>
        </li>
        <li>
          <p>Keep it running in the background, and let it hear 05's events:</p>
          <pre>use05 cloud install</pre>
          <p className="small muted">This adds one listener to <code>~/.config/05/extensions.toml</code> and a launchd job, <code>dev.use05.cloud</code>. Its log is <code>~/.config/05/cloud.log</code>.</p>
        </li>
      </ol>

      <h2 id="approve">Approve from your phone</h2>
      <p>When an agent's work needs a person (a protected file, a risky change, a plan your policy wants approved), 05 on your Mac says so, the helper asks 05 to prepare the exact approval, and it appears on Home. You get an email if email is on.</p>
      <ol>
        <li>Open it. You see the plan, the files touched (names only), what 05 found, and the checks.</li>
        <li>Tap <strong>Approve with passkey</strong>. Face ID or your fingerprint signs exactly what your Mac prepared: this tree, under the policy in force now.</li>
        <li>The helper files it on your Mac within seconds. The seal closes when it is filed.</li>
        <li>Tell the agent to carry on, in the app you prompt it from. Nothing wakes it by itself.</li>
      </ol>
      <p>If the work changes after you approve, the approval stops counting and 05 asks again. To reject a change, tell the agent, or reject it at a terminal.</p>

      <h2 id="testing">Sign off your testing</h2>
      <p>If the repository's policy asks for testing before a push, a push to the chosen branches waits until the person driving the work has tried the change in their own environment and signed off. On the task's page, under <strong>Tested before a push</strong>, write what you tried, then sign with your passkey: your Mac prepares the exact statement, your passkey signs it, and your Mac files it. Where the policy allows, you can skip it instead, saying why. The note shows on the task and in the brief. Change the code afterwards, and sign off again.</p>

      <h2 id="policy">Edit a policy</h2>
      <p>Open a repository and choose <strong>Edit policy</strong>. Every setting is a switch, a choice or a list; folders and files come from your repository's tree (names only). The bar at the bottom shows what changed, and <strong>Show the file</strong> shows exactly what will be written, comments kept.</p>
      <p>Save one rule at a time with <strong>Save this rule</strong> beside it, or every change at once from the bar. Each save is its own edit. Saving is approving. Your Mac builds the edit as a commit on top of origin's landing branch and checks it; then you sign it with your passkey; then it pushes the commit. Your other machines get it with their next pull, and agents that start from old code are told to update.</p>
      <p>Some settings are only ever changed at a terminal: check commands and the variables they see, trusted keys, what counts as evidence, how many approvals are needed, locks that cannot be bypassed, and whether 05 fails open. These decide what runs on your machine and what counts as proof, so a browser never touches them. A check your Mac found by itself can be added; a typed command never can.</p>

      <h2 id="base">Your base policy</h2>
      <p>The base policy is a template: the settings you like to start a repository with. Edit it under <Link to="/base">Base policy</Link>. On a repository's policy page, <strong>Use base policy</strong> copies its settings into the editor, where you review and save as usual. The repository's own checks and keys are kept. Changing the template later does not touch repositories you already set up.</p>
      <p>A repository without 05 is set up at a terminal first, with <code>use05 init</code>.</p>

      <h2 id="email">Email alerts</h2>
      <p>Email comes only when something needs you: an approval of your work waiting, your policy edit stuck, or your machine refusing a request. Each person gets only their own, at the address they set and confirmed under <Link to="/settings">Settings</Link>; something about nobody in particular goes to the admins. Several at once become one email. An email names the repository and what is waiting, never the plan or the files, and its link only opens the page: approving always asks for your passkey.</p>
      <p>Whoever hosts the console turns email on, with Cloudflare Email Service or any SMTP server:</p>
      <ol>
        <li><strong>Cloudflare:</strong> under Email Service, add your domain as a sending domain and let Cloudflare add its DNS records; create an API token that may send email; set <code>CLOUDFLARE_ACCOUNT_ID</code> and <code>CLOUDFLARE_API_TOKEN</code>.</li>
        <li><strong>Or SMTP:</strong> set <code>SMTP_URL</code>, for example <code>smtps://user:password@mail.example.com:465</code>.</li>
        <li>Set <code>ALERT_FROM</code> to the address emails come from, on that domain.</li>
        <li>Each person sets their own address under <Link to="/settings">Settings</Link>, confirms it from the link, and can send a test email. If the provider refuses one, the reason shows there.</li>
      </ol>

      <h2 id="ci">Cloud sessions and CI</h2>
      <p>Work an agent does in the cloud, or that reaches your landing branch through CI, can show here too. Under <Link to="/machines">Machines</Link>, <strong>Cloud sessions and CI</strong>, make a token for one repository. In a Claude Code cloud environment, store it as <code>USE05_SESSION</code>: with <code>use05 init --shared-hooks</code> committed, each cloud session installs 05 and reports here as you. In CI, store it as <code>USE05_CI</code> and run <code>use05-cloud ci collect</code> before the gate and <code>use05-cloud ci report gate.json</code> after it: the repository's page shows CI's verdict, and work only CI sees can be approved here with your passkey and is filed on CI's next run. A token runs nothing it is sent, what it reports is labelled as coming from it and never replaces what a machine paired at a terminal reported, and it stops working when your console's key changes: make a new one then.</p>

      <h2 id="security">What is safe, and why</h2>
      <p>The console's server cannot read your work. Each machine seals what it reports (plans, file and folder names, checks and verdicts, the policy) to your console's key and signs it with its own; this page checks the signature, opens it, and builds what you see. The policy editor runs here too. The console keeps sealed bytes and what it needs to route them: which machine, which repository by an opaque id, what kind, when, and who must approve what. Emails say only that something needs you. Code, diffs, prompts and the agent's messages never leave your machines.</p>
      <p>That key is unlocked in your browser by your passkey, or by your recovery code. If you invite people and later remove someone, the console gets a new key; each of you confirms it for your own machines, and a machine takes it only from a passkey you pinned there.</p>
      <p>The honest limit: this page's code comes from the console. Suppose someone took over the host completely. They could serve a page that reads what you unlock here, or that shows you one thing and asks your passkey to sign another: an approval a machine really asked for, a policy edit you would not have made, or a new console key for your machines. Approvals and edits show in git and in 05's brief, and can be undone.</p>
      <p>They could not run anything on your machines: the helper runs no command it is sent. It does only five things when asked (send the folder tree, prepare a policy edit, apply one you signed, file an approval you signed, take a new console key you confirmed with your passkey), and a policy edit it prepares can only make the rules stricter: it can never add a command, a check or a key. They could not read your code; it never leaves your machines. They could not reach a machine; machines only connect out. They could not approve anything a machine did not ask for: a machine files a signed approval only of a statement it prepared itself, for that repository and purpose, and only once, and it co-signs that statement when it prepares it. A passkey's signature counts, on a machine or in CI, only beside that co-signature and only for the person driving the work, so a signature taken some other way (passed off as a sign-in, say) counts for nothing. An approval lasts at most as long as your policy's <code>expire_days</code>, whatever its dates say. And each machine trusts only passkeys you pinned there at the terminal; <code>use05 cloud enrol</code> offers only passkeys made for this console's address, and asks you about each one.</p>
      <p>Each repository is spoken for by the first machine that reports it. Another machine reporting it waits on the Machines page until you allow it, so a pairing token taken from one machine cannot rewrite what another machine asks you to sign. Adding a passkey needs a fresh check with one you already have, and emails you. Sign-in and pairing are rate limited.</p>
      <p>Before your passkey is asked, this page checks that what you sign is the statement shown, and shows what it approves and until when, read from the statement itself.</p>
      <p>If a machine refuses a request, it says so on Home, emails you, and keeps its own record in <code>~/.config/05/cloud-refusals.log</code>. If you did not ask for what it refused, revoke the machine's pairing, sign out everywhere by removing and re-adding your passkeys, and rotate <code>SETUP_SECRET</code>.</p>
      <p>Local enforcement is advisory, as everywhere in 05: an agent running unsandboxed as you could write its own key into <code>passkeys.pub</code>. CI counts a passkey only when it is listed under <code>[[trust.key]]</code> in the policy, which is a terminal change.</p>

      <h2 id="trouble">When something is stuck</h2>
      <ul>
        <li><strong>A machine shows offline.</strong> Is it awake? <code>use05 cloud status</code> says whether it reaches the console; the log is <code>~/.config/05/cloud.log</code>.</li>
        <li><strong>An approval is filed but will not count.</strong> The work or the policy changed after it was prepared. Ask the agent to finish again; a fresh request appears.</li>
        <li><strong>The machine could not file an approval.</strong> Usually the passkey is not pinned there yet: run <code>use05 cloud enrol</code> on that machine.</li>
        <li><strong>A policy edit is stuck because origin moved.</strong> Someone pushed meanwhile. Save the edit again; it is prepared on the new tip.</li>
        <li><strong>A policy edit is stuck because the push was refused.</strong> The landing branch is protected on your Git host (for example, pull requests required). Change the policy at a terminal and open a pull request, or allow direct pushes for this branch.</li>
        <li><strong>Work an agent left behind keeps asking for you.</strong> Open the task and choose <strong>Discard this work</strong>. Your machine says what would go (the worktree, the branch here and on origin) and what would be lost that exists nowhere else; your passkey confirms, and the machine removes it all. It cannot be undone. At a terminal: <code>use05 discard &lt;task&gt;</code>.</li>
        <li><strong>Lost your phone.</strong> Sign in with another passkey and remove the lost one under Machines. If it was your only passkey, you cannot sign in again, so keep a second one: another device, or a security key, added under Machines.</li>
      </ul>

      <h2 id="commands">Commands</h2>
      <dl className="commands">
        {[
          ["use05 cloud login <url>", "claim a new console, and pair this machine; inside a repository it also reports it, pins your passkeys and keeps running"],
          ["use05 cloud add [path]", "report a repository"],
          ["use05 cloud enrol", "pin your passkeys as approvers here"],
          ["use05 cloud install", "run in the background, hear 05's events"],
          ["use05 cloud status", "what is set up, and whether the console answers"],
          ["use05 cloud sync", "send everything once, now"],
          ["use05 discard <task>", "throw away work an agent left behind, after seeing what would be lost"],
        ].map(([command, what]) => <Fragment key={command}><dt><code>{command}</code></dt><dd>{what}</dd></Fragment>)}
      </dl>
    </div>
  );
}
