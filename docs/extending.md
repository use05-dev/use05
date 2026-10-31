# Extending 05

05 is extended from the outside. Nothing is loaded into it: an extension is a program you put on your machine, and it talks to 05 through commands, JSON and receipts. That keeps the core small, keeps the gate deterministic, and means an extension can never change what 05 decides.

There are five extension points.

## 1. Commands: `use05-<name>`

A program named `use05-<name>` on your `PATH` is the command `use05 <name>`, the way git finds `git-<name>`.

```sh
$ cat ~/.local/bin/use05-hello
#!/bin/sh
echo "hello $*"
$ use05 hello world
hello world
```

- Arguments are passed through as they are, and so is the exit code.
- The program gets `USE05_BIN`, the path of the `use05` that ran it, so it can call back (`"$USE05_BIN" brief --json`), and `USE05_VERSION`.
- A built-in command always wins over an extension with the same name.
- `use05 doctor` lists the extensions it finds, under **Extend**.
- An unknown name exits 6 and says which program would provide it.

Use `--json` when you call back. The JSON envelope and the exit codes are the stable contract; human output can change.

## 2. Any agent: `use05 hook generic <event>`

Claude Code and Codex have their own hook formats. Any other agent can use `generic`. Call it at each of these points, with one JSON object on stdin:

| Event | When | Useful fields |
|---|---|---|
| `SessionStart` | the session begins | `session_id`, `cwd` |
| `UserPromptSubmit` | the person sends a request | `prompt` (kept on this machine only) |
| `PreToolUse` | before a tool runs | `tool_name`, `tool_input` |
| `PostToolUse` | after a tool ran | `tool_name`, `tool_input` |
| `Stop` | the agent finishes a turn | `last_assistant_message`, `stop_hook_active` |
| `SubagentStart` | the agent starts a subagent | `agent_id`, `agent_type`; the answer's `context` holds the rules to give the subagent |
| `SubagentStop` | a subagent finished | `agent_id`, `agent_type` |
| `SessionEnd` | the session is over | |

Every event needs `session_id` and `cwd`. A subagent's events keep the parent's `session_id` and add `agent_id` and `agent_type`, on its tool calls too, so its work belongs to the same task and every action is recorded with the subagent that took it. A model name in `model` is recorded when given. In `tool_input`, 05 reads the files a tool is about to write from `file_path`, `notebook_path` or `path`, from patches (`*** Update File: <path>` lines) in `input`, `patch` or `command`, and shell commands from `command`.

The answer is on stdout, and empty when there is nothing to say:

```json
{ "decision": "deny", "reason": "05: .05/policy.toml is protected. A person must approve the intent first: ...", "context": "..." }
```

- `decision` is `deny`, `ask` (a person should confirm) or, after `Stop`, `block` (keep working: a check failed). Absent means go ahead.
- `reason` explains a decision; show it to the agent.
- `context` is information for the agent, such as "05 sealed your declaration". Add it to the agent's context.
- If `stop_hook_active` is true on a `Stop`, 05 never blocks again, so an agent cannot loop.

The hook always exits 0. If 05 itself fails, it says so on stderr and allows the step (fail open), unless `.05/policy.toml` sets `on_error = "closed"` under `[enforce]`, in which case `PreToolUse` gets a `deny`.

**Declarations.** When the agent runs `use05 start` or `use05 finish`, set `USE05_SESSION_ID` in its environment to the same session id. 05 then leaves the declaration in `.05/inbox` and the agent's own hook seals it before the next edit, so the record names the agent (`agent:generic`), not whatever the agent claims. Remove `USE05_SESSION_ID` from the environment of any other agent your agent starts.

Like every agent hook, this is advisory: an agent running as you can reach around it. The CI gate is what enforces.

## 3. Events: `extensions.toml`

Programs listed in your `extensions.toml` hear what happened. The file is in 05's per-user directory (`$USE05_HOME`, else `$XDG_CONFIG_HOME/05`, else `~/.config/05`).

```toml
[[on]]
events = ["sealed", "finished", "gate", "landed"]
run = ["/usr/local/bin/notify-team"]   # an absolute path
timeout_secs = 5          # the default; then it is stopped
```

`run` must start with an absolute path: a relative one would be looked up inside whichever repository the event came from. Each listener gets one line of JSON on stdin, and runs in the repository's top directory with a plain environment (`PATH`, `HOME`, `LANG`, `TMPDIR`, `USE05_HOME`). It never sees the runner key, a push token or anything else 05 was given. The gates read `extensions.toml` before any of the change's code runs, so a change under test cannot choose what runs after it.

| Event | When | Fields besides `v`, `event`, `at`, `repo` |
|---|---|---|
| `sealed` | a declaration was sealed (`agent` is empty when a person ran `use05 start`) | `task`, `agent`, `intent_sha256` |
| `finished` | the author's statement of what was done was recorded | `task`, `agent`, `tree` |
| `gate` | the pre-push or CI gate decided | `where` (`pre-push` or `ci`), `tree`, `task`, `decision`, `findings` (codes) |
| `landed` | `use05 land` moved a change into its target | `task`, `branch`, `target`, `head` |

Listeners hear identifiers and verdicts, never code, diffs, prompts, titles or outcomes. For more, a listener asks 05 itself: `use05 brief --task <id> --json`.

Listeners cannot hold work up. 05 waits for each one at most `timeout_secs`, then stops it, and ignores what it says, how it exits and whether it starts at all. An `extensions.toml` that cannot be read runs nothing, and `use05 doctor` names the problem.

The file belongs to the machine, not to a repository. If a repository could choose programs to run on every hook, anyone who can commit to it could run code on your machine.

## 4. Records: your own receipt types

Extensions can keep their own signed records on the same `05-receipts/<key>` branches, so they travel with the repository too. Use the [receipt format](receipts.md) (an in-toto Statement v1 in a DSSE envelope) with a `predicateType` URI of your own, such as `https://example.com/coverage/v1`. A path inside the branch, such as `receipts/<subject>/<sha256>.json`, keeps one record per file.

05 never reads or judges records of another tool's type. It counts them, and the brief says "N receipt(s) of other tools' kinds were not read", so nobody mistakes them for evidence 05 checked. Only `https://use05.dev/` types are 05's.

## 5. Checks: any command

If a tool's result should count, make it a check in `.05/policy.toml`. `use05 prove` runs it on a copy of the exact tree and signs the outcome, and the gate reads that receipt like any other.

## What extensions cannot do

They cannot change a gate decision, approve, or loosen policy. Gates are deterministic and read only 05's own records, verified against the keys your policy trusts. The one way a tool's result counts is as a check.
