//! `use05`: the acceptance layer for AI-written code.
//!
//! Humans own the intent and the outcome; agents own everything in between; 05 keeps the middle
//! in check. This binary parses arguments and renders results. The decisions are made in
//! `use05-core`.
#![forbid(unsafe_code)]

mod cmd;
mod ctx;
mod extend;
mod policy_edit;
mod prompt;
mod report;
mod ui;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use report::emit;

#[derive(Parser)]
#[command(
    name = "use05",
    version,
    about = "05: the acceptance layer for AI-written code",
    long_about = "05 keeps AI-written code in check. You state the intent; agents do the work; 05 proves what was checked, compares the result to the intent, and gives you one page to accept or reject.\n\nRun with no arguments for the status of this repository."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Set up this repository: policy, keys, hooks. Shows exactly what it changes.
    Init(InitCli),
    /// Begin a task: say what you are about to do, and where it may touch
    Start(StartCli),
    /// Run the policy's checks on the exact tree and sign what happened
    #[command(after_help = "Examples:\n  use05 prove                 run every required check\n  use05 prove test lint       run named checks\n  use05 prove -- cargo test   run any command\n\nChecks run on a copy of exactly the staged files (or --tree), with a scrubbed environment.\nA failing check still gets a receipt that records the failure.")]
    Prove(ProveCli),
    /// The one page a person reads: intent, outcome, evidence, drift, what to do
    Brief(BriefCli),
    /// Approve (or reject) an intent or an outcome, signed with your passphrase-protected key
    Approve(ApproveCli),
    /// Check a receipt offline: no account, no network
    #[command(after_help = "Examples:\n  use05 verify receipt.json --key me.pub\n  use05 verify 05-receipts/<key>:receipts/<tree>/<id>.json --tree HEAD\n\nWithout --key, receipts are checked against the keys your policy and this machine trust.")]
    Verify(VerifyCli),
    /// Show the effective policy and where each setting came from
    Policy(PolicyCli),
    /// Check this setup and say how strongly each control is enforced
    Doctor(DoctorCli),
    /// Break glass: let one exact tree through a block, for a stated reason. Logged.
    Bypass(BypassCli),

    #[command(hide = true)]
    Hook(HookCli),
    #[command(hide = true)]
    Gate(GateCli),
    /// Move a task's work into its target branch when the gate allows it, then clean up
    Land(LandCli),
    #[command(hide = true)]
    Finish(FinishCli),
    #[command(hide = true)]
    Key {
        #[command(subcommand)]
        action: KeyCmd,
    },
    #[command(hide = true)]
    Uninstall(UninstallCli),
    /// Any other name runs the extension `use05-<name>` from PATH (D73).
    #[command(external_subcommand)]
    External(Vec<String>),
}

#[derive(Args)]
struct Common {
    /// A directory inside the repository
    #[arg(long, default_value = ".", value_name = "DIR", global = false)]
    repo: PathBuf,
    /// Print machine-readable JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct InitCli {
    /// Also write a CI workflow ("github")
    #[arg(long, value_name = "HOST")]
    ci: Option<String>,
    /// Do not install agent hooks or the git pre-push hook
    #[arg(long)]
    no_hooks: bool,
    /// Do not touch AGENTS.md
    #[arg(long)]
    no_agents_md: bool,
    /// Do not ask anything; write the default policy
    #[arg(long)]
    defaults: bool,
    /// Ask the setup questions even without a terminal, reading the answers from stdin
    #[arg(long, conflicts_with = "defaults")]
    guided: bool,
    /// Who works here, setting how strict the rules start: solo, small or regulated
    #[arg(long, value_name = "TEAM", value_parser = ["solo", "small", "regulated"])]
    team: Option<String>,
    /// The branch finished changes land on
    #[arg(long, value_name = "BRANCH")]
    target: Option<String>,
    /// An environment and its branch, lowest first (repeatable): dev=main, prod=production, or NAME=BRANCH:LEVEL for another name: dev-eu=eu-main:dev
    #[arg(long = "env", value_name = "NAME=BRANCH")]
    envs: Vec<String>,
    #[command(flatten)]
    common: Common,
}

#[derive(Args)]
struct StartCli {
    /// What you are about to do, in a few words
    title: String,
    /// The goal, in a sentence
    #[arg(long)]
    goal: Option<String>,
    /// Paths the change may touch (repeatable): src/payments/**
    #[arg(long = "scope", value_name = "GLOB")]
    scope: Vec<String>,
    /// Paths it must not touch (repeatable)
    #[arg(long = "exclude", value_name = "GLOB")]
    exclude: Vec<String>,
    /// Checks that must pass for this change (repeatable): test
    #[arg(long = "check", value_name = "NAME")]
    check: Vec<String>,
    /// Promise not to change dependency files
    #[arg(long)]
    no_new_deps: bool,
    /// Read the intent card from a TOML file instead
    #[arg(long, value_name = "FILE")]
    card: Option<PathBuf>,
    #[arg(long, hide = true)]
    session: Option<String>,
    #[command(flatten)]
    common: Common,
}

#[derive(Args)]
struct ProveCli {
    /// Names of policy checks to run (default: every required one)
    names: Vec<String>,
    /// Sign with this secret key file (default: the CI runner key, else this machine's key)
    #[arg(long, value_name = "FILE")]
    key: Option<PathBuf>,
    /// The tree to prove: "index" (staged files), "worktree", or a commit or tree revision
    /// (default: the staged files if any are staged, otherwise the working tree)
    #[arg(long, default_value = "auto", value_name = "REV")]
    tree: String,
    /// Do not store the receipt on the receipts branch
    #[arg(long)]
    no_store: bool,
    /// Push the receipts branch to origin afterwards, so others and CI can see it
    #[arg(long)]
    push: bool,
    /// Also write the receipt to a file (one check only)
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
    /// Pass a variable through to the command: NAME, or NAME=VALUE (repeatable)
    #[arg(long = "env", value_name = "NAME[=VALUE]")]
    env: Vec<String>,
    /// Stop a check after this many seconds
    #[arg(long, value_name = "SECONDS")]
    timeout: Option<u64>,
    /// Run this command instead of a policy check, after --
    #[arg(last = true, value_name = "COMMAND")]
    command: Vec<String>,
    #[command(flatten)]
    common: Common,
}

#[derive(Args)]
struct BriefCli {
    /// Look at this tree: "index" (staged files), "worktree", or a commit (default: staged files if any, else the working tree)
    #[arg(long, value_name = "REV")]
    tree: Option<String>,
    /// A task id (default: the current task)
    #[arg(long)]
    task: Option<String>,
    /// Fetch everyone's receipts from origin first
    #[arg(long)]
    fetch: bool,
    #[command(flatten)]
    common: Common,
}

#[derive(Args)]
struct ApproveCli {
    /// Approve the declared intent, before work (default: the outcome)
    #[arg(long, conflicts_with = "outcome")]
    intent: bool,
    /// Approve the finished outcome (the default)
    #[arg(long)]
    outcome: bool,
    /// Reject instead of approving
    #[arg(long)]
    reject: bool,
    /// Why
    #[arg(long, value_name = "TEXT")]
    reason: Option<String>,
    /// A task id (default: the current task)
    #[arg(long)]
    task: Option<String>,
    /// The tree to approve: "index", "worktree", or a commit (default: what the brief shows)
    #[arg(long, value_name = "REV")]
    tree: Option<String>,
    /// Read the passphrase from the first line of stdin instead of the terminal
    #[arg(long)]
    passphrase_stdin: bool,
    /// Push the receipts branch to origin afterwards
    #[arg(long)]
    push: bool,
    #[command(flatten)]
    common: Common,
}

#[derive(Args)]
struct VerifyCli {
    /// A receipt file, or a git object name for a receipt
    receipt: String,
    /// The public key to verify against (default: trusted keys)
    #[arg(long, value_name = "FILE")]
    key: Option<PathBuf>,
    /// Also check the receipt is for this tree: "index", or a commit or tree revision
    #[arg(long, value_name = "REV")]
    tree: Option<String>,
    #[command(flatten)]
    common: Common,
}

#[derive(Args)]
struct PolicyCli {
    #[command(subcommand)]
    action: Option<PolicyCmd>,
    /// Change the policy by answering the setup questions again
    #[arg(long)]
    edit: bool,
    /// Ask the setup questions even without a terminal, reading the answers from stdin
    #[arg(long, requires = "edit")]
    guided: bool,
    /// Who works here, setting how strict the rules start: solo, small or regulated
    #[arg(long, requires = "edit", value_name = "TEAM", value_parser = ["solo", "small", "regulated"])]
    team: Option<String>,
    /// The branch finished changes land on
    #[arg(long, requires = "edit", value_name = "BRANCH")]
    target: Option<String>,
    /// An environment and its branch, lowest first (repeatable): dev=main, prod=production, or NAME=BRANCH:LEVEL for another name: dev-eu=eu-main:dev
    #[arg(long = "env", requires = "edit", value_name = "NAME=BRANCH")]
    envs: Vec<String>,
    #[command(flatten)]
    common: Common,
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Sign an organisation floor (what the cloud app will do for you)
    #[command(hide = true)]
    OrgSign {
        /// The floor, as a TOML file
        floor: PathBuf,
        #[arg(long)]
        org: String,
        /// The organisation's secret key file
        #[arg(long)]
        key: PathBuf,
        /// Where to write the signed layer
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Args)]
struct DoctorCli {
    #[command(flatten)]
    common: Common,
}

#[derive(Args)]
struct BypassCli {
    /// Why you are overriding the block
    #[arg(long, value_name = "TEXT")]
    reason: String,
    /// How long it lasts
    #[arg(long, default_value_t = 4, value_name = "HOURS")]
    hours: u32,
    /// The tree to let through: "index", "worktree", or a commit (default: what the brief shows)
    #[arg(long, value_name = "REV")]
    tree: Option<String>,
    /// Read the passphrase from the first line of stdin instead of the terminal
    #[arg(long)]
    passphrase_stdin: bool,
    /// Push the receipts branch to origin afterwards
    #[arg(long)]
    push: bool,
    #[command(flatten)]
    common: Common,
}

#[derive(Args)]
struct HookCli {
    /// `claude-code`, `codex`, or `generic` for any other agent
    agent: String,
    /// The hook event name
    event: String,
}

#[derive(Args)]
struct GateCli {
    /// Run as a git hook: `pre-push`
    #[arg(long, value_name = "HOOK")]
    git_hook: Option<String>,
    /// Run in CI: prove the required checks, then gate the HEAD tree
    #[arg(long)]
    ci: bool,
    #[arg(long, value_name = "REV")]
    tree: Option<String>,
    /// In CI: push the runner's receipts branch afterwards, so its seals outlive the job
    #[arg(long)]
    push: bool,
    /// Remaining arguments from git (remote name and url)
    #[arg(trailing_var_arg = true, hide = true)]
    rest: Vec<String>,
    #[command(flatten)]
    common: Common,
}

#[derive(Args)]
struct FinishCli {
    /// What was done, in the author's own words. An assertion, never a fact.
    #[arg(long)]
    outcome: Option<String>,
    #[arg(long)]
    task: Option<String>,
    #[command(flatten)]
    common: Common,
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Create a key pair at PATH (and PATH.pub), or --approver for your approval key
    New {
        /// Where to write the key (not with --approver)
        path: Option<PathBuf>,
        /// Make your approval key, opened only by a passphrase
        #[arg(long)]
        approver: bool,
        /// Read the passphrase from the first line of stdin instead of the terminal
        #[arg(long)]
        passphrase_stdin: bool,
        /// Print machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Show the public keys this machine uses
    Show {
        /// Print machine-readable JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args)]
struct LandCli {
    /// A task id (default: the current task)
    #[arg(long)]
    task: Option<String>,
    #[command(flatten)]
    common: Common,
}

#[derive(Args)]
struct UninstallCli {
    #[command(flatten)]
    common: Common,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // Usage mistakes exit 6 (invalid request) so exit 2 always means "denied".
            let code = if e.use_stderr() { 6 } else { 0 };
            let _ = e.print();
            return ExitCode::from(code);
        }
    };

    let Some(command) = cli.command else {
        return cmd::status::run_bare();
    };

    match command {
        Cmd::Init(a) => {
            let flags = match setup_flags(a.team.as_deref(), a.target, &a.envs) {
                Ok(f) => f,
                Err(e) => return emit(&report::Report::error("init", "USAGE", e, None, 6), a.common.json),
            };
            let interactive = a.guided || (!a.defaults && terminal());
            emit(&cmd::init::run(cmd::init::Args { ci: a.ci, no_hooks: a.no_hooks, no_agents_md: a.no_agents_md, repo: a.common.repo, interactive, flags }), a.common.json)
        }
        Cmd::Start(a) => emit(
            &cmd::start::run(cmd::start::Args {
                title: a.title,
                goal: a.goal,
                scope: a.scope,
                exclude: a.exclude,
                check: a.check,
                no_new_deps: a.no_new_deps,
                card: a.card,
                session: a.session,
                repo: a.common.repo,
            }),
            a.common.json,
        ),
        Cmd::Prove(a) => emit(
            &cmd::prove::run(cmd::prove::Args {
                names: a.names,
                command: a.command,
                key: a.key,
                tree: a.tree,
                repo: a.common.repo,
                out: a.out,
                timeout: a.timeout,
                env: a.env,
                no_store: a.no_store,
                push: a.push,
                policy_rev: None,
                task: None,
            }),
            a.common.json,
        ),
        Cmd::Brief(a) => cmd::brief::run(&a.common.repo, a.task.as_deref(), a.tree.as_deref(), a.fetch, a.common.json),
        Cmd::Approve(a) => emit(
            &cmd::approve::run_approve(cmd::approve::ApproveArgs { intent: a.intent, reject: a.reject, reason: a.reason, task: a.task, tree: a.tree, passphrase_stdin: a.passphrase_stdin, push: a.push, repo: a.common.repo }),
            a.common.json,
        ),
        Cmd::Verify(a) => emit(&cmd::verify::run(cmd::verify::Args { receipt: a.receipt, key: a.key, tree: a.tree, repo: a.common.repo }), a.common.json),
        Cmd::Policy(a) => match a.action {
            Some(PolicyCmd::OrgSign { floor, org, key, out }) => emit(&cmd::policy::org_sign(&floor, &org, &key, &out), a.common.json),
            None if a.edit => {
                let flags = match setup_flags(a.team.as_deref(), a.target, &a.envs) {
                    Ok(f) => f,
                    Err(e) => return emit(&report::Report::error("policy", "USAGE", e, None, 6), a.common.json),
                };
                emit(&cmd::policy::edit(&a.common.repo, a.guided || terminal(), &flags), a.common.json)
            }
            None => emit(&cmd::policy::run(&a.common.repo), a.common.json),
        },
        Cmd::Doctor(a) => cmd::doctor::run(&a.common.repo, a.common.json),
        Cmd::Bypass(a) => emit(
            &cmd::approve::run_bypass(cmd::approve::BypassArgs { reason: a.reason, hours: a.hours, tree: a.tree, passphrase_stdin: a.passphrase_stdin, push: a.push, repo: a.common.repo }),
            a.common.json,
        ),
        Cmd::Hook(a) => cmd::hook::run(&a.agent, &a.event),
        Cmd::Gate(a) => cmd::gate::run(cmd::gate::Args { git_hook: a.git_hook, ci: a.ci, tree: a.tree, push: a.push, repo: a.common.repo, json: a.common.json }),
        Cmd::Land(a) => emit(&cmd::land::run(&a.common.repo, a.task.as_deref()), a.common.json),
        Cmd::Finish(a) => emit(&cmd::start::finish(&a.common.repo, a.task.as_deref(), a.outcome.as_deref()), a.common.json),
        Cmd::Key { action } => match action {
            KeyCmd::New { path, approver, passphrase_stdin, json } => emit(&cmd::approve::key_new(path, approver, passphrase_stdin), json),
            KeyCmd::Show { json } => emit(&cmd::approve::key_show(), json),
        },
        Cmd::Uninstall(a) => emit(&cmd::init::uninstall(&a.common.repo), a.common.json),
        Cmd::External(argv) => extend::run_command(&argv),
    }
}

/// A person at a terminal to answer questions: stdin, and stderr where the questions go.
fn terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// The setup answers given as flags.
fn setup_flags(team: Option<&str>, target: Option<String>, envs: &[String]) -> Result<cmd::setup::Flags, String> {
    Ok(cmd::setup::Flags {
        team: team.and_then(use05_core::setup::Team::from_name),
        target,
        envs: envs.iter().map(|e| cmd::setup::Flags::parse_env(e)).collect::<Result<_, _>>()?,
    })
}
