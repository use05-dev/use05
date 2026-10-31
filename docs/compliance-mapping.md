# How 05 maps to AI governance guidance

05 holds AI coding agents to what they declared: a plan sealed before they start, checks run on the exact tree, a signed record of what they did, and a person's approval bound to exact content. This page maps that to four sets of guidance that compliance teams ask about. It is 05's own reading, not a certification, and it is honest about scope.

**Scope first.** 05 governs AI agents that change software. It does not govern AI systems that make decisions about people (eligibility, benefits, hiring), which is what the Directive on Automated Decision-Making and much of the NIST AI RMF are about. Where guidance is about those systems, this page says "not applicable" rather than stretching a fit.

**Strength.** On a developer's machine, 05's controls are advisory: an agent running as you can get around them, and 05 says so. The strong form is the CI gate: checks proved and signed by a runner key the agent never sees, and a required check on the merge. Ratings below assume the CI gate is on where it matters.

Ratings: **met**, **partly met**, **not met**, **not applicable** (n/a).

## TBS Guide on the Use of Agentic AI (May 2026)

The guide closest to what 05 does. Quotes are from the guide.

| The guide asks for | 05 | Rating |
|---|---|---|
| Actions "fully logged in a system that the agent does not have the ability to change" | The action log is a hash chain, sealed by signed receipts at each declaration, finish and stop, copied to the receipts branch, and countersigned by the CI runner key (`use05 gate --ci`) up to the last seal it trusts. The brief says how strongly it is sealed and flags `LOG_ALTERED`. The seals use a key on the developer's machine, so an agent running unsandboxed as the user could rewrite the log and its unpushed seals; only an agent in a sandbox that cannot write the log (as Codex's is) cannot change it at all | partly met |
| For tool calls, "the tool name, time, outcome and the type of parameters passed" | Each event records the tool, the time, the files it touched and the hook's decision. Parameter values and contents are deliberately never recorded | partly met |
| Logs of "approvals" | Approvals and rejections are signed receipts bound to the exact tree or intent and to the policy in force; break-glass bypasses are signed and shown in the brief | met |
| Clear agent IDs | Each declaration records the agent kind, its session and, when the agent's hook gives it, the model (D71). They come from the agent's own hook and session, not from a separate identity system | partly met |
| A named human accountable for each agent, with a delegate | The owner is the holder of an approver key, recorded with the declaration and confirmed by that key's signed approval. Delegates are not modelled | partly met |
| A review or confirmation step before actions that change state | Protected paths and risky areas need a person's signed approval of the plan or the outcome; the gate holds the change at push and in CI. Hooks deny edits to protected paths without an approved plan | met for changes to the repository; n/a for other systems |
| Bounded autonomy: limits on data, tools, permissions and scope | The declared scope reserves an area; edits outside it, to protected paths or into another agent's area are flagged or blocked by policy. Tool permissions themselves belong to the agent's own settings | partly met |
| A kill switch "outside the agent" | Not provided. The agent's own controls stop it | not met |
| Reversibility: versioning, undo | Every change is in git; the brief gives the undo command; landing is fast-forward only and 05 never force-updates a branch | met |
| Reassess controls when tools, data, permissions or scope change | A changed declaration voids its approval (`INTENT_CHANGED`); a change to 05's own rules needs a person (`PROTECTED_PATH`) | partly met |

## Directive on Automated Decision-Making

The Directive applies to systems that make or support administrative decisions about clients. AI coding agents are tools used to build software, not such systems, so most of it is n/a. Where an organisation builds an automated decision system with AI agents, 05 helps with the software side. Clause references follow the topics of the Directive; check numbering against the current text.

| Topic | 05 | Rating |
|---|---|---|
| Algorithmic Impact Assessment, notice, explanation, peer review, human final decision | About the decision system, not its code | n/a |
| Safeguarding the released versions of software components, with access to test them | Every proved tree has signed evidence; receipts travel with the repository and verify offline | partly met (for the code, not deployments) |
| Re-assessing when functionality or scope changes | The declared plan, its scope and risk are recorded per change; risky changes need approval | partly met (signals the change; the assessment is yours) |
| Documenting decisions, assessments and human overrides | Approvals, rejections and break-glass overrides of a change are signed and kept | partly met (for changes to the system, not its decisions) |
| Traceable data used and produced by the system | Not about data | n/a |
| Testing and monitoring for accuracy and bias | 05 runs the checks you define and catches weakened tests; it does not test models for bias | not met |

## ISO/IEC 42001 (AI management system)

05 is a tool that produces evidence for a management system; it is not one. Mapped to the standard's management-system clause topics; map to your own control set and check numbering against your copy of the standard.

| Topic | 05 | Rating |
|---|---|---|
| Roles, responsibilities and authorities | Owner and approver roles; machine keys cannot approve; policy names trusted keys and roles | partly met |
| Documented information, controlled and retained | Signed, offline-verifiable receipts and sealed logs on the receipts branch, under your own git hosting and retention | partly met |
| Operational planning and control of AI use | Declared plans, derived risk, deterministic gates, an organisation floor that repositories can only tighten | partly met |
| Event logging for AI systems | The sealed action log (see above) | partly met |
| Monitoring, measurement, internal audit | Evidence an auditor can verify without your machine; no audit programme, metrics dashboard or management review | partly met |
| AI system impact assessment, data quality, third-party suppliers | Not covered | not met |

## NIST AI Risk Management Framework (AI RMF 1.0)

Mapped to the four functions; subcategories are not numbered here.

| Function | 05 | Rating |
|---|---|---|
| GOVERN: policies, roles, accountability, oversight | Policy as code read from a change's base, an organisation floor, named owners and approvers, signed approvals and break-glass | partly met |
| MAP: context, intended use, risks | Each change's declared plan and scope, with risk derived from what it touches; not system-level context or impacts on people | partly met |
| MEASURE: testing, evaluation, monitoring | Checks proved on the exact tree and signed; weakened tests caught; claims checked against evidence. No model evaluation, fairness or robustness testing | partly met |
| MANAGE: prioritise, respond, document | Findings with stable codes and next steps; risky changes held for a person; undo for every change. No incident response | partly met |

## What 05 does not do

No register or inventory of AI systems, no assessment of AI systems against policy, no data, model or fairness monitoring, and no kill switch for agents. Those belong to governance platforms; 05's signed receipts are evidence such platforms and auditors can consume. The receipt formats are in [receipts.md](receipts.md).
