# Request routing rules

Before any tool call, file edit, MCP operation, or final answer, classify the
current user request by mode. Do this for every new user message, including
follow-up messages after a long implementation task.

## Required mode gate

Choose the narrowest applicable mode before acting:

- `implementation`: code, tests, configuration, project assets, serialized resources, or project files may be changed when the request asks to perform work.
- `local-environment-only`: change explicitly scoped machine-local development tools, SDKs, runtimes, Editors, modules, plugins, tool configuration, or local application state. This mode does not authorize repository/project mutations or external-system mutations unless those surfaces are separately authorized.
- `review-only`: inspect and report findings; do not create tasks, contexts, or
  code changes unless the user explicitly changes the mode.
- `analysis-only`: investigate and explain; do not change files or taskbook
  state.
- `taskbook-only`: read or update Obsidian task/context/log state only through
  the configured MCP or declared fallback outbox.
- `wiki-only`: query or update LLM Wiki/backlog content only through the
  configured MCP or declared fallback outbox.
- `external-system-only`: read or mutate explicitly scoped data in a configured
  external system through its approved connector, MCP server, or API. Do not
  change repository files, code, tests, configuration, taskbook, or wiki state
  unless the request separately authorizes those surfaces.
- `commit-text-only`: prepare commit message text only. Read-only inspection of
  the current Git state is allowed solely to determine the complete verified
  change set. Do not mutate Git state. When verification succeeds, do not add
  explanatory prose outside the requested format; when it is unavailable,
  report the verification gap instead of fabricating commit text. Be sure to
  take into account the rule for the git.md agent.
- `status-only`: report the current state; do not continue implementation unless
  the user asks to keep working.
- `question-only`: answer the question; do not make repository changes or
  external-system mutations.
- `documentation-only`: change only the requested documentation/rule/profile
  files.

Use `local-environment-only` for mutations such as installing/removing a local SDK or Editor, changing machine-local tool/plugin/module state, changing local tool defaults, switching persistent local contexts, or configuring a local development integration when the project itself is not being changed. Read-only local-tool inspection inherits the ordinary `question-only`, `status-only`, `analysis-only`, or `review-only` mode and does not require this mutation gate.

Use `external-system-only` for direct operations such as reading or changing a
Jira issue, updating a ticket, posting a comment, changing a remote workflow
state, or invoking another configured external service. Use `implementation`
when the task changes integration source code, tests, configuration, or project
files rather than the external system's live data.

## Mode precedence and composition

A direct call to a configured external system uses the external-system gate even
when the user-facing intent is a question, status check, analysis, or review.
For read-only calls, keep the operation read-only and preserve the requested
answer format; `question-only`, `status-only`, `analysis-only`, or `review-only`
do not authorize a mutation.

Read-only source retrieval, including web access or documentation MCPs, inherits
the selected request mode and does not require `external-system-only` by itself.
The surface gate must still permit network/MCP access. Changing the retrieval
service's account, credentials, indexed private sources, or other remote state is
an external-system operation.

If the request only discusses an external system without calling it, use the
ordinary `question-only`, `status-only`, `analysis-only`, or `review-only` mode
without the external-system gate.

Use the specialized Obsidian modes instead of the generic external-system mode:

- `taskbook-only` has priority for all taskbook reads and writes;
- `wiki-only` has priority for all LLM Wiki Query/Ingest reads and writes;
- `external-system-only` does not authorize taskbook or wiki side effects;
- other explicitly requested Obsidian MCP operations outside those overlays may
  use `external-system-only` together with `obsidian-mcp-core`.

Local tools may expose project, local-environment, and external/remote operations through the same executable. Classify the real target and side effect rather than the command name. A local IPC/HTTP/CLI boundary controlling a local application is not automatically an external-system operation. A command that also mutates cloud/account/remote state still requires the external-system gate.

Repository-hosting operations that complete the current repository workflow
inherit the repository mode. Branch creation, commits, pushes, and pull-request
creation or updates performed as part of an authorized `implementation` or
`documentation-only` change do not require a separate `external-system-only`
mode. A standalone operation on remote issue or pull-request metadata, such as
adding a comment, label, assignee, reviewer, or changing remote state without a
repository change, uses `external-system-only`. `commit-text-only` remains a
strict text-output mode and never authorizes Git mutations or remote hosting
operations. It may use read-only Git inspection solely to verify the commit
contents.

If the request combines repository work with a direct external-system operation,
identify each requested surface and side effect separately. A repository change
does not authorize an external-system mutation, and an external-system operation
does not authorize repository changes. Use a combined gate only for side
effects explicitly requested by the user. If the required target or side effect
remains ambiguous, ask before acting.

## Authorization and narrowing precedence

The current user message defines the maximum authorized side-effect scope for
that turn. Prior conversation may be used only to resolve an explicit referent
in the current message, such as `do that` or `yes` to a previously proposed
bounded action. It must not preserve the previous request mode, carry forward a
broader scope, or authorize unrelated side effects. Previous implementation
work, remembered workflows, or the apparent end goal must not broaden the
resolved scope.

Active rules and skills may refine or narrow the selected request mode, allowed
surfaces, side effects, or required output format. They must never grant
authorization that is absent from the current request.

When an applicable active rule or skill maps a request form to a specific mode,
strict output contract, or narrower side-effect boundary, that restriction is
controlling. Do not combine it with a broader inferred mode.

A request to prepare text, inspect, analyse, review, explain, report status, or
answer a question is read-only unless the current message explicitly authorizes
a mutation on the target surface.

For a combined request, decompose the requested operations and resolve the mode,
surface, and side-effect gate for each operation independently. Authorization
for one operation or surface does not imply authorization for another.

## Surface and side-effect gate

After selecting the mode, identify all allowed and forbidden surfaces before the
first action:

- code files
- tests
- project configuration
- project assets and serialized resources
- build/test/generated artifacts
- Markdown rules/docs
- local application/editor state
- local development toolchain/installations
- local package/module/plugin state
- Obsidian MCP
- shell commands
- Git commands
- web access
- external services

Do not run tools or produce the final answer until this gate is resolved.

For the selected mode, explicitly account for:

- whether file edits are allowed;
- whether task/context/wiki updates are allowed;
- whether shell/Git commands are allowed;
- whether external network calls are allowed;
- which repository rules and skills are active;
- which source-of-truth files must be read;
- the required final response format.

If a candidate command or edit would touch a forbidden surface, replace it with
a project-safe action or do not run it.

## Mutation checkpoint

Before each mutating operation, validate the candidate action against the
already resolved current-message authorization, selected mode, allowed surfaces,
applicable active rules and skills, and their validated hard dependencies.

This checkpoint verifies the candidate action against already loaded constraints;
it does not require rereading unchanged rule and skill entrypoints before every
low-level write.

Resolve the gate again when:

- a new user message changes or may change the mode;
- the target surface changes;
- a previously irrelevant rule or skill becomes applicable;
- activation or dependency state changes.

If the target, action, scope, or interaction between applicable instructions
remains ambiguous, do not perform the mutation. Permitted read-only inspection
may continue when it can resolve the ambiguity; otherwise ask the user for the
missing target, action, or scope.

Do not perform an additional mutation merely because it would be helpful,
convenient, or necessary for a broader inferred goal.

Before the final response, verify that every performed mutation remained within
the resolved gate and report only side effects that actually occurred.

## Local development-tool gate

Before a machine-local development-tool mutation, resolve:

- the exact executable/tool and installed version;
- the target installation, project, Editor/application, module, plugin, or configuration scope;
- whether the operation is read-only, temporary runtime state, or persistent machine state;
- whether it also changes repository/project files;
- whether it also changes credentials, cloud/account state, or another external system;
- whether the operation is destructive, administrative, broad, or difficult to reverse.

Read-only inspection does not authorize installation, removal, upgrade, default/context switching, authentication changes, plugin/module changes, or client/integration configuration.

Ordinary machine-local mutations require an explicit request or an active project workflow that clearly authorizes that mutation. Upgrades, removals, default-target/context changes, authentication changes, and broad environment changes must not be performed merely as an incidental prerequisite.

When one command spans local environment, project, and external-system surfaces, require authorization for each mutated surface separately and verify the resulting state when technically practical.

## External-system gate

Before any direct external-system call, resolve:

- the exact external system and configured instance/account/environment;
- whether the operation is read-only or mutating;
- the target resource identifiers and bounded scope;
- the exact requested action and expected state change;
- the approved connector, MCP server, or API boundary;
- the configured credential source without exposing secrets;
- whether the action is bulk, destructive, administrative, or difficult to
  reverse.

A read-only request does not authorize a mutation. Ordinary scoped writes require
an explicit user request naming the intended state change. Bulk, destructive,
administrative, or broadly scoped writes require an explicit scope and a
preview, dry-run, or target-state check when the external system supports one.
Do not perform a write when the instance, environment, target, action, or scope
is ambiguous.

After a mutation, verify the resulting remote state through the same approved
boundary when technically possible. Report partial success, rejected items, or
unverified outcomes explicitly.

## Project-rule precedence

Active repository rules and `CODEX_PROJECT.md` refine reusable memory and generic
workflows. When a remembered workflow conflicts with current project rules, the
current project rules win.

Do not treat a follow-up request as continuing the previous mode by default.
Reclassify the new user message independently before acting.

## Output gate

Before the final answer, verify:

- the response language matches `CODEX_PROJECT.md`;
- the output format matches the selected mode and the user request;
- the answer does not report side effects that were not performed;
- required citations or memory citations are present when applicable;
- disallowed explanation is not added for strict-output modes;
- unresolved verification gaps are stated plainly.
