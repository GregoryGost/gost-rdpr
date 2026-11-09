# Agent Bootstrap

Determine the repository mode before doing work.

## Mandatory Request Routing

`.codex/rules/request_routing.md` is mandatory in both target projects and the `agent-projects-tools` template repository.

Before any task-specific tool call, file edit, MCP operation, external-system call, or final answer:

1. Read and apply `.codex/rules/request_routing.md`.
2. Classify the current user message independently from previous turns.
3. Resolve the allowed and forbidden surfaces and side effects.
4. Continue only within the selected mode and surface gate.

The initial read of `.codex/rules/request_routing.md` is the only bootstrap file operation allowed before its gate is resolved. This rule does not depend on `CODEX_PROJECT.md` activation and must not be omitted, set to `none`, disabled, or replaced by another routing rule.

## Target Project Mode

Use this mode in a project that consumes rules, skills, and the project profile from this repository.

1. Apply the mandatory request-routing gate above.
2. Read `CODEX_PROJECT.md` when it exists. It is the source of truth for project-specific stack choices, paths, natural-language/style profile, dependency policy, migration policy, validation commands, and enabled external systems.
3. If `CODEX_PROJECT.md` is missing or incomplete, inspect repository evidence first: manifests, package manager files, lockfiles, framework configs, source tree, test configs, build configs, and documentation.
4. If the project type and active profiles can be determined with confidence, create or update `CODEX_PROJECT.md` from `.codex/project.template.md`. If material choices remain ambiguous, ask the user before creating or changing the profile.
5. Resolve activation for additional rules and skills from exact entries in `Active Rules`, exact entries in `Active Skills`, active stack profiles, and enabled specialized profile sections.
6. Before applying an active rule or skill, read its entrypoint.
7. When the entrypoint declares hard dependencies, require `.codex/rules/material_dependencies.md` to exist and apply it as a conditional bootstrap support rule, even when it is not listed in `Active Rules`.
8. If the validator file is missing or a required dependency is invalid, report the profile error and do not apply the dependent artifact.
9. Apply only materials that match the task, are active through an allowed signal, and have valid required dependencies.
10. Report conflicting activation signals instead of guessing. Optional activation entries cannot disable `request_routing.md`.

## Active Material Execution Invariants

- Resolve applicable rules and skills only from activation signals allowed by this bootstrap and `CODEX_PROJECT.md`.
- Read every applicable rule or skill entrypoint before relying on it. A remembered workflow, previous tool result, prior conversation, or generic capability is not a substitute for the current active entrypoint.
- Validate declared hard dependencies before applying the dependent artifact.
- An active rule or skill may narrow the selected request mode, allowed surfaces, side effects, or output format, but cannot broaden authorization from the current user message.
- Before a mutation, the candidate action must satisfy both request routing and every applicable active material. A prohibition from either boundary wins.

## Subagents For Code Changes

- When a target project enables delegated executable code/test work, `.codex/rules/subagent_coordination.md` becomes mandatory bootstrap support before the primary dispatches or a specialist acts. It does not require an optional Active Rules entry; missing it blocks delegation but never authorizes unrelated writes.
- Delegate only within authorized executable application/test-code work. Do not delegate documentation-only, comment-only, docstring-only, instruction-only or unrelated tasks. The primary chooses relevant roles rather than launching all agents; preserve active rule/skill activation and request_routing.md in every handoff. Delegation never expands user authorization, sandbox permissions or allowed side effects.
- Before dependent work, the primary explicitly selects a scope-specific Architecture Gate state: NOT_REQUIRED when architects are not appointed, or PENDING immediately when both architects are appointed (even mid-task). PENDING, REOPENED and architecture BLOCKED bar affected downstream design, test scenario authoring, code/test edits, testing and acceptance by the PRIMARY and all subagents. Bounded authorized read-only research, architecture proposals/critique and factual diagnosis remain permitted.
- When a target selects `database_architect`, the primary must screen data-impacting code/test work: material data design, migration, transactional integrity, privacy/tenant isolation, resilience or substantial performance risk requires a scoped database assessment. Keep `db_assessment_status` separate from Architecture Gate; a required PENDING, CHANGES_REQUIRED, BLOCKED or STALE assessment blocks affected DOWNSTREAM implementation planning, code/test edits, test execution and acceptance, including with Architecture Gate NOT_REQUIRED. Bounded read-only architecture proposals, specialist review and factual investigation remain permitted while existing Architecture Gate rules allow them. Before APPROVED require DBA CLEAR for the exact canonical candidate when mandatory. DBA is NOT a third general-architect endorsement; do not waive a required specialist solely because both architects agree.
- BOTH architects must endorse the identical canonical final design revision; only then may the primary issue an approved, scoped Architecture Handoff with an explicit decision_version. Pass its current scope/version/contracts to downstream agents. If approvals, scope or source of truth cannot be verified, stop dependent work; never silently deselect architects to bypass the gate.
- When architecture is appointed mid-task or reopened, the primary requests interruption of affected agents, waits for acknowledgment/completion when supported, verifies any in-flight commands and partial writes, and confirms the shared workspace is quiescent before proceeding. A stop message alone is not a verified pause. Keep affected writes blocked when the pause cannot be confirmed.
- Classify implementation violation of a correct architectural contract as an IMPLEMENTATION defect and return it to the implementer; reopen architecture only when evidence shows the approved DESIGN itself is invalid. For ambiguous causes, suspend affected writes for bounded read-only investigation. Architecture Gate is independent of testing_status: a test-environment BLOCKED verdict is not an architecture BLOCKED state.
- The test_engineer edits only assigned test paths; implementers edit only assigned code/test paths. Acceptance applies to an identified stable snapshot of code, tests, fixtures and relevant config, including uncommitted inputs; rerun affected checks after material changes. Independent code review is required when assigned or mandated. The primary owns final integration and acceptance.
- Manage thread capacity by waiting for results or closing finished threads. Every new assignment must use a fresh no-history subagent spawn (`fork_turns: "none"` on verified MultiAgentV2); never reuse a completed thread or `followup_task`. Transfer only bounded, verified predecessor reports through the primary under `subagent_coordination.md`. For overlapping Codex sessions, confirm exclusive writing ownership or isolation before mutations. After context compression/resumption, recover the explicit NOT_REQUIRED decision or, for APPROVED scopes, the authoritative handoff, together with current authorization; fail closed when required evidence is missing. Do not automatically create task notes, Obsidian contexts, Git worktrees or CI tests.

## Template Repository Mode

Use this mode when working in the `agent-projects-tools` source repository itself.

1. Apply the mandatory request-routing gate above.
2. Do not create `CODEX_PROJECT.md`; its absence is intentional in this template repository.
3. Read `README.md`, `.codex/project.template.md`, and the rules, skills, metadata, and references directly relevant to the requested repository change.
4. Apply `.codex/rules/material_dependencies.md` when adding, changing, or reviewing dependency declarations.
5. Treat `.codex/project.template.md`, `.codex/rules/`, `.codex/agents/`, and `.agents/skills/` as source artifacts being maintained, not as an active application stack.
6. Check affected cross-references, profile identifiers, rule names, skill names, hard dependencies, metadata, and README coverage before completing a change.

Keep `AGENTS.md` small. Detailed workflows belong in `.codex/rules/`, `.agents/skills/`, or skill `references/`.

## Hard Constraints

- `.codex/rules/request_routing.md` must exist and be applied for every new user message in both repository modes.
- Never omit, disable, replace, or set the mandatory request-routing rule to `none` in a target project's `CODEX_PROJECT.md`.
- `.codex/rules/subagent_coordination.md` is conditionally mandatory when a target project enables delegated code/test work; this rule cannot expand the current request's permissions.
- `.codex/rules/material_dependencies.md` is conditionally mandatory whenever an active artifact declares hard dependencies; it does not require a separate `Active Rules` entry.
- Do not apply a dependent artifact when the validator file or any required rule or skill is missing, inactive, disabled, ambiguous, or set to `none`.
- Do not silently activate missing dependencies or unrelated overlays.
- `.codex/project.template.md` is a template, not an active rule. Do not load it as a rule after a target project's `CODEX_PROJECT.md` is complete.
- Never create `CODEX_PROJECT.md` inside the `agent-projects-tools` template repository.
- In a target project, use repository metadata for profile discovery, but do not invent project-specific stack choices when material evidence is missing or ambiguous.
- Do not add new dependencies unless the user explicitly approves it or the target project's `CODEX_PROJECT.md` explicitly allows it.
- Do not silently resolve contradictory activation entries.
- In the template repository, activation restrictions do not prevent reviewing or editing an artifact directly in the requested maintenance scope.
- If Obsidian is enabled in a target project's `CODEX_PROJECT.md`, use only the configured Obsidian MCP server for vault content.
- If Obsidian MCP is unavailable, use only the fallback outbox paths declared in the target project's `CODEX_PROJECT.md`, then synchronize through MCP after successful verification.
- You need to remember what rules and what skills are available and use them when necessary.
- It is impossible to draw any conclusions based only on superficial data; it is necessary to conduct an analysis as deeply and in detail as possible.

## Review Expectations

- Review code and tests together when the task touches implementation.
- In target projects, apply relevant rules and specialist skills only after activation and required-dependency validation.
- In the template repository, review the requested artifacts together with directly dependent rules, skills, references, metadata, and README entries.
- Run or report the relevant validation commands declared by the target project's `CODEX_PROJECT.md` when possible.

## Project-Specific Evidence And Environment Requirements

- This is the `gost-rdpr` target project. Resolve its active materials through `CODEX_PROJECT.md` after request routing.
- Re-establish bootstrap from source after compaction, a long context gap, or uncertain repository state:
  reread routing, this file, the current profile, and applicable active entrypoints and dependencies.
- Verify material conclusions using complete relevant files or contiguous semantic sections,
  together with directly relevant callers, configuration, tests, and documentation.
  Search results are locators and coverage aids, not sufficient evidence.
- For non-trivial or high-impact work, test competing interpretations, failure modes, compatibility constraints,
  and contradictions with existing contracts before selecting a solution.
- Use PowerShell-compatible commands on the Windows host. Use `curl.exe` when actual curl behavior is needed.
  Shell-specific Linux commands require an explicitly verified container, WSL, or other non-Windows boundary.
- Preserve unrelated user changes and local secrets. Do not load `.env` or print authentication configuration
  merely to discover project metadata.
