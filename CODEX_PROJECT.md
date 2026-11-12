# Codex Project Profile

## Execution Contract

This repository consumes `agent-projects-tools` v1.19.2 in target project mode.
`AGENTS.md` defines bootstrap order; `.codex/rules/request_routing.md` is mandatory for every request.
This profile declares capabilities and constraints; it grants no permission for side effects.
Only exact active entries below and enabled specialized sections activate materials.
Omitted optional materials are inactive. Read applicable entrypoints and validate their transitive hard dependencies
with `.codex/rules/material_dependencies.md` before applying them.
The code comment quality, FastAPI, cashews, and Python service E2E rule/skill pairs are intentional mutual dependencies;
each member is explicitly active.
Select applicable engineering policies for the intended project stack even before their implementation or scenarios
exist. Missing scenarios or tooling affect execution readiness and acceptance evidence, not policy activation.
Do not disable a selected profile solely because its implementation, fixtures, or tests have not been written yet.
The full source catalog and template are not active profiles.

## Project Identity

- Project key: `gost-rdpr`
- Workspace: repository root; derive its path at runtime.
- Project type: Python backend for domain/IP resolution and MikroTik RouterOS updates.
- Primary programming language: Python.
- Deployment: Docker on Linux; local agent commands run in Windows PowerShell.
- UI: separate `gost-rdpr-ui` repository cloned by `Dockerfile`; no frontend profile is active here.

## Natural Language Profile

- User-facing answers language: Russian.
- Git commit text language: Russian.
- Documentation language policy: English for repository technical documentation and reusable agent materials.
  Preserve upstream text and exact quoted contracts in their original language.
- Task tracking language policy: Russian for task titles, descriptions, checklists, acceptance criteria and status
  notes, including `TASKS.md` and `TASKS_ARCHIVE.md`. This overrides the general documentation language policy
  for task tracking.
- Test/comment natural language policy: English for comments, docstrings, test explanations, documentation blocks,
  and other code-adjacent prose. Apply `comment-language-audit` when those surfaces are in scope.
- API descriptions and developer-facing runtime messages: English, preserving established public contract values.
- Keep identifiers, library names, protocols, commands, paths, packages, and proper names in their original language.
- Apply language changes to the requested scope; this profile does not request a repository-wide translation.

## Code Documentation Profile

- Code comment quality enabled: yes.
- Active code documentation rule/skill: `code_comment_quality.md` + `code-comment-quality`.
- Required coverage: every authored declaration in affected owned functions/types, including private methods,
  fields, constants, local/loop/exception bindings, test functions and fixtures.
- Documentation language: use the Test/comment natural language policy above.
- Documentation placement: Python docstrings for functions/methods; adjacent comments or explicitly named group
  comments for fields, constants and variables; parameters may be documented inside the owning docstring.
- Change boundary: apply to authorized affected definitions, including their existing declarations.
  Repository-wide comment rewrites and new runtime behavior require separate authorization.
- Validation: inventory declaration coverage and verify technical accuracy and human-readable wording
  during implementation and review; `comment-language-audit` independently checks prose language.

## Agent Roles And Model Selection

- Subagents enabled: yes
- Delegation scope: authorized executable application/test-code changes only (not documentation-only, comment-only,
  docstring-only or instruction-only tasks).
- Primary agent model/effort: gpt-6.1-sol / xhigh (select in the client or target .codex/config.toml; this entry alone
  does not configure the running session).
- Selected role files: all ten exact paths in the role table below.
- Model availability: confirm with the active Codex client/account; report unavailable models and effort levels instead
  of substituting silently.
- Fresh thread policy: EVERY delegated assignment uses a new no-history `spawn_agent` (`fork_turns: "none"` for verified
  MultiAgentV2); never `followup_task`.
- Subagent handoff persistence: local-ephemeral.
- Local handoff persistence is enabled in `.agent-handoffs/<task_scope_id>/`; `.agent-handoffs/` remains ignored by Git.

| Role | Custom agent file | Model | Effort |
| --- | --- | --- | --- |
| Architecture: stability | .codex/agents/architect_stability.toml | gpt-6.1-sol | xhigh |
| Architecture: evolution | .codex/agents/architect_evolution.toml | gpt-6.1-sol | xhigh |
| Database architecture: specialist | .codex/agents/database_architect.toml | gpt-6.1-sol | xhigh |
| Codebase research | .codex/agents/code_explorer.toml | gpt-6-luna | high |
| Documentation/API research | .codex/agents/docs_researcher.toml | gpt-6-luna | high |
| Complex implementation | .codex/agents/complex_implementer.toml | gpt-6.1-sol | high |
| Small fixes / boilerplate | .codex/agents/simple_implementer.toml | gpt-6-luna | high |
| Independent test engineering | .codex/agents/test_engineer.toml | gpt-6.1-sol | high |
| Independent code review | .codex/agents/code_reviewer.toml | gpt-6.1-sol | high |
| Difficult bugs / design disputes | .codex/agents/deep_debugger.toml | gpt-6-astra | xhigh |

### Delegation And Ownership

- `.codex/rules/subagent_coordination.md` is mandatory when subagents are enabled for authorized code/test changes, even
  if not listed in Active Rules. Load it before delegation; a missing copy blocks delegation. Send a bounded task packet
  with current verified predecessor reports, not the parent chat. Only the primary may publish verified completed
  handoff files.
- Before delegating a scoped code-change workflow, the primary decides whether architecture is needed, records the
  Architecture Gate state and dependencies, determines required test/review roles based on risk and the active project
  policy, and verifies allowed side effects. Spawn only relevant agents. The gate applies to the PRIMARY as well as all
  downstream agents.
- Every assignment contains original user requirements, authorized scope, verified baseline, applicable project
  rules/skills, selected model/effort, file ownership, safe commands and expected result. When architects are selected,
  downstream assignments additionally require the current approved Architecture Handoff. No role file or subagent
  delegation can widen request_routing.md permissions.
- The PRIMARY distinguishes requested behavior, necessary safeguards for verified requirements/contracts/invariants, and
  optional enhancements. Trace material requested behavior to the user's request; require a credible failure and
  examination of the smallest sufficient alternative only for additional behavior claimed necessary. Do not turn risk
  analysis or a subagent recommendation into an authorized feature. This check applies with Architecture Gate
  NOT_REQUIRED as well as APPROVED.
- Read-only codebase/docs research and neutral diagnosis may support architects while the gate is closed. No downstream
  implementation plan, test scenario matrix, prototype, code/test change or acceptance can be initiated before APPROVED
  for the affected scope.
- Implementation and test file ownership must be disjoint where agents work concurrently. Read-only role instructions
  are not independent technical sandboxes; stop conflicting writers and verify workspace state.

### Database Architecture Specialist Review (When Role Is Selected)

- Selection is explicit in `Selected role files`; the mere presence of `.codex/agents/database_architect.toml` does not
  activate it. When selected, the PRIMARY assesses every data-impacting code/test assignment BEFORE downstream data
  design or changes and records the scoped `db_assessment_status`. For tasks with no data-impact, record `NOT_REQUIRED`
  without delegating. A small, proven low-risk read-query/ORM change may also be `NOT_REQUIRED` with a factual reason.
- DBA review is REQUIRED for material persisted data contracts or schema evolution, existing-data
  migration/backfill/deletion, integrity/isolation/transaction changes, multi-tenant/privacy/retention boundaries,
  substantial production-scale query/index/partition impact, replication/sharding/backup/recovery, or cross-service
  data/event consistency. These are risk/impact triggers, not keyword matches: describe actual affected data, consumers
  and material hazards. Do not call the DBA for every ordinary SQLAlchemy operation.
- On material DATABASE ARCHITECTURE redesign, the PRIMARY appoints BOTH existing system architects and sets Architecture
  Gate PENDING; if either required role/model is not selected or unavailable, report BLOCKED for the affected scope
  instead of silently substituting another role. DBA is an independent subject-matter reviewer, not a third universal
  architect. The primary may choose Architecture Gate NOT_REQUIRED for a proven bounded non-architectural database fix,
  but a required specialist review must still be satisfied before affected code/test writes or acceptance.
- `db_assessment_status`: `NOT_REQUIRED` (scoped, reason recorded), `PENDING` (required assessment not completed),
  `CLEAR` (no unresolved supported blockers for the exact reviewed candidate/scope), `CHANGES_REQUIRED` (actionable
  evidence-backed issues), `BLOCKED` (missing critical evidence/required role), `STALE` (candidate, requirements or
  material data baseline changed). Only the PRIMARY tracks status. This is a specialist prerequisite, NOT an independent
  Architecture Gate or a third endorsement.
- For material architectural changes, DBA provides initial verified facts, invariants, risks and unknowns to BOTH
  architects equally BEFORE their independent first proposals; do not present a preferred DBA design as mandatory or
  relay the other architect's draft. After peer critique, the PRIMARY supplies the COMPLETE immutable canonical
  candidate with `candidate_revision` to a NEW DBA thread for final review. When mandatory, only CLEAR tied to that
  exact candidate and relevant data baseline permits both-architect final endorsement/primary APPROVED. DBA cannot
  independently grant APPROVED or override user authorization.
- CHANGES_REQUIRED requires a corrected candidate or an evidence-grounded refutation, verified through a new scoped
  specialist review; BLOCKED and STALE do not count as CLEAR. Pending or stale required assessment blocks ONLY affected
  downstream implementation planning, code/test edits, test execution and acceptance, even if Architecture Gate is
  otherwise NOT_REQUIRED/APPROVED. Authorized read-only fact gathering and system architecture options remain permitted
  subject to the existing Architecture Gate. Preserve unrelated authorized independent work. An implementation that
  precisely follows an already reviewed data contract does not by itself stale the design-level CLEAR; newly discovered
  conditions or deviations must be reassessed and actual code/migration behavior still needs separate validation.
  Missing configured mandatory role/model is reported as a blocker, never silently waived.
- DBA does not write schema/code/tests, issue live SQL or execute migration/benchmark/restore. The implementers own
  explicitly assigned changes, the independent test engineer derives its own scenarios from original requirements and
  verified contracts, and the PRIMARY integrates the current DBA assessment into Architecture Handoff and final
  validation where applicable.

### Completed Subagent Reports And Local Handoffs

- The primary receives each role's existing REQUIRED REPORT, verifies scope, evidence, architecture version and
  code/test snapshot, and passes only current relevant predecessor reports to downstream fresh agents.
- Use `local-ephemeral` persistence for authorized delegated code/test workflows. The primary alone publishes verified,
  versioned completed-stage reports and a task-local `index.md` in `.agent-handoffs/<task_scope_id>/`, following
  `.codex/rules/subagent_coordination.md`. Subagents return reports to the primary and do not write shared handoff files.
- When the current request/routing gate does not permit local writes, or the handoff root is unsafe or unavailable,
  keep reports in-session and state the persistence limitation. This setting does not authorize unrelated task notes,
  Obsidian entries, worktrees, Git commits or external-system writes.
- Keep `.agent-handoffs/` ignored by Git. Do not commit, push, export, sync or automatically delete its contents.
- Reports and indexes are secondary evidence, not an authority: old/stale reports cannot satisfy Architecture Gate,
  independent tester acceptance or review. Follow `.codex/rules/subagent_coordination.md` for publication, provenance,
  safety and compaction recovery.

### Architecture Gate — Primary-Agent Orchestration

Architecture Gate is an instruction-level ordering policy, not a built-in Codex lock or a grant of permissions. The
primary agent owns authoritative scope-specific state and its transitions.

| Architecture state | Meaning | Permitted work |
| --- | --- | --- |
| NOT_REQUIRED | The primary explicitly did not appoint architects for this scoped task. | Normal authorized implementation, testing and review, subject to reassessment on a scope change. |
| PENDING | Both architects were appointed, even mid-task; there is no approved design. | Authorized read-only evidence gathering and architect design/critique only; affected downstream work stops. |
| APPROVED | Both architects endorsed the SAME canonical final proposal revision; the primary approved the current Architecture Handoff. | Authorized downstream work bound to its decision_version. |
| REOPENED | Verified facts/changed requirements show the approved DESIGN needs reassessment. | Pause affected downstream work; two architects reassess with read-only evidence support. |
| BLOCKED | Required architectural consensus, evidence, requirements, model or tool are unavailable. | Report the architectural blocker; do not proceed with affected downstream work. |

**Opening, pausing and approving**

1. PENDING applies immediately on architect appointment. The primary coordinates interruption of affected running agent
   turns/commands, waits for actual completion/acknowledgment where supported, then inspects in-flight work and partial
   changes. A request to stop does not prove a quiescent workspace. If pause cannot be verified, keep affected writes
   and acceptance blocked and report the uncertainty. Preserve unrelated changes.
1. Architects independently study the SAME verified request before viewing each other's designs. After exchanging
   critiques, the primary circulates one identical, canonical final design revision (exact content and revision
   identifier) to both. Require explicit endorsement of that specific revision by EACH architect. Different drafts,
   silence or the deep_debugger's opinion cannot substitute for both approvals.
1. Before that approval, when a mandatory DBA assessment applies, verify CLEAR refers to the identical canonical final
   candidate and still-matching data baseline; an initial assessment or DBA CLEAR for another revision is insufficient.
   Before marking APPROVED, the primary also checks the canonical candidate for material new behavior without
   requirement/contract provenance or a justified necessary safeguard. If any addition is ungrounded, withhold approval:
   obtain an explicit user scope decision, or remove the addition and obtain BOTH architects' endorsements of the NEW
   canonical revision (and a matching DBA CLEAR where mandatory).
   Only then may the primary independently verify scope, evidence, user request and active policies, mark APPROVED, and
   issue an Architecture Handoff with task_scope_id; unique decision_version for the scoped task; relevant requirement
   and repository baseline; immutable final design and both endorsements; primary approval; contracts, ownership
   boundaries and invariants; known risks/alternatives; mandatory validation/review obligations; and affected paths,
   fixtures, state and resource dependencies. A revised handoff identifies which decision_version it supersedes.
1. The primary maintains exactly one authoritative CURRENT architecture state per scoped task and, only when APPROVED, a
   current approved handoff in the active task/session context or an already authorized persistent context, with
   recoverable references. This requirement does NOT itself authorize new repo files, Obsidian records or remote
   updates. After context compression/resumption, independently recover current gate state and scope; for APPROVED also
   recover the applicable canonical decision, both endorsements, primary approval and decision_version. For NOT_REQUIRED
   verify only the explicit no-architect decision and ongoing authorization, not a nonexistent handoff. If they cannot
   be verified, stop and reacquire evidence/approval, never manufacture it.
1. Scope-level parallel work is allowed only after verifying that files, tests, fixtures, internal/public contracts and
   external state/resource ownership do not overlap. Splitting or renaming tasks does not bypass a closed gate. On any
   uncertain shared boundary, pause all affected writers but allow unrelated verified-independent work under original
   authorization.

**Defects, status separation and reopening**

- Distinguish a *correct design implemented incorrectly* (IMPLEMENTATION defect, fix via implementer, architecture stays
  APPROVED) from a *design that cannot meet verified requirements/invariants even if implemented correctly*
  (ARCHITECTURAL defect, reopen affected scopes and return to BOTH architects). A test failure or contract violation
  alone does not establish an invalid design. If cause is ambiguous, pause affected writes for bounded read-only
  investigation; do not reopen architecture reflexively.
- An incorrect test remains the test engineer's responsibility; an unavailable/unsafe test environment is
  testing_status=BLOCKED. Neither requires architectural reopening. Architecture state and testing_status, review_status
  and implementation_status are independent; architecture APPROVED can coexist with testing BLOCKED or NOT_ACCEPTED.
- Reopening invalidates only affected prior architecture-dependent acceptance/review. Safely pause in-flight downstream
  work as in PENDING. Following a new identical design revision endorsed by both architects and approved by the primary,
  issue a NEW decision_version and rerun affected tests/review. If reconciliation fails, set architecture BLOCKED with
  the reason; never downgrade PENDING/REOPENED/BLOCKED to NOT_REQUIRED merely to evade an uncompleted approval.
- If user requirements change scope, independently reapply request_routing.md and update the dependency map; do not
  carry prior authorization or architecture approval into newly affected scopes without verification. An approved
  architecture never expands side-effect permissions.

### Two-Architect Workflow

1. Assign architect_stability and architect_evolution the same scope/evidence and obtain two read-only independent
   proposals before peer exchange.
1. Relay substantive critiques both ways; ask each architect to test counterarguments. Limit to three productive
   critique/revision rounds before a factual escalation to deep_debugger or reporting a blocker.
1. Circulate an immutable final candidate design revision to BOTH architects. Obtain two explicit endorsements
   referencing that precise candidate, not another draft or a loose summary.
1. The primary checks the final candidate and approvals, issues its versioned Architecture Handoff and explicitly marks
   APPROVED. Otherwise the architecture gate remains closed.

### Implementer–Tester Acceptance Loop

This loop begins after a verified NOT_REQUIRED or APPROVED decision for the scope. The test engineer does not design
scenarios before appointed architects complete their approval.

1. The primary supplies both agents the original requirements and, if applicable, current Architecture Handoff, owned
   paths, allowed test environment and acceptance criteria. The tester independently derives positive/negative and
   risk-specific hypotheses from user requirements; the approved architecture adds contract/concurrency/error coverage
   without overruling requirements.
1. The implementer modifies only owned paths and returns an identified revision; the tester designs tests in separately
   owned files. Their independent work may overlap after architecture approval, but final acceptance requires an
   unchanged code/test validation snapshot.
1. Classify failures before returning them: a code bug under a valid design goes to implementer; wrong assertion/fixture
   goes to test engineer with evidence; unsafe/unavailable environment sets testing_status=BLOCKED; a verified defect in
   the design itself reopens the affected architecture. If the cause is unknown, pause affected writes for read-only
   triage, not automatic architectural redesign.
1. After each implementation correction, the test engineer reruns the failed scenario and affected regressions on a new
   identified snapshot. Incorrect owned tests may be corrected only with evidence of the intended requirement. Repeat
   only while progress or new evidence exists; otherwise report a blocker rather than weakening expectations or looping
   indefinitely.
1. Independent tester ACCEPTED applies only to a stable snapshot and current decision_version (or NOT_REQUIRED) with all
   required risk-relevant positive/negative and regression checks actually performed. Any unperformed mandatory check is
   NOT_ACCEPTED or testing BLOCKED with an explicit reason. Do not imply global task acceptance from a passing
   individual test.
1. When assigned or project-required, code_reviewer reviews the current snapshot independently. The primary owns final
   validation and cannot accept while required test, review or project checks are failing, blocked or stale.

### Validation Gate — Stable Snapshot And Final Acceptance

- Before final checks the primary identifies the exact validation snapshot: architecture scope/version or NOT_REQUIRED;
  code and test revision; all relevant modified/untracked source, test, fixture and configuration files; and safe
  environment and test input conditions. A Git commit SHA is sufficient only for committed material; uncommitted inputs
  need their own verified identity. Do NOT require a commit or create one automatically.
- Test authoring finishes before final acceptance verification. While final checks run, prohibit edits to relevant
  source, tests, fixtures and config or use a separately authorized isolated worktree. Verify these inputs stayed
  stable. Generated runtime output can appear only in authorized locations and does not define source identity. An
  unstable or unverified snapshot means validation INCONCLUSIVE/BLOCKED, never ACCEPTED.
- Where required, the PRIMARY also verifies the current scoped DBA assessment and its constraints against the validation
  snapshot; the assessment is not a substitute for test/review, and changes invalidating DB contracts require
  reassessment. Evidence from test_engineer and code_reviewer is tied to the checked snapshot and architecture
  decision_version, with exact commands/results and coverage gaps. After a material change, invalidate and repeat
  affected checks/review on a new snapshot. Avoid unnecessary full reruns only when impact is verified.
- The primary explicitly determines independent testing/review requirements BEFORE work based on risk and the active
  project's validation policy. Complex, high-impact or security-sensitive code defaults to independent tester and
  reviewer; a genuinely bounded low-risk fix may omit an additional agent with a documented reason, without skipping
  required project tests. Unavailable required roles/models or environments are reported as blockers, never silently
  waived.
- Testing status (NOT_STARTED/IN_PROGRESS/ACCEPTED/NOT_ACCEPTED/BLOCKED) is distinct from architecture state
  (NOT_REQUIRED/PENDING/APPROVED/REOPENED/BLOCKED) and independent review status. Overall task completion requires a
  valid architecture gate, current evidence of any required tester/reviewer approval, and successful mandatory project
  checks.
- For Python code, test, or quality-tool configuration changes, mandatory project checks include Ruff lint,
  Ruff format check, Pyright, the applicable unit/integration/E2E tests, and coverage with the configured threshold.
  A failed, blocked, unperformed, or stale required check prevents final ACCEPTED; passing tests alone is insufficient.
- Require service E2E evidence when changes affect a public API flow, application startup/shutdown, or a critical
  background-job/persistence flow that narrower tests cannot establish. An empty required E2E selection is a missing
  check, never a pass or permission to deactivate the profile. Document task-specific applicability before execution.
- The final acceptance report and any applicable validation handoff identify the checked snapshot, exact commands,
  scopes, exit codes, Ruff lint/format results, Pyright error/warning counts, test counts, coverage and threshold,
  independent review status, and any unavailable or failing checks. Documentation-only changes use material and
  reference consistency checks unless they also change executable code or tool configuration.

### Agent Thread And Workspace Lifecycle

- Respect the active client's limit for open subagent threads. Wait for results or close completed threads where
  supported; start EVERY new assignment in a newly spawned, no-history thread. Never reuse prior threads or use
  `followup_task` for corrections, critique rounds or reviews. Closing threads never proves task acceptance; preserve
  their evidence first. Unavailable model/effort or thread capacity is a reported blocker, not permission for silent
  role substitution.
- Codex subagents share their parent's environment and permissions. Across separate Codex sessions, verify
  file/test/fixture/branch and background-command ownership; prefer separately authorized worktrees or explicit
  single-writer coordination. Never create a worktree automatically. If safe independence cannot be established, prevent
  overlapping writes.
- After compaction/resumption revalidate the current authorized task, explicit gate state, applicable handoff only for
  APPROVED, scope, active threads, stable snapshot (if any) and permissions. A stale subagent response is not
  authoritative; when verification fails, continue only authorized read-only inspection until reconciled.

## Active Stack Profiles

- `python-core`
- `python-testing`
- `python-service-e2e-testing`
- `python-fastapi`
- `python-cashews-cache`

Database and security skills are selected explicitly below; do not invent additional stack profile identifiers.

## Active Rules

- Required routing rule: `.codex/rules/request_routing.md`
- `source_code_hygiene.md`
- `code_comment_quality.md`
- `mark.md`
- `context7_documentation.md`
- `git.md`
- `python_fastapi.md`
- `python_cashews_cache.md`
- `python_service_e2e_testing.md`

Conditional bootstrap support files:

- `.codex/rules/material_dependencies.md` for hard-dependency validation.
- `.codex/rules/subagent_coordination.md` before authorized code/test delegation.

## Active Skills

- `comment-language-audit`
- `code-comment-quality`
- `python-core`
- `python-testing`
- `python-fastapi-expert`
- `python-service-e2e-testing`
- `python-backend-security`
- `python-cashews-cache`
- `python-sqlalchemy-core`
- `python-sqlalchemy-sqlite`
- `python-httpx-client`

Each skill resides under `.agents/skills/<name>/SKILL.md` with its complete package.
Apply only skills relevant to the current authorized task.
MySQL, NATS, Redis, frontend, Obsidian, and Jira overlays are outside the selected backend stack.

## Build And Validation Commands

- Command source of truth: this profile, `pyproject.toml`, `poetry.lock`, `README.md`, and `Dockerfile`.
- Tool executable policy: use `.\.venv\Scripts\python.exe` in PowerShell.
  Use the equivalent `.venv/bin/python` only inside a verified non-Windows boundary.
- Install dependencies: `poetry install` from the existing lockfile, only within authorized environment changes.
- Format: `.\.venv\Scripts\python.exe -m ruff format <explicitly assigned Python paths>` during authorized edits.
- Format check: `.\.venv\Scripts\python.exe -m ruff format --check .`.
- Python lint: `.\.venv\Scripts\python.exe -m ruff check .`.
- Type check / static analysis: `.\.venv\Scripts\python.exe -m pyright --project pyproject.toml`.
- Full acceptance tests: `.\.venv\Scripts\python.exe -m pytest -n 0 -m "not e2e_load"`.
  The explicit marker expression overrides the configured `-m unit`; unit, integration, ordinary E2E and unmarked
  tests are included. Use the isolated E2E environment declared below when the selected tests cross service boundaries.
- Unit tests: `.\.venv\Scripts\python.exe -m pytest -n 0 -m unit tests/unit`.
- Integration tests: `.\.venv\Scripts\python.exe -m pytest -n 0 -m integration tests/integration`.
- Service E2E: `.\.venv\Scripts\python.exe -m pytest -n 0 -m "e2e and not e2e_load"`.
- Load E2E: `.\.venv\Scripts\python.exe -m pytest -n 0 -m e2e_load` for an explicitly scoped load/performance task.
- Coverage: `.\.venv\Scripts\python.exe -m pytest -n 0 -m "not e2e_load" --cov
  --cov-config=pyproject.toml --cov-report=term-missing --cov-report=html` as one command.
  Read source packages, branch tracking, and fail-under from `[tool.coverage.*]`; do not override its source list.
- Coverage report: `.\.venv\Scripts\python.exe -m coverage report --show-missing` with the configured fail-under.
- Coverage HTML: `.\.venv\Scripts\python.exe -m coverage html`; inspect `.pytest_cache/coverage/htmlcov/`.
  Coverage data and subprocess fragments use `.pytest_cache/coverage/.coverage*` from the declared configuration.
- Parallel tests: `.\.venv\Scripts\python.exe -m pytest -m "not e2e and not e2e_load" -n auto --dist loadfile`
  only for a scope whose worker/resource isolation has been verified, after focused serial tests pass.
  Rerun parallel failures with `-n 0`; parallel execution does not replace the required serial acceptance baseline.
- Service E2E policy: enabled through `python_service_e2e_testing.md` + `python-service-e2e-testing`.
- Browser validation: outside this backend repository's selected test boundary; the UI has a separate repository.
- Metadata validation: parse `pyproject.toml` and project agent TOML with standard-library `tomllib`.
- Python syntax validation when Python changes: use `ast.parse` with the project interpreter for the affected files
  without importing the app. This checks syntax only and does not substitute for behavior tests.
- Agent-material validation: check active paths, skill metadata, transitive dependencies, intentional cycles,
  local references, and role names/models/effort.
- Whitespace validation: `git diff --check` for changed tracked files; inspect newly added files as well.
- Start application: `.\.venv\Scripts\python.exe .\main.py` only when runtime execution is authorized and isolated.
  Startup initializes SQLite, runs migrations, and starts the writer; importing modules also creates global resources.
- Build: `docker buildx build --platform linux/amd64 --load -t gost-rdpr:local .` only when authorized.
  The build fetches the external UI and dependencies. Publish/push requires separately authorized scope.
- For executable changes, run the relevant behavior tests and coverage commands above.
  Do not treat a syntax pass as functional acceptance.

## Python Profile

- Python enabled: yes.
- Python version: `>=3.15` from `pyproject.toml`; README development instructions use Python 3.15.2,
  and Docker targets `python:3.15-slim-trixie`.
- Compatibility policy: preserve the manifest's Python 3.15 minimum. Do not introduce language/API behavior requiring
  a later Python version without explicitly resolving a minimum-version change first.
- Dependency manager: Poetry; `package-mode = false`.
- Virtual environment policy: repository `.venv`.
- Source layout: flat packages at the repository root.
- Style: preserve the existing two-space indentation and local quoting conventions in touched Python code.
  Ruff owns formatting and linting; Pyright owns static type checking, using `pyproject.toml`.
  Keep formatter edits within the assigned paths and avoid unrelated repository-wide rewrites.
- Active Python base skill: `python-core`.
- Dependency versions source: constraints in `pyproject.toml`; resolved versions in `poetry.lock`.
  Recheck installed versions before version-sensitive work.

## Python Testing Profile

- Python testing enabled: yes.
- Test runner: pytest.
- Pytest configuration source: `[tool.pytest.ini_options]` in `pyproject.toml`.
- Test layout: `tests/unit/` and `tests/integration/`, separate from production code.
- Test discovery: `test_*.py` files, `*Tests` classes, and `test_*` functions under `tests/`.
- Service E2E scenarios use the registered `e2e` marker within the existing `tests/` structure; a new folder is not
  required to activate the policy. Structural changes still follow the Critical rules below.
- Default marker selection: `-m unit` from `addopts`; this is a focused development run, not full acceptance.
  Acceptance commands explicitly include integration and ordinary E2E tests; do not inherit the unit-only filter.
- Pytest import mode: `importlib`.
- Async test plugin: `pytest-asyncio`.
- Asyncio mode: `auto`.
- Test and fixture loop scopes: function; do not share event-loop-bound clients between unrelated tests.
- Coverage tool: `coverage.py` through the declared `pytest-cov` plugin.
- Coverage configuration source: `[tool.coverage.run]`, `[tool.coverage.report]`, and `[tool.coverage.html]`
  in `pyproject.toml`, including the configured `migrations` source package.
- Generated coverage data, subprocess fragments and HTML stay under `.pytest_cache/coverage/`, not as root files.
- Coverage branch tracking: yes.
- Coverage fail-under: 85; target 90–95% for critical domain behavior.
- Parallel test execution enabled: yes, explicitly selected isolated scopes only; serial execution remains the baseline.
- Parallel test plugin: `pytest-xdist`.
- Parallel test command: use the command declared under Build And Validation Commands after focused serial tests pass.
- xdist distribution mode: `loadfile`; serial rerun: `-n 0`.
- Worker resource isolation policy: worker-local temporary SQLite files, directories, ports and cache state;
  never share a writable production database or external resource. Recheck isolation after fixture or test changes.
- Isolation: temporary SQLite files, isolated process/cache/queue state, mocked external boundaries,
  no real RouterOS changes, list downloads, DNS calls, or RIPEstat requests in ordinary tests.
- Use the tracked `tests/` layout; the ignored `test/` directory is not the test-suite destination.
- Active Python testing skill: `python-testing`.
- Documentation/instruction-only changes use material consistency checks.
- Functional changes require meaningful behavior, boundary, failure, and regression tests.
- Tests and coverage commands are engineering policy; activation does not authorize dependency or environment changes.

## Python Service E2E Testing Profile

- Python service E2E enabled: yes.
- Active Python service E2E rule/skill: `python_service_e2e_testing.md` + `python-service-e2e-testing`.
- E2E boundary: backend HTTP API and critical job/queue-to-SQLite flows, exercised through public application behavior.
- E2E command: use the dedicated serial command under Build And Validation Commands.
- App/process start policy: prefer a subprocess running the project interpreter and `main.py` to exercise real
  composition, router registration, lifespan, migrations and writer lifecycle. An in-process app boundary is allowed
  only when it preserves that real composition and lifespan; do not reuse unit wiring that replaces application logic.
- Dependency setup: disposable SQLite files and process-local cashews state; use existing declared dependencies.
- External dependency stub policy: deterministic local protocol fakes for DNS/DoH, RIPEstat and RouterOS outside the
  tested application boundary. Do not mock internal services, repositories, business branches or the composition root.
- Environment policy: isolated temporary paths and settings; prevent loading local secret files and contacting real
  routers, shared databases or uncontrolled providers. Bound startup, requests, jobs and shutdown with timeouts.
- Data isolation policy: unique temporary database/files, cache state, test IDs and ports; run required migrations and
  minimal seeds against disposable data only. Fixtures own cleanup of processes, tasks, clients and persistent state.
- Parallel E2E policy: serial by default; xdist requires independently verified per-worker resource isolation.
- Load E2E policy: active for relevant performance/resilience work, with explicit workload bounds and measurements;
  the registered `e2e_load` marker remains a separately selected run rather than an automatic load test on every task.
- Coverage policy: retain configured unit/integration coverage and treat service E2E as additional behavioral evidence.
  For subprocess scenarios, verify child-process measurement and combined data before claiming application coverage.
- Acceptance policy: activation is independent of scenario readiness. If required scenarios or their isolated
  environment are unavailable, report the specific unperformed check and block affected acceptance without disabling
  this profile. Pytest exit code 5 (no tests selected) never satisfies a required E2E check.
- New dependencies, container infrastructure and project structure changes require the existing authorization gates.

## Markdown Profile

- Markdown rule: `mark.md`, active for non-Obsidian Markdown maintenance.
- Markdown configuration source: repository `.markdownlint.json`; keep its configured style and file scope.
- Validation policy: use a project-declared Markdown check command when available; otherwise review the changed
  Markdown against that configuration and report the actual validation performed. Do not install a linter implicitly.
- New documentation remains subject to request routing and the Markdown rule. An active profile never grants
  permission to create unrelated documentation or directories.

## Formatting And Linting Profile

- Ruff enabled: yes, for linting and formatting.
- Ruff configuration source: `[tool.ruff]`, `[tool.ruff.lint]`, and `[tool.ruff.format]` in `pyproject.toml`.
- Ruff target: `py315`; line length: 120; indentation: two spaces; quote style: single quotes.
- Preserve configured rule selection, ignores, per-file ignores, and formatter exclusions for `.agents/**` and `.codex/**`.
- Pyright enabled: yes.
- Pyright configuration source: `[tool.pyright]` in `pyproject.toml`.
- Pyright mode: `standard`; Python version: `3.15`; environment: repository `.venv`.
- Pyright scope: the configured production `include` paths. `tests/` is not currently included; do not describe
  the production type-check result as type-check coverage of the test suite.
- Acceptance uses non-mutating lint, format-check, and type-check commands. Do not run format or `--fix` during
  verification, weaken diagnostics, change exclusions, or ignore nonzero exit codes to obtain acceptance.
- Changes to tool policy or scope require current authorization; existing project settings remain authoritative.

## Python FastAPI Profile

- FastAPI enabled: yes.
- App entry point: `main.py` calls `server/server.py::AppServer.run`.
- App creation: `AppServer.__init__`; routers and middleware are attached inside `run`.
  Tests must account for this wiring; constructing `AppServer().app` alone does not attach the routes.
- Router layout: `routers/*_router.py`, class-owned `APIRouter` objects.
- Dependency injection policy: existing class-owned collaborators and module globals;
  inspect actual callers before changing ownership. No new DI container is selected.
- Schema/model policy: Pydantic HTTP models in `models/http/`; DTOs in `models/dto/`; ORM mappings in `models/db/`.
- Lifespan owner: `AppServer.__lifespan` resets job state, sets up the database, starts saving coordination,
  and closes coordinator/writer resources before HTTP clients on shutdown.
- Background task policy: domain-resolution requests register directly with the lifespan-owned saving coordinator;
  list and RouterOS commands retain `BackgroundTasks` and process-local `JobRegistry` reservations.
  Neither mechanism provides durable job execution. Do not introduce a worker framework implicitly.
- DNS configuration: each nonempty new/stale resolution job reads one immutable task-local snapshot before queue work.
  Changes committed after that read apply to the next job; single-domain operations read fresh committed settings.
  Keep explicit DNS selection and default row `0` semantics. Failed configuration reads must not start queue work.
  Each endpoint receives an A query first; validated reachable aliases from that response are reused. A failure without
  usable alias evidence permits a separate best-effort CNAME query. It never changes the A result's storage authority.
  Ordinary DNS resolvers and their fixed timeout/lifetime settings belong to one job or single-domain operation;
  each endpoint's resolver is reused within that scope. DNS response caching remains disabled pending evidence of
  useful TTLs and repeated queries.
- Saving resolution: one lifespan-owned coordinator shares a fixed pool limited by
  `domains_resolve_worker_limit` (default `32`) across automatic NEW/STALE and explicit stored-ID operations.
  Accepted NEW demand pauses subsequent STALE dispatch; started STALE work finishes. Repeated NEW triggers coalesce
  into one pending successor, captured after the current NEW list finishes processing/admission without commit drain.
  Each accepted explicit request gets a fresh priority operation, serialized per ID through
  known writer outcome. Automatic passes use full finite lightweight snapshots, not the legacy 500/2000 total caps.
  `domains_resolve_semaphore_limit` (default `64`) independently bounds classic DNS/DoH A/CNAME operations across all
  entrypoints. Checks without saving bypass saving coordination. Both limits and `queue_max_size` must be positive.
  Explicit unstarted admission and writer queues apply backpressure. Heavy results/tasks are created lazily.
  Token ownership and generation/actual-attempt evidence survive SELECT/adoption and cancellation cleanup;
  mandatory DB receipts and sticky writer-failure wakeups are separate from optional metrics. Unknown outcomes retain
  ownership without TTL/replay. Worker completion does not wait commit. Shutdown cleans coordinator preadmission work
  before writer drain and retains outcome bookkeeping through native cleanup before closing HTTP clients.
- Public API docs: runtime `/docs` and `/docs/openapi.json`; checked-in export `docs/OPENAPI.json`.
  Contract changes must reconcile models, route metadata, tests, and the export when applicable.
- Active FastAPI rule/skill: `python_fastapi.md` + `python-fastapi-expert`.

## Python Cashews Cache Profile

- Python cashews cache enabled: yes.
- Cache library: cashews.
- Cache backend: process-local `mem://` with size from `settings.ripe_stat_cache_size`.
- Cache lifecycle owner: module-owned `cache/cache.py::ripe_stat_cache`; setup occurs at import time.
  An explicit application shutdown hook for this cache is not currently wired.
- Cache consumer: `client/ripe_stat_client.py::RipeStatClient`.
- Cache key scope policy: normalized IP in `prefix:<address>`; per-key lock `lock:prefix:<address>`.
  Wrapper backend registration prefix: `ripe_stat_cache`.
- Cache values: prefix string; empty string represents a successful response with no prefix;
  `None` represents a miss. Errors are not converted to successful empty results.
- Cache TTL: `ripe_stat_prefix_cache_ttl_sec` and `ripe_stat_empty_prefix_cache_ttl_sec`;
  lock lifetime: `ripe_stat_cache_lock_ttl_sec`. Source of defaults: `config/config.py`.
- Cache invalidation policy: TTL-based freshness for externally owned RIPEstat results.
  No local persisted-data cache or post-commit invalidation is currently configured.
  Any future mutable-data cache must define its own post-commit invalidation contract.
- Deployment assumption: one application process; memory cache and locks are process-local.
- Active Python cashews cache rule/skill: `python_cashews_cache.md` + `python-cashews-cache`.
- If FastAPI is active, use FastAPI rule/skill for app wiring and API behavior: yes.

## Database Profile

- Database enabled: yes.
- Database toolkit/ORM: SQLAlchemy 2.x.
- Active database / server family: SQLite.
- Database server version: runtime interpreter's SQLite library; inspect `sqlite3.sqlite_version` safely.
  Do not infer a deployed SQLite version from the lockfile.
- Database driver: `aiosqlite`.
- Database pool library: SQLAlchemy; `AsyncAdaptedQueuePool` for reads and `NullPool` for writes.
  `aiosqlitepool` is not a declared dependency despite an old README install example.
- Database implementation: `database/db.py`; mapped entities: `models/db/`.
- Migration tool: project runner in `DataBase.__main_migrations`, with ordered `migrations/migration_*.py`.
- Migration policy: preserve startup runner/history/checksum contracts; do not introduce Alembic.
  Inspect the full runner before edits: it currently invokes both available `upgrade` and `downgrade` functions,
  and records migration names/checksums. A downgrade stub does not establish tested rollback support.
  Do not rewrite already applied migrations or run them against existing data as part of agent setup.
- Shared IP storage: `IpRecordsDbo` is globally unique by exact address; `IpSupportDbo` in the same model module
  records independent domain/non-list and domain/list supports. Scalar domain/list fields are nullable `SET NULL`
  compatibility projections, retaining a valid incumbent or selecting a deterministic remaining support.
  Domain and IP-list reads traverse distinct supported global records. Explicit IP administration still deletes
  the global entity; IP-list refresh withdraws only that list's support. Domain `0` is a real standalone context.
- Shared IP migration: `migration_202618042123.py` preserves global IDs/metadata and backfills only known old contexts.
  Ordinary starts trust completed history without auditing completed effects, exact indexes, managed FKs or support
  consistency. Pending migrations retain their input/output checks; when any new migration is processed, final managed
  FK and support-state checks run after migrations/default seeding and before commit. Failed upgrades roll back
  atomically. Completed legacy import skips its preflight; pending historical imports retain their full validation.
  Previously discarded secondary owners can be learned only from later DNS evidence. An old app on the upgraded
  database and automatic downgrade are unsupported; rollback requires restoring the paired prior app and database.
- Active database toolkit skill: `python-sqlalchemy-core`.
- Active database-specific skill: `python-sqlalchemy-sqlite`.
- Dependency versions source: `pyproject.toml` and `poetry.lock`.
- PRAGMA policy source: `config/config.py` and `DataBase.__configure_connection`.
  Both engines register instance connect listeners before first use; validate and verify settings for each physical
  connection, including pooled replacements and every NullPool writer connection. Reads do not repeat tuning.
  Supported journal modes are WAL, DELETE, TRUNCATE, PERSIST and MEMORY; OFF is rejected to preserve rollback support.
  Keep the dedicated startup connection's temporary FK OFF phase before BEGIN IMMEDIATE and physical closure afterward.
  Verify actual per-connection behavior when changing engine/session code, including SQLite normalization/platform caps.

## Persistence / Runtime Write Policy

- Runtime write policy: single writer queue.
- Read path policy: read engine/session factory owned by `DataBase`.
- Write path owner: `DataBase.__task_process_commit_db_from_queue` and `__batch_items_commit`.
- Normal mutations: enqueue explicit `QueueElementDto` / `TargetAction` values into `db_save_queue`.
- Direct write exceptions: existing startup table creation and migrations; isolated test setup when authorized.
- Durability/backpressure policy: bounded process-local `asyncio.Queue`, producer waiting,
  batch-size/time based writes; this queue is not durable.
- Transaction policy: batch writer uses `BEGIN IMMEDIATE` and owns commit/rollback.
  Enqueue completion is not a commit acknowledgement and does not guarantee immediate read-after-write.
- Resolution payload: admission freezes domain ID, completeness and the full prepared `storage_ips` tuple.
  Resolution intents reconcile supports in admission order inside the existing category phases. Complete IPv4
  evidence withdraws only that domain's absent supports and advances its checkpoint; partial evidence only adds,
  failures preserve prior state, and IPv6 is untouched. Orphan cleanup/projection repair follows all successful
  batch phases, preserving retained IP IDs/metadata and avoiding incidental `updated_at` changes.
- Deployment process/worker assumption: one Python application process per database.
  Verify again before any multi-worker/process change.
- Writer lifecycle: `DataBase` owns its queue, pending batch and writer/cleanup tasks; setup starts one writer.
  Every admitted command has a mandatory retained receipt independent of optional observations. Writer failure
  publishes a sticky lifecycle wakeup. `AppServer.__lifespan` stops coordinator preadmission work, drains through
  `DataBase.close`, and retains outcome bookkeeping through `wait_closed_cleanup`; failures retain unresolved counts.
  This profile records the current boundary, not a claim that all reusable skill recommendations are implemented.
- Required DBA screening: schema/migration, transaction/integrity, writer semantics, retention/privacy,
  or material query/index/performance changes follow the specialist gate above.

## HTTP Client Profile

- HTTP client enabled: yes.
- HTTP client library: HTTPX.
- Retry layer: `httpx-retries`.
- Active HTTP client skill: `python-httpx-client`.
- Timeout policy source: `config/config.py` and the integration-specific client contract. Connect, read, write and pool
  phases are explicit; unset write/pool overrides inherit the integration default. Defaults remain `20/30/20/20`
  seconds for general clients and `20/59/59/59` for RouterOS. DoH and RIPEstat have independent `3/5/3/2` phase
  defaults, one additional HTTP attempt, a one-second cumulative retry-sleep budget and a ten-second operation budget.
  Ordinary DNS explicitly configures timeout/lifetime at `2/5` seconds and a ten-second operation budget.
- External dependency stub policy: `httpx.MockTransport` for outbound unit tests;
  `httpx.ASGITransport` where the tested boundary is an in-process ASGI app.
- Dependency versions source: `pyproject.toml` and `poetry.lock`.
- Retry owner: `RetryTransport` wraps a base `AsyncHTTPTransport` with native retries disabled and configured pool
  limits. Ordinary profiles allow `GET`/`HEAD`; RouterOS allows `GET`/`POST`/`PATCH`/`DELETE`, never `PUT`.
  RouterOS currently uses `POST` only for `/print` reads and `PUT` for creation; preserve this operation boundary.
  Only explicitly selected statuses/exceptions retry; `PoolTimeout`, cancellation and returned response-body failures
  do not. Backoff, jitter and `Retry-After` are bounded; `req_retry_total_timeout` limits cumulative sleep, not full
  request duration. DoH and RIPEstat select their own retry counts and sleep budgets through the same transport owner.
  Their client/resolver operation budgets remain outside the retry transport and cover body consumption plus relevant
  semaphore/cache-lock waits. DNS query budgets cover A/CNAME and bulk/stored/one-shot entrypoints. Expiry is failed
  evidence, while external cancellation propagates. Budgets are per query/lookup, not per whole domain/job.
  Independent eligible RIPEstat lookups use bounded workers and the existing shared semaphore; timeout/error handling
  retains the stored-CIDR/host policy and never caches failures as successful empty results.
- Named client profiles are immutable: reuse matching effective configuration and reject conflicting configuration.
  Limits apply independently to each pool; HTTPcore caps idle connections by the open-connection limit.
- `ObservedAsyncTransport` stays outside the retry layer, preserving one measured exchange across its attempts.
  Environment certificate configuration remains supported, while environment proxy mounts remain disabled.
- Client owner: `HttpClient`; named clients are closed by FastAPI lifespan.
- Preserve RouterOS integration contracts; private router targets can be intentional.
  Determine trust boundaries separately for configured devices and user-supplied list URLs before security changes.

## Security Profile

- Security enabled: yes for relevant backend changes.
- Active security skill: `python-backend-security`.
- Authentication/authorization policy source: inspect relevant routes, clients, settings, and deployment.
  No new authentication, tenancy, or password-hashing scheme is selected by this integration.
- Secrets/configuration policy: environment and Pydantic settings; `.env` and `.codex/config.toml` remain local.
  Never expose credentials in source, reports, logs, documentation queries, or test fixtures.
- Security-sensitive surfaces: RouterOS credentials, outbound URLs, SQL construction, filesystem paths,
  request/error logging, CORS, and resource limits.
- Dependency versions source: `pyproject.toml` and `poetry.lock`.

## Documentation Retrieval

- `context7_documentation.md` is active; Context7 is a preferred read-only source for applicable library versions.
- Discover exact dependencies and runtime configuration first; resolve the intended library, then query only needed
  topics.
- Cross-check ambiguous or consequential results with primary official sources.
- Unavailable Context7 or missing version coverage does not disable subject skills.
  Use official sources when allowed and state remaining version/compatibility gaps.
- Context7 credentials remain in the existing local MCP configuration; no credential is copied into tracked files.

## Dependency Policy

- Existing dependency source of truth: `pyproject.toml` and `poetry.lock`.
- New dependencies require explicit user approval: yes.
- Runtime dependencies: preserve declared constraints and the lockfile unless a requested change authorizes updates.
- Development dependencies: changes follow the same explicit-approval policy as runtime dependencies.
- Security-sensitive dependencies: approval and compatibility/migration review before replacement.

## Project Description

- Primary project documentation: `README.md`.
- Architecture source of truth: actual source/configuration plus this profile; no separate architecture document exists.
- Current integration concerns agent materials and project policy; it does not remediate existing application behavior.

## Critical rules

- Any changes to the project’s folder and file structure must be critically justified and submitted to the user for approval. Modifying the folder and file structure on one’s own is prohibited; all core work must initially be carried out within the existing structure. Only if implementation proves impossible without altering the current structure should the user be consulted. The folder for subagent operations is not subject to these restrictions, but only insofar as it relates to the subagents' own activities, rather than the project code itself.
