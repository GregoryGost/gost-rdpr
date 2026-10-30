# Material dependency rules

Apply this rule when an active rule or skill declares another rule or skill as required, or when maintaining dependency declarations in the template repository.

This is a conditional bootstrap support rule. When hard dependencies exist, the file must be present and applied regardless of whether it is listed in `Active Rules`. It validates only explicitly declared hard dependencies and does not activate unrelated materials.

## Hard dependency declarations

Treat a referenced rule or skill as a hard dependency when the entrypoint declares it unambiguously through one of these forms:

- a `Required Dependencies` section;
- a `Required skills` section;
- `Use together with` when the wording is unconditional and identifies exact artifacts;
- an explicit `requires` statement;
- an unconditional `Apply <artifact> together with this ...` statement.

When an entrypoint contains a `Required Dependencies` section, treat that section as authoritative for its hard dependencies. Do not reinterpret optional-coordination sections as additional hard dependencies.

Do not treat conditional coordination as a hard dependency, including wording such as:

- `combine with ... when active`;
- `apply ... when the task touches that area`;
- `use the active ... skill` when that area is optional for the current task;
- examples, related-material lists, or references that do not state a requirement.

For new or substantially updated skills, use a `Required Dependencies` section containing exact skill names and full rule paths. Rules should use `Required skills` and exact skill names; required rule paths must be stated explicitly.

## Material versus runtime/tool dependencies

This validator covers dependencies between repository materials: rules and skills.

Do not treat an executable, SDK, runtime, framework, engine, Editor, package, plugin, compiler, platform module, service, or version requirement as a material dependency merely because an active artifact needs it at runtime or during validation.

Examples of non-material requirements include:

- a Unity Editor version;
- a Unity CLI version;
- a Unity package or Editor module;
- a Blender Editor version;
- the official Blender MCP server/add-on version;
- Blender's embedded Python or `bpy` runtime;
- a compiler/runtime version;
- a platform SDK;
- a connected local application or service.

The owning specialized profile/rule/skill must declare and validate runtime/tool requirements against project or runtime evidence. A runtime/tool requirement never activates a rule or skill and does not satisfy a missing material dependency.

## Validator availability

When an active artifact declares at least one hard dependency:

- `.codex/rules/material_dependencies.md` must exist in the target project;
- the bootstrap must apply it even when it is not listed in `Active Rules`;
- an absent validator file is a profile error;
- dependency validation must stop before applying the dependent artifact.

Report this failure explicitly:

```text
Dependency validation is required, but .codex/rules/material_dependencies.md is missing.
```

## Validation workflow

Complete dependency validation before the first task-specific action whose
behavior depends on the artifact. Validation performed after using the artifact
does not retroactively authorize that use.

Before applying a dependent artifact:

1. Confirm that the artifact itself is active through a signal allowed by `AGENTS.md` and `CODEX_PROJECT.md`.
2. Read the artifact entrypoint and collect only its explicit hard dependencies.
3. Resolve each dependency to an exact rule path or skill name.
4. Confirm that each dependency exists in the target project.
5. Confirm that each dependency is active through an allowed activation signal and is not disabled or set to `none`.
6. Repeat the same validation for every dependency until the complete transitive closure is checked.
7. Track visited artifacts so a valid intentional cycle does not recurse indefinitely.

A dependency cycle never activates its members. Every member must be active independently through the project profile.

## Cycle policy

Allow a cycle only in one of these cases:

- a mutual `rule ↔ skill` pair where each entrypoint explicitly requires the other;
- another intentional cycle documented as such in the entrypoints of every member.

For an allowed cycle, every member must exist, be active, and have all outgoing dependencies satisfied.

Treat these as dependency-graph errors:

- a self-dependency;
- an undocumented cycle;
- a multi-node cycle documented by only some participants;
- a cycle containing a missing, inactive, disabled, or ambiguous member.

## Failure handling

When a dependency or validator is missing, inactive, disabled, or ambiguous:

- do not apply the dependent artifact;
- do not silently activate or copy the missing dependency;
- report the dependent artifact, the missing dependency, and the full dependency chain;
- distinguish a missing file/package from a present but inactive dependency;
- change `CODEX_PROJECT.md` only when the current request and `request_routing.md` authorize a profile change;
- after an authorized correction, run dependency validation again from the original artifact.

If dependency wording is ambiguous, treat the profile as unresolved rather than guessing whether the dependency is mandatory.

## Template repository maintenance

When adding, changing, or reviewing a rule or skill dependency declaration, apply this rule and:

- keep hard dependencies in the entrypoint, not only in references;
- use exact identifiers that match `.codex/rules/` paths and `.agents/skills/` names;
- prefer `Required Dependencies` in skills and `Required skills` in rules;
- keep optional coordination in a separate section;
- verify reverse references and transitive dependencies;
- preserve only explicitly documented intentional cycles;
- update `README.md` and `.codex/project.template.md` when dependency handling or required project files change.

## Review checklist

- [ ] The validator file is present when hard dependencies exist.
- [ ] Every hard dependency is declared explicitly in the entrypoint.
- [ ] Optional coordination is not misclassified as required.
- [ ] Runtime/tool requirements are not misclassified as material dependencies.
- [ ] Exact rule paths and skill names resolve to existing artifacts.
- [ ] Every required artifact is active and not set to `none`.
- [ ] The full transitive closure was validated.
- [ ] Only documented intentional cycles were accepted.
- [ ] Missing dependencies were reported instead of activated silently.
