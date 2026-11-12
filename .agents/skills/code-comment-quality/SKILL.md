---
name: code-comment-quality
description: "Use for mandatory human-readable documentation of all authored functions, methods, fields, variables and constants, with technical completeness and independent review."
---

# Code Comment Quality

## Required Dependencies

- `.codex/rules/code_comment_quality.md`

This is an intentional **mutual rule ↔ skill dependency**: the rule requires this skill, and the skill requires the
rule. Both must be independently active through the target project's `CODEX_PROJECT.md`, with `material_dependencies.md`
validation. Presence of this package or a comment-related request does not activate the pair.

## Purpose and boundaries

Use this skill to ensure **every declaration in the authorized affected source** is documented, then determine the level
of detail it needs and explain it to a human developer. The presence of a short or descriptive identifier does not
permit an undocumented declaration. This is not a formatter, a separate prose-language checker, a code generator or
authorization to rewrite unrelated source.

- Follow the active rule's change-scope and evidence boundaries, existing project convention, and the active
  language/framework skill for syntax and official doc tags.
- For grammatical correctness and target-language consistency, use `comment-language-audit` only if it is independently
  active.
- Do not copy the examples into a real project verbatim. Each worked example is illustrative; its claims must be
  independently checked against the actual target implementation.

## Task-specific reference routing

For any task that creates or changes authored declarations, read the relevant sections of **both** references. Short
methods and local bindings also require documentation; use the short-form examples instead of skipping reference
guidance.

| Need | Reference sections |
| --- | --- |
| Functions, methods, fields and short declarations | `references/documentation-patterns.md`: declaration coverage and placement; `references/examples-and-antipatterns.md`: 1, 16–19 |
| API and error/side-effect contracts | Patterns: contracts/boundaries; Examples: 3, 8, 9 |
| State machine, ordering, concurrency | Patterns: states and concurrency; Examples: 4–6 |
| Async lifecycle, network integration, retries | Patterns: lifecycle/integrations; Examples: 6–8 |
| Resource ownership, architectural trade-offs | Patterns: ownership and decisions; Examples: 2, 9–11 |
| Local, grouped, destructured and loop variables | Patterns: variable coverage and grouping; Examples: 17, 18, 20 |
| Test functions, test locals, misleading/stale text | Patterns: tests and maintenance; Examples: 12–14, 21 |
| Module globals, constants, callbacks and exception bindings | Patterns: declaration coverage and placement; Examples: 22–23 |
| Russian wording by declaration role (class, method, field), including infinitives | Patterns: natural-language check and role-specific wording; Examples: 15, 24–28 |

For a genuinely complex component with multiple relevant dimensions, inspect more than one worked contrast. The
references teach reasoning patterns, not required comment layouts.

## Authoring workflow

1. **Inspect actual behavior.** Read the complete affected function/type, callers, contracts, tests and project
   conventions. Search snippets alone are not proof.
1. **Inventory declarations.** Identify every function/method, callback, class field, constant, module/global variable,
   local and temporary, loop/index, destructured and exception binding, plus test functions and locals inside the
   affected owned definitions. Include short and private declarations.
1. **Map each declaration to documentation.** Give every named function/method its own block; put local/field comments
   beside declarations or in a nearby group that **explicitly names every covered variable and its purpose**. Cover
   parameters inside their function block. If syntax prevents an independent block on a callback, explain that callback
   in the containing declaration's attached block.
1. **Determine required content.** For functions, explain purpose and behavior; add relevant inputs, outputs, errors,
   side effects and constraints. For variables, explain the value's meaning, origin/use and any material units, updates
   or lifetime. Expand complex state, ownership, algorithms or races sufficiently; never manufacture details.
1. **Write for a human developer.** Use specific, naturally phrased sentences and appropriate technical vocabulary, not
   agent-oriented labels or rote templates. In Russian, first distinguish a class that performs work from a class that
   holds data, a method that performs an operation from a field that describes a value. Normally describe methods with
   their actual action and result in the present tense ("Возвращает...", "Открывает..."), rather than a task-like
   infinitive ("Вернуть...", "Открыть..."). This is a preferred style, not a ban on valid infinitives or noun phrases.
   Translate real semantics, not the English name of the symbol. A concise description is mandatory when complete; a
   complex declaration requires the full relevant explanation.
1. **Verify and audit.** Re-read the code and every declaration against the documentation inventory, including
   pre-existing bindings within the affected definition. Check factual accuracy, meaningful coverage, native doc-comment
   syntax, and whether the wording would sound natural when explaining the element to another developer in the target
   language. Use the conditional Russian contrasts in examples 24–28, distinguishing storage from delegation and
   descriptions from instructions. Correct literal calques, vague labels, task-like phrases, and inaccurate blocks
   without inventing behaviors or deleting required documentation.

## Review and handoff

- Review **missing mandatory documentation** separately from content quality. An undocumented named method or binding in
  the affected scope is a finding even when the implementation is short. Treat opaque agent jargon as a readability
  problem without banning necessary technical terms.
- Classify each finding as missing contract, insufficient rationale, missing state/ordering/ownership invariant,
  stale/inaccurate statement, or redundant/misleading narration.
- Give file/line, the verified missing or false claim, concrete maintenance risk, and the smallest source-adjacent
  correction. If behavior is unknowable from available evidence, report uncertainty rather than write a speculative
  comment.
- A comment-only PR is not a code implementation; do not delegate it to subagents when the active project delegation
  contract prohibits comment-only tasks.
- Require documentation for every authored declaration in the affected scope, but not a fixed **length**, repeated
  headings, or comments after every operation. Never use the shortness of a declaration to waive its documentation. Do
  not initiate broad rewrites, new tooling or tests solely for comments.
