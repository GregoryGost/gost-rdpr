# Code Comment Quality

Apply this cross-language rule only when it is explicitly active in the target project's `CODEX_PROJECT.md`. It applies
to authorized creation, modification, and review of source code, tests, code comments, docstrings, and API documentation
embedded in source. It does not authorize unrelated documentation edits or a repository-wide comment rewrite.

## Required skills

- `code-comment-quality`

This rule and `code-comment-quality` intentionally declare a **mutual rule ↔ skill dependency**. Both must be
independently active; validate the pair with `.codex/rules/material_dependencies.md` before use. This rule does not
activate the skill by reference.

## Mandatory coverage: every authored declaration

For new or affected **authored declarations in the permitted scope**, a comment or documentation block is **required**,
regardless of function size, visibility, identifier clarity, or number of operations. The agent determines **what
information to include**, not whether to document.

- **Every function and method** must have its own explanatory block attached to the declaration: public/private
  functions, constructors, destructors, accessors, handlers, named nested functions, test functions and fixtures. For
  anonymous callbacks or expressions that cannot carry a standalone block, an adjacent block on the containing
  declaration must explicitly identify and describe that callback.
- **Every variable or constant** must be documented: instance/static fields, properties, module/global variables,
  constants, locals, temporary values, destructured bindings, loop variables, and exception/catch bindings. A nearby
  **group block is allowed only if it explicitly identifies each declared name and explains its role**. Merely
  describing the enclosing function or class is not coverage of its variables.
- **Named classes/types** also need documentation of their responsibilities; module-level context should be documented
  where applicable. A class summary never replaces comments for its fields or methods.
- **Parameters** may be documented together inside the owning function/method block, including their meaning and
  relevant constraints. No separate inline comment is needed for each parameter.
- Document **declarations**, not mechanically every use, assignment, operator, or import. Add further explanatory
  comments for significant mutations and fragile sequences when needed. Generated/vendor/external source is excluded
  only because it is not authored within the authorized task, never because it appears simple.

**Required detail:** a small function or variable must have a short, meaningful description of its purpose and actual
behavior/meaning. A complex one must have enough explanation to cover its relevant algorithm, state, interactions,
contracts, constraints, and error paths. A comment that only restates a name is **insufficient** even though one is
present. No fixed word counts or mandatory headings apply.

## Technical completeness

- For each **function or method**, explain its purpose and result; where applicable, include inputs, outputs, side
  effects, errors, lifecycle, ordering, cancellation, state changes, and reasons for important choices.
- For each **variable, field or constant**, explain what its value means **here** and why it exists; when relevant
  describe initialization, source, units, allowed values, updates, ownership, and lifetime.
- Attach documentation at the declaration using the active language conventions (Python docstrings, Go declaration
  comments, JSDoc/TSDoc, C++/Qt documentation, C# XML tags, etc.). A shared architecture overview supplements rather
  than replaces required per-declaration documentation.
- Use diagrams or multi-paragraph explanations when needed to make a complex mechanism understandable. Never omit
  relevant information in order to be brief, and never invent material to fill a template.

## Human maintainer first

Write comments **for another developer who must understand, debug, or change this code**, not for an AI agent, an
automated reviewer, or a documentation checklist. The content should sound like a colleague explaining a concrete
behavior, not a generated analysis report.

- Prefer natural, direct sentences with identifiable actors and actions: what can happen, under which condition, why the
  code acts this way, and what would break if it changed. Concrete explanations beat labels such as "enforce lifecycle
  invariant" when those labels alone do not explain the behavior.
- Use accurate technical terms, identifiers, protocol names, and project vocabulary when they make an explanation **more
  precise**. Do not ban necessary terminology or oversimplify expert concepts. Briefly explain an unfamiliar term in
  context when the intended project's developers would otherwise have to guess.
- Avoid artificial "AI-style" prose: generic padding, repeated "responsible for" descriptions, abstract buzzword chains,
  rigid What/Why/How or Risk/Invariant/Decision sections, and self-assessment or instructions addressed to agents. A
  project-required documentation format (for example, `@param` or XML documentation tags) and a genuinely useful state
  diagram are exceptions, not defects.
- Make the prose readable in the project's chosen natural language. Do not copy internal task analysis, prompts,
  reviewer checklists, or English-language constructions into source comments. Use ordinary, grammatically natural
  language rather than a literal translation of reference examples.
- Explain a real mechanism at the detail necessary for safe maintenance; do not trade away important conditions or
  guarantees merely to shorten the text.

## Russian and other natural-language explanations

A grammatically possible phrase is not necessarily useful documentation. Check the **verified role or behavior**, not
just whether the comment has words.

- Do not convert a code identifier into an untranslated topic label or an imperative task. Explain what the element
  does, contains, returns, or changes, and why that matters here.
- Reject literal calques of English technical idioms when they hide the actual meaning. For example, "Владеть
  транспортом интеграции" does not explain whether the HTTP client creates, uses, or closes the transport. Find the
  actual resource-lifetime contract and describe that in normal Russian.
- "Настройки одного графа" may label a data object but is incomplete for a configuration **reader**. If the class reads
  a graph's configuration, explain the reading operation and its verified result; do not invent parsing, validation, or
  return semantics.
- Keep Russian case agreement, idiomatic word order, and coherent subjects and actions. Prefer natural
  developer-to-developer prose to a word-for-word English translation, isolated infinitives that read like task
  instructions, and opaque noun stacks.
- Do **not** mechanically ban infinitives, noun phrases, precise technical vocabulary, or short blocks. They are
  acceptable when they communicate the actual meaning naturally.
- **Choose Russian wording by the declaration's verified role.** An active class should describe the service or
  operation it performs (e.g. "Читает...", "Отправляет...", "Предоставляет..."); a data container can be described as
  holding or representing particular values ("Хранит...", "Содержит...", "Параметры..."). A method normally describes
  its observed action/result ("Открывает...", "Закрывает...", "Возвращает...", "Заменяет..."); a field may use a concise
  descriptive noun phrase.
- A Russian method docstring consisting only of an infinitive such as "Открыть...", "Закрыть..." or "Заменить..." can
  read like an assignment to the author. **Prefer an actual-behavior statement in the present tense** for method
  documentation when it communicates the contract naturally. This is a style preference, not a grammatical prohibition;
  never rewrite a valid statement only to change its verb form.
- Do not replace a task-like infinitive with a present-tense verb mechanically. First establish what the declaration
  actually does: retains data, transforms it, delegates an operation, coordinates other components, or serves another
  role. An identifier alone cannot justify claims about persistence, serialization, resource ownership, backend choice,
  or lifecycle.
- Keep reusable guidance technology-independent. A user-provided example illustrates a general failure mode; it is not a
  reason to make its package, class, or particular implementation an exception or focus of the rule.
- This meaning/readability check is part of **this** rule even if the optional `comment-language-audit` skill is not
  active; that skill adds deeper language-focused review.

## Evidence, accuracy, and upkeep

- Ground each factual comment in the real implementation, callers, tests, project contracts, or verified platform/API
  behavior. Do not invent design history, alternative approaches that were never considered, concurrency guarantees, or
  external-service behavior.
- Distinguish guarantees from implementation details, assumptions, contingencies, and examples. When rationale is
  unknown, investigate within authorization or report the gap; do not manufacture an explanation.
- Keep comments synchronized with changed conditions, error cases, control flow, API semantics, and invariants. Remove
  or correct misleading documentation in the affected scope.
- Respect the project-selected natural language and language-specific syntax (Go doc comments, Python docstrings, C++/Qt
  documentation, JSDoc/TSDoc, XML docs, etc.). The separately active `comment-language-audit` checks prose language; it
  is neither a substitute for nor an automatic dependency of this pair.
- Avoid ticket IDs, internal planning labels, and temporary implementation-history commentary except where they are
  genuine product contracts; preserve `source_code_hygiene.md` when active.

## Change-scope boundary

For an authorized code change, inventory **every authored declaration inside the affected owned function/type**,
including existing local variables and nested functions, and bring required documentation there into compliance. Check
comments affected by the behavior change. Do **not** turn a narrow task into an unsolicited audit of unrelated modules,
files, or generated code, or refactor code solely to satisfy comment formatting. A repository-wide documentation update
requires explicit authorization; this rule authorizes no new runtime behavior or tooling.

## Reviewer gate

On the affected stable source snapshot:

1. **Inventory every named function/method and every variable, field and constant** within the authorized affected
   definitions, including private and short methods, loop and destructured bindings, callbacks and tests.
1. Check each function/method for its **own** attached explanatory block. Check each variable for an adjacent
   explanation or a group block that **names it and explains its meaning**. Parameters may live in the method block.
1. Independently verify the content: purpose and actual behavior, applicable contracts, reasons, constraints and
   outcomes; no tautologies, gaps or fictitious guarantees.
1. Check for natural, complete explanations in the selected language, not just formal grammatical correctness. Compare
   the **actual declaration role** with its wording: does a class describe its verified responsibility, a method
   describe its operation/result, and a field describe its value? Identify literal translations, task-style infinitives,
   and class-name paraphrases when they hide real behavior. Prefer descriptive present-tense Russian for method
   docstrings where suitable, without banning valid infinitives, nominal descriptions, or necessary technical terms.
1. Report **missing mandatory documentation** and insufficient or stale comments as actionable findings, with exact
   path/line and the smallest correction. Do not waive the finding because a declaration is short or its name appears
   descriptive.

The mere presence or number of comment lines does not establish quality. Review the skill's applicable patterns and
examples; do not use unrelated documentation rewrites to satisfy the check.
