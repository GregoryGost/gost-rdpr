# Documentation Patterns: Technical Coverage Without Narration

These patterns are language-independent. Adapt syntax, naming, terminology, target natural language, and doc conventions
to the active project. **Every authored declaration in the affected scope requires documentation.** The length varies
with factual complexity, never with permission to omit the comment.

## 1. Required declaration coverage and placement

| Declaration | What to explain | Where to document |
| --- | --- | --- |
| Module, class or named type | Its responsibility and important relationships | Module/type block |
| Every function/method, including private, constructor, accessor, handler, nested and test functions | Purpose, actual behavior, relevant inputs/results/errors and effects | Its **own** declaration-attached block; Python uses an in-body docstring |
| Anonymous callback | Trigger, role and effects | Adjacent block explicitly describing it on the owning declaration if a separate block is not supported |
| Class/instance/static field and property | Meaning and role of the stored value, relevant initialization, ownership or changes | Adjacent or explicitly named group block |
| Module/global/local variable, constant, temporary, destructured/pattern binding | What its value represents **here** and why it is used | Adjacent or group block that names and explains **each binding** |
| Loop index/key, exception/catch variable | What it represents in the loop or handler | Before its loop/handler or beside the binding, explicitly identified |
| Function parameter | Role and relevant constraints | In the function documentation block or language-native parameter tags |

**Coverage is per declaration.** One group block can cover related variables but must identify every name and its role.
A class or function summary does not automatically cover its fields or locals. Do not demand a separate comment for
every subsequent assignment or use.

### Group and local examples

~~~ts
// These settings are used when connecting to the service:
// - endpoint: address to which requests are sent;
// - retryDelayMs: delay in milliseconds before another permitted attempt.
const { endpoint, retryDelayMs } = readSettings()
~~~

~~~go
// index points to the source record being processed on each iteration.
for index := range records {
    // ...
}
~~~

Use the natural language and correct comment syntax selected by the project; these are hypothetical excerpts, not
permission to invent contract details. See worked examples 22–23 for module-level values, an anonymous callback, and a
catch binding.

## 2. Locate the explanation at the right level

| Level | Document when relevant | Do not |
| --- | --- | --- |
| File/package/module | The component's responsibility, entry points, external boundaries, shared invariants or protocol assumptions | Restate the import list or every public symbol |
| Class/type/subsystem | Ownership, lifecycle, cooperation between components, states, thread affinity, shared state | Replace individual member documentation with a class summary |
| Public API | Inputs/preconditions, outputs, mutation/side effects, errors, cancellation, idempotency, guarantees, surprising edge cases | Promise behavior not established by code or contract |
| Private method | Purpose and behavior; algorithm stages, correctness conditions and constraints when relevant | Treat a short or private method as exempt |
| Delicate operation | Why the exact order, guard, lock, retry limit, or cleanup boundary matters | Record temporary design discussion or ticket history |
| Test | The scenario, important setup, asserted invariant and regression the test protects when not evident from its name | Assert the implementation algorithm in prose rather than expected behavior |

Avoid scattering one global contract over many methods: describe it once near its authoritative owner and
cross-reference existing established names where useful.

## 3. Contract completeness: focus on caller-visible distinctions

Ask which aspects could change the correct use of the API:

- Null/empty values, valid ranges, units, defaults, sentinel values, and who owns or mutates arguments.
- Meaning and stability of return values; partial results; ordering; cardinality; persistence.
- Error types, cancellation and timeout semantics, early exits, and whether work may already have committed.
- Resource lifetime, thread/callback affinity, backpressure, and retry/idempotency guarantees.
- Version-/platform-specific assumptions only when verified for the actual project.

Document **only** applicable items. An internal helper need not restate a fully established public contract.

## 4. State machines and long-running coordination

When behavior depends on states, show the **reachable model**, not only a list of constants:

1. Identify the owner of state and whether state is local, shared, persisted, or externally observed.
1. Specify triggering events and allowed transitions, including failure and interruption paths where they matter.
1. State terminal states, forbidden transitions, and invariants that guard correctness.
1. Explain timing/race windows and the mechanism ensuring an old event cannot affect a new operation.
1. Distinguish a conceptual diagram from actual runtime values if there are intermediate/transient states.

Use an ASCII transition table/diagram when it is clearer than prose, as in complex schedulers; do not copy a particular
upstream implementation's states into an unrelated project.

## 5. Concurrency, async lifecycle, and resource ownership

A useful explanation connects a specific hazard to the protection used:

- **Concurrency:** Who may access state concurrently? Which lock, atomic operation or event-loop confinement establishes
  the guarantee? What must be done under the lock? What race would omission cause?
- **Async:** Who schedules and cancels work? Can a callback arrive during teardown? What does cancellation guarantee,
  and what *doesn't* it guarantee?
- **Ownership:** Who allocates, borrows and releases a resource? Can a borrowed view outlive the owner? What happens on
  exceptional exits?
- **Ordering:** Why must A precede B? Is it a publication barrier, transaction/commit boundary, or protocol constraint?
- **Failure:** What can be retried safely, how can an ambiguous remote outcome arise, and which resource remains live
  after failure?

Do not claim a particular memory-order, cancellation guarantee, or event-loop behavior unless the target's
implementation or verified platform contract supports it.

## 6. Integration and technical choices

Document the verified boundary, such as:

- What the dependency is responsible for versus what this component must enforce.
- An external protocol or serialization assumption, including units and compatibility.
- Why an apparently simpler option violates a real requirement or invariant.
- What happens on a transient fault, a partial response, or an already-committed remote write.

A comment can explain a *known technical constraint* without inventing historical intent: say “This order prevents ...”
only when the causal relation is verified. Do not claim “We chose ... over ... after testing” without actual evidence.

## 7. Mandatory depth and coverage review

- **Small function or variable:** an accurate, specific sentence that explains its purpose and behavior/value;
  documentation is still required.
- **Contract-bearing function:** describe the real inputs, result, relevant effects, errors and usage limits.
- **Complex algorithm or subsystem:** explain important stages, transitions, invariants, ordering, concurrent or failure
  behavior as fully as needed.
- **Local bindings:** individually explain their meaning or use a group block explicitly mapping every name to a
  concrete purpose.

These are levels of **required detail**, not a choice between documenting and omitting. An identifier paraphrase such as
`// Retry count` is insufficient. Do not add fabricated details or filler to meet a length target.

Review every authored declaration within the affected owned function/type. Check for an attached function/method block
and individual or grouped coverage for all variables. Then independently check accuracy, useful specificity and
human-readable style. A missing declaration block is actionable even when the code is short.

## 8. A developer should understand it on first reading

The patterns and review questions in this document are **instructions for the author**, not headings or wording to paste
into actual source comments.

- Write like a colleague explaining a concrete problem: "The old response can arrive last and replace newer data" rather
  than "preserve asynchronous ordering invariants".
- Prefer specific nouns and verbs over stacked abstractions. Name the worker, request, lock, database row, or callback
  when the code makes it identifiable.
- Give context for a specialist term if a teammate working on this project may not know it; preserve established terms
  such as `commit`, `mutex`, `QPointer`, `context.Context` and exact API names when they are the clearest description.
- Keep paragraphs and lists only when they improve navigation. Do not stamp every comment with "Context / Contract /
  Invariants / Risks", introduce your own grading scale, address an AI assistant, or embed a reviewer task list in
  production source.
- Don't turn source comments into beginner tutorials for standard language features. Readers are developers, not
  necessarily nontechnical users. The desired result is clarity **without losing precision**.
- In the project's selected language, use phrases a teammate would naturally write; translate meaning, not the English
  syntax of examples.

**Human-reader check:** after reading the comment alone, can a developer say what might go wrong and why the code
prevents it, in plain technical language? If not, simplify the *wording* or add the missing concrete cause, rather than
deleting necessary facts.

## 9. Natural-language checks for code comments

This is guidance for the author, **not** a set of headings to insert into source comments.

- Recover the real meaning first. English "own" can mean that the component creates and closes a resource, borrows it,
  or is responsible for a resource owned elsewhere. Those cases require different comments.
- Name the declaration's action when a class actually reads a configuration; a mere noun phrase describing the data it
  handles can hide its responsibility.
- Reject word-for-word calques and machine-like noun stacks when they obscure meaning. Use fluent grammar and normal
  word order in the configured language.
- Do not treat any single word or sentence form as forbidden: a nominal explanation can accurately describe a value
  object, and specialist terminology may be essential.
- Verify every asserted action or lifetime rule against source and actual contracts. Do not add invented behavior just
  to complete the prose.

**Maintainer test:** can a colleague tell what the component actually does or represents, without mentally translating
the sentence back into English? Examples 24–28 illustrate Russian-specific failures, distinct contracts, and
role-specific phrasing.

## 10. Russian description style by declaration kind

Choose the **meaning first**, then a natural way to express it. Prefer third-person, present-tense descriptions of
operations for Russian functions/methods; this is a project writing convention, not an attempt to change the API's
behavior or prohibit every infinitive.

| Declaration | Russian description when the code supports it | What to avoid |
| --- | --- | --- |
| Active class (reader, HTTP client, adapter, coordinator) | "Читает конфигурацию и возвращает настройки...", "Отправляет запросы через переданный транспорт..." | Describe only its data or name; attribute storage/ownership it does not implement |
| Class that actually keeps data | "Хранит записи по ключам в словаре экземпляра..." | Assume internal storage or serialization solely from a name rather than inspecting the implementation |
| Value object / configuration record | "Содержит параметры...", "Параметры отображения графа..." | Force an action verb when the object is only a data container |
| Function or method | "Открывает файл и возвращает поток...", "Закрывает переданный поток...", "Заменяет фрагмент и возвращает результат..." | Bare "Открыть...", "Закрыть...", "Заменить..." that reads as an instruction and omits the actual result |
| Field, property, local variable | "Путь к файлу, который будет открыт...", "Время последнего успешного обновления..." | A meaningless noun/name paraphrase or an invented lifecycle guarantee |

The same verb can be correct for one class and false for another. "Хранит" is useful when a component really retains
values; it may be inaccurate for a wrapper that forwards calls to a separately configured backend. Likewise, a method
named `open` might return a stream, merely mark state as open, or schedule an asynchronous operation. **Inspect the
implementation before choosing the description.**

A nominal phrase or infinitive is not inherently an error in Russian: it may be appropriate for a value definition,
established API style, or a genuine instruction. Do not transplant the English imperative convention of some
documentation styles into Russian verbatim. Check whether the phrase explains **what this declaration does/contains**
rather than telling someone what to do.

## 11. Maintenance and change discipline

A behavior change may invalidate a comment that is physically outside the modified lines. Inspect directly dependent
comments and examples within the permitted scope. Correct or remove stale promises. Do not initiate a repository-wide
documentation campaign, generate speculative explanations, or alter executable behavior merely to make a comment sound
complete.

Reference inspiration can come from high-quality open-source code, but **extract transferable reasoning patterns rather
than importing a particular class's documentation layout, implementation-specific transitions, or code text**.
