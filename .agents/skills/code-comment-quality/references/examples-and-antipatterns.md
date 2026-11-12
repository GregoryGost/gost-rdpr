# Worked Contrasts: What a Maintainer Actually Needs to Know

**Illustrative examples, not executable project code or universally correct contracts.** Assume the stated behavior
exists in each hypothetical component; before using a similar comment, verify it against the target's complete source,
tests, callers and dependency contracts. The snippets use several languages only to expose different engineering
situations. Fragments without complete declarations teach a local explanation only; the containing function and all
authored declarations must still be documented in real code. Translate natural-language prose to the project's selected
language and use its doc-comment syntax. Each lesson concerns **semantic information**, not length. The comments should
sound like something a developer would explain to a teammate, not like an agent's summary or scoring rubric. Technical
terms are welcome where useful, but unexplained abstractions are not.

## 1. A small method still needs a useful block (TypeScript)

**Insufficient:**

~~~ts
class Task {
    private id: string
    idValue(): string { return this.id }
}
~~~

**Correct for a task whose ID is stored at construction:**

~~~ts
/** Keeps the identifier assigned when this task is created. */
class Task {
    /** Identifier supplied by the task creator. */
    private readonly id: string

    /** Creates a task that stores the given identifier.
     * @param id Identifier assigned by the calling code.
     */
    constructor(id: string) { this.id = id }

    /** Returns the stored identifier without changing the task. */
    idValue(): string { return this.id }
}
~~~

**Why:** even the one-line method is documented. The field, constructor, parameter, and accessor have distinct roles and
explanations. The example's `readonly` modifier supports its non-reassignment property; do not infer that other
implementations provide the same guarantee.

## 2. Module role and shared invariants (Python)

**Insufficient:**

~~~python
"""Event delivery helpers."""
~~~

**Stronger when this describes the actual module:**

~~~python
"""Coordinate ordered delivery of stored events to subscribers.

The store owns event identity and persistence; this module owns per-subscriber
delivery cursors. A cursor advances only after the subscriber acknowledges an
event, so a disconnected subscriber may receive the last unacknowledged event
again. Consumers must therefore tolerate duplicate delivery.

This module never deletes events and cannot ensure that the receiver processes each event only once.
"""
~~~

**Why:** this establishes ownership, important observable behavior, and a constraint across multiple functions. It is
not merely a longer title.

## 3. Public API: exceptional and boundary contract (Python)

**Insufficient:**

~~~python
def read_page(limit: int, cursor: str | None) -> Page:
    """Read events."""
    ...
~~~

**Stronger for a hypothetical API that enforces these rules:**

~~~python
def read_page(limit: int, cursor: str | None) -> Page:
    """Return up to `limit` events after `cursor` in ascending ID order.

    A missing cursor starts at the oldest retained event. A valid cursor is
    exclusive: the event identified by it is not repeated in this page.

    Args:
        limit: Number of events to request, in the inclusive range 1..500.
        cursor: Previously returned cursor, or None for the first page.

    Returns:
        Page with events and a next cursor; a missing next cursor means
        no additional retained events were available at read time.

    Raises:
        ValueError: If limit or cursor format is invalid.
    """
    ...
~~~

**Why:** inputs, pagination semantics, boundary values, and errors are actionable to callers. Do not promise stable
snapshots or atomic reads unless the implementation provides them.

## 4. State machine: description versus lifecycle (Go)

**Insufficient:** `// Task state: pending, running, done, cancelled.`

**Better, but still incomplete:** `// Tasks start pending and end done or cancelled.`

**Stronger for a fictional task scheduler:**

~~~go
// Task lifecycle:
//
//     pending --> running --> done
//        |           |
//        +-----------+-----> cancelled
//
// Only the scheduler starts a pending task. A worker can finish just as
// another goroutine requests cancellation. Both updates use the same lock,
// so the task ends as either done or cancelled, never both.
//
// After completion or cancellation, callbacks can read the result, but
// cannot restart the task or change its final state.
~~~

**Why:** the diagram describes reachable transitions, and the prose names the actor, race, winner, and terminal
invariant. Verify that the implementation really enforces a single terminal transition.

## 5. Concurrency: why a guard matters (Go)

**Insufficient:**

~~~go
// Lock to avoid races.
mu.Lock()
defer mu.Unlock()
~~~

**Stronger when these facts are proven:**

~~~go
// A lease can be renewed while an expiry callback from its previous
// version is still running. We check the version under the lock so the
// old callback cannot cancel the renewed lease.
mu.Lock()
defer mu.Unlock()
if expiringVersion != lease.version {
    return
}
lease.expired = true
~~~

**Why:** “avoid races” describes an abstract goal, while the improved version exposes the actual race and the protected
invariant. It must agree with the code's lock coverage.

## 6. Qt/C++ asynchronous lifetime and cancellation

**Insufficient:**

~~~cpp
// Clean up the network response.
reply->deleteLater();
~~~

**Stronger for a finished handler with a `QPointer<Controller> controller`:**

~~~cpp
// The controller may have been destroyed before the reply finishes.
// QPointer becomes null when that happens, so check it before passing
// the data on. Read the reply before scheduling its deletion; do not
// keep the reply after this handler returns.
if (controller) {
    controller->accept(reply->readAll());
}
reply->deleteLater();
~~~

**Why:** the comment says what can go wrong during shutdown and why the pointer check and cleanup order matter. This is
illustrative: the full handler must still be checked for correct reply and receiver lifetimes.

## 7. HTTP retry and ambiguous completion (TypeScript)

**Insufficient:** `// Retry the request when the connection fails.`

**Stronger for an implementation that retries only declared-safe operations:**

~~~ts
// The connection can fail after the server has already saved the change.
// Sending the same request again might apply it twice. Retry only operations
// that the endpoint explicitly allows us to repeat; otherwise the caller
// must check what happened before trying again.
~~~

**Why:** this covers the causality, scope, and consequence of retries. “All POSTs are unsafe” or “GET is always
harmless” would be an unjustified universal claim.

## 8. Cancellation and partial side effects (C# XML documentation)

**Insufficient:**

~~~csharp
/// <summary>Sends the batch.</summary>
Task SendAsync(Batch batch, CancellationToken cancellationToken);
~~~

**Stronger for a client that can stop locally after server acceptance:**

~~~csharp
/// <summary>Submits a batch and waits for the server acknowledgement.</summary>
/// <param name="batch">The batch to submit; its contents are not modified.</param>
/// <param name="cancellationToken">
/// Requests cancellation of local waiting and transport activity.
/// </param>
/// <remarks>
/// Cancellation does not roll back a batch already accepted by the server.
/// If the acknowledgement is lost, the caller must check whether the
/// server accepted the batch before sending it again.
/// </remarks>
Task SendAsync(Batch batch, CancellationToken cancellationToken);
~~~

**Why:** this distinguishes local cancellation from remote rollback. Do not invent exception types or idempotency rules
missing from the real contract.

## 9. Owned versus borrowed data (C++)

**Insufficient:** `// Store bytes for later.`

**Stronger for a hypothetical non-owning input API:**

~~~cpp
// The parser borrows [data, data + size) only for this call and never saves
// the pointer. The caller retains ownership and may release or reuse the
// buffer immediately after parse() returns. Any deferred parsing must first
// copy the bytes into parser-owned storage.
~~~

**Why:** ownership and lifetime are otherwise hard to infer from a raw-pointer signature. Do not make this guarantee if
the implementation queues work that refers to the original memory.

## 10. Justifying a technical decision without fictional history (Go)

**Insufficient:** `// Use two queues because it is faster.`

**Stronger if the actual synchronization contract confirms it:**

~~~go
// Timer callbacks have their own limited queue. Ordinary work waiting
// in another queue cannot prevent an expired timer from being queued.
// This does not guarantee that its callback runs immediately or exactly
// in the order timers expired.
~~~

**Why:** it describes the precise purpose and the limit of the guarantee. Avoid claims about benchmarks, speedups, or
decisions by previous authors without evidence.

## 11. Ordering and persistence boundary (SQL)

**Insufficient:** `-- Insert a row before sending the notification.`

**Stronger for an actual transactional outbox:**

~~~sql
-- Store the event in the same transaction as the business change.
-- Publishing it before commit could tell other services about a change
-- that is later rolled back. The sender may retry and deliver the event
-- twice, so receivers must detect events they have already handled.
~~~

**Why:** this ties the ordering to a real failure mode and explains the delivery consequence. Only use when the
schema/dispatcher behavior supports the outbox contract.

## 12. Test intent and regression protection (Python)

**Insufficient:** `# Call cancel and assert that state is cancelled.`

**Stronger where the test actually exercises the race:**

~~~python
# A timeout from an old lease may arrive after that lease is renewed.
# The old timeout must not cancel the renewed lease or send a second
# cancellation notification.
~~~

**Why:** it explains which defect the test detects. Ensure synchronization in the test actually controls this
interleaving; a comment cannot make a nondeterministic test reliable.

## 13. Stale or speculative explanation: correct or remove

**Misleading after implementation changes:**

~~~ts
// Exactly once: successful sends are never retried.
await transport.send(payload)
~~~

**Better:** confirm what `send` and the surrounding caller actually guarantee. If retries or ambiguous outcomes are
possible, replace the false promise with a verified account of commit/replay semantics. Replace a false declaration
comment with a truthful description of its actual purpose and behavior, even when that explanation is short. Only remove
extra narration that does **not** serve as the mandatory documentation for a declaration.

**Why:** invented guarantees are harmful, but deleting a function or variable's required documentation is not a valid
fix.

## 14. Excess narration versus one high-value constraint

**Overdocumented:**

~~~go
// Read the flag.
enabled := config.Enabled
// Check the flag.
if enabled {
    // Start the worker.
    startWorker()
}
~~~

**Better where a real startup invariant applies:**

~~~go
// routing holds the complete table built from the current configuration.
routing := buildRoutingTable(config)
publishRoutingTable(routing)
// Workers must start after publication of the complete routing table;
// starting earlier would allow a worker to read partially updated routes.
if config.Enabled {
    startWorker()
}
~~~

**Why:** the useful comments explain what `routing` stores and why the sequence matters, rather than narrating each
operation. If startup ordering is not enforced here, the proposed explanation would be misleading.

---

## 15. Human explanation instead of an agent-style abstraction (TypeScript)

**Formally technical, but difficult to read:**

~~~ts
// Enforce request exclusivity invariant to prevent stale asynchronous
// response propagation across overlapping execution boundaries.
if (requestInFlight) return
~~~

**Clearer, when this guard really prevents overlapping requests:**

~~~ts
// Don't start a second request while the previous one is still running.
// Otherwise the older response could arrive last and overwrite newer data.
if (requestInFlight) return
~~~

**Why:** both comments point toward the same risk, but the second names the real situation and consequence. The goal is
not to avoid the terms "async", "invariant" or "race" everywhere. Use them when they genuinely help the intended
developers, and explain an unfamiliar mechanism rather than decorating it with jargon. Do not paste an instruction such
as "Review the contract" or a generated What/Why/Risk template into source comments.

---

## 16. Short method and field (Go)

**Missing documentation (not acceptable):**

~~~go
type Task struct { id string }
func (t Task) ID() string { return t.id }
~~~

**Documented (for the hypothetical task model below):**

~~~go
// Task keeps the identifier assigned when a task is created.
type Task struct {
    // id is the stored identifier used to refer to this task.
    id string
}

// ID returns the identifier kept in the task without modifying it.
func (t Task) ID() string { return t.id }
~~~

**Why:** brief implementation is no exception. The method and field each have a different role to describe.

## 17. Function contract and local variables (Python)

**Insufficient:** `def page_bounds(start, count): return max(start, 0), max(start, 0) + count` (no docstring and no
named explanation).

**Documented for a function whose caller supplies a non-negative count:**

~~~python
def page_bounds(start: int, count: int) -> tuple[int, int]:
    """Return the start and exclusive end of a page within a sequence.

    Negative start values are treated as zero. The caller provides a
    non-negative count; this function does not validate it.
    """
    # first is the starting index after adjusting a negative input.
    first = max(start, 0)
    # end is the index immediately after the selected page.
    end = first + count
    return first, end
~~~

**Why:** the function block describes both inputs, output and a restriction; each local value has a documented role.

## 18. Grouped and destructured variables (TypeScript)

**Insufficient:**

~~~ts
const { endpoint, retryDelayMs } = loadConfig()
~~~

**Documented:**

~~~ts
// Values taken from the current client configuration:
// - endpoint is the address used for outgoing API requests.
// - retryDelayMs is the pause in milliseconds before a permitted retry.
const { endpoint, retryDelayMs } = loadConfig()
~~~

**Why:** a single nearby block is sufficient for related variables **only because it names each one and explains what it
means**. A generic label such as "Client settings" would not cover either binding.

## 19. Properties and constructor (C#)

**Documented for a class that normalizes a lower attempt bound:**

~~~csharp
/// <summary>Holds the retry limit used by the request sender.</summary>
public sealed class RetrySettings
{
    /// <summary>The maximum number of attempts; always at least one.</summary>
    public int MaxAttempts { get; }

    /// <summary>Creates settings with at least one allowed attempt.</summary>
    /// <param name="attempts">Requested attempt limit; values below one become one.</param>
    public RetrySettings(int attempts)
    {
        MaxAttempts = Math.Max(1, attempts);
    }
}
~~~

**Why:** the constructor and property are independently documented. The parameter's meaning is covered by the
constructor block; no duplicate inline comment is required.

## 20. Loop bindings and a temporary value (Go)

**Documented:**

~~~go
// collectNames returns the names in the input records, preserving their order.
func collectNames(records []Record) []string {
    // names collects the values returned to the caller in input order.
    names := make([]string, 0, len(records))
    // index is the position of the record currently being read.
    for index := range records {
        // record is the item from that position in the input slice.
        record := records[index]
        names = append(names, record.Name)
    }
    return names
}
~~~

**Why:** the loop index and temporary are variables too. Their roles are described without inserting a comment after
every operation.

## 21. Test function and test-local values (Python)

**Documented:**

~~~python
def test_empty_page_returns_no_items():
    """Check that an empty input produces an empty page without a cursor."""
    # records represents a source with no available events.
    records = []
    # result is the page returned for that empty source.
    result = make_page(records)
    assert result.items == []
    assert result.next_cursor is None
~~~

**Why:** the test function has its own docstring and both local values are explained. A descriptive test name does not
replace required documentation.

---

## 22. Standalone global variable and constant (TypeScript)

**Insufficient:**

~~~ts
export const MAX_PAGE_ITEMS = 250
let lastRefreshMs: number | null = null
~~~

**Documented for a client using this paging and refresh policy:**

~~~ts
/** Maximum number of records this client requests in a single page. */
export const MAX_PAGE_ITEMS = 250

// Time of the last successful refresh in milliseconds, or null if
// this module has not completed a refresh yet.
let lastRefreshMs: number | null = null
~~~

**Why:** constants and module variables require the same coverage as fields. Their descriptions explain the meaning, use
and units of their values.

## 23. Anonymous callback, its parameter, locals and a catch binding (TypeScript)

**Documented:**

~~~ts
/**
 * Watches for a socket closing and reports the reason.
 * connection is the socket whose close events will be observed.
 */
function watchConnection(connection: WebSocket): void {
    // onClose runs after the socket closes. Its event parameter contains
    // the close reason; the callback sends that reason to the logger.
    const onClose = (event: CloseEvent): void => {
        // reason is the description received with this close event,
        // or "unknown" when the event contains no reason.
        const reason = event.reason || "unknown"
        try {
            reportDisconnect(reason)
        } catch (error) {
            // error is the exception thrown while reporting this disconnect.
            logDisconnectFailure(String(error))
        }
    }
    connection.addEventListener("close", onClose)
}
~~~

**Why:** the named function has its own block, the anonymous function is documented through the declaration that owns
it, and its parameter and local/catch bindings are explained. This is a hypothetical fragment: validate the real
callback lifecycle, error contract and listener cleanup instead of copying it blindly.

---

## 24. Русская калька о владении HTTP-транспортом

Это отдельные фрагменты условных реализаций, а не полные классы. Фактическую ответственность за транспорт необходимо
установить по коду, включая создание и закрытие ресурса.

**Неудачно:**

~~~python
# Владеть транспортом интеграции.
self._transport = transport
~~~

**Если клиент использует переданный ему транспорт, а закрывает его вызывающий код:**

~~~python
# Клиент отправляет HTTP-запросы через переданный транспорт.
# Его закрывает компонент, который передал транспорт клиенту.
self._transport = transport
~~~

**Если клиент самостоятельно создаёт транспорт и закрывает его при завершении работы:**

~~~python
# Клиент создаёт транспорт для отправки запросов и закрывает его
# при завершении своей работы.
self._transport = create_transport()
~~~

**Почему:** слово "владеть" само по себе не объясняет ни использование, ни закрытие ресурса. В каждом исправленном
варианте указаны конкретные действия. Выбирать вариант без проверки устройства реального клиента нельзя.

## 25. Тема класса и реальное чтение настроек графа

**Неудачно для класса, отвечающего за чтение конфигурации:**

~~~python
class GraphConfigReader:
    """Настройки одного графа."""
~~~

**Если он читает соответствующий раздел и возвращает параметры:**

~~~python
class GraphConfigReader:
    """Читает настройки указанного графа из конфигурации.

    Находит относящийся к графу раздел и возвращает параметры,
    которые затем использует код создания графа.
    """
~~~

**Если другой класс только хранит готовые параметры, а не читает их:**

~~~python
class GraphSettings:
    """Хранит параметры, используемые при создании одного графа."""
~~~

**Почему:** "Настройки одного графа" называет тему, но не объясняет, что класс читает конфигурацию. Допустимо и короткое
именное описание, если оно действительно передаёт роль хранилища данных. Не приписывайте чтение разделов, возврат
значений или другие действия, пока они не подтверждены реализацией.

---

## 26. Класс с поведением: описание результата вместо поручения (Python)

**Недостаточно:**

~~~python
class StatusFormatter:
    """Форматировать статус задачи."""
~~~

**Если класс действительно формирует подписи для интерфейса:**

~~~python
class StatusFormatter:
    """Преобразует состояние задачи в подпись для интерфейса."""

    def label(self, is_running: bool) -> str:
        """Возвращает подпись, соответствующую состоянию задачи.

        is_running показывает, выполняется ли задача сейчас.
        """
        return "Выполняется" if is_running else "Остановлена"
~~~

**Разбор:** «Форматировать...» выглядит как поручение разработчику. В исправленном варианте описаны фактическое действие
класса, результат метода и значение параметра. Такой текст подходит только реализации с показанным поведением; другой
класс с похожим названием может выполнять иную работу.

## 27. Методы: не задание «Открыть», а реальное действие и результат (Python)

**Недостаточно как самостоятельные docstring методов:** «Открыть файл», «Закрыть файл», «Заменить фрагмент». Они звучат
как пункты задания и ничего не сообщают об условиях или результате.

**Пример конкретных контрактов методов:**

~~~python
from pathlib import Path
from typing import TextIO


class TextFileOperations:
    """Предоставляет методы открытия, закрытия и преобразования текста.

    Не сохраняет открытые файлы: вызывающий код отвечает за их закрытие.
    """

    @staticmethod
    def open_text(path: Path) -> TextIO:
        """Открывает файл path для чтения в UTF-8 и возвращает поток.

        Вызывающий код должен закрыть возвращённый поток.
        """
        return path.open("r", encoding="utf-8")

    @staticmethod
    def close_text(stream: TextIO) -> None:
        """Закрывает переданный поток stream."""
        stream.close()

    @staticmethod
    def replace_text(text: str, old: str, new: str) -> str:
        """Возвращает строку text, заменив все вхождения old на new.

        Исходная строка остаётся неизменной.
        """
        return text.replace(old, new)
~~~

**Разбор:** «Открывает», «Закрывает», «Возвращает» здесь описывают то, что делает код, и его фактический результат. В
другом методе `open` смысл может быть иным: например, он может только менять состояние или запускать асинхронную
операцию. Не заменяйте инфинитив на форму настоящего времени без проверки поведения. Русский описательный стиль является
предпочтением для документации методов, а не универсальным запретом других форм.

## 28. Класс данных: именная формулировка допустима (Python)

**Пример объекта параметров:**

~~~python
from dataclasses import dataclass


@dataclass(frozen=True)
class LayoutOptions:
    """Параметры оформления элементов интерфейса.

    Содержит отступ и размер текста. Сам объект не применяет эти
    значения к элементам интерфейса.
    """

    # spacing_px задаёт расстояние между элементами в пикселях.
    spacing_px: int
    # font_size_px задаёт размер текста в пикселях.
    font_size_px: int
~~~

**Разбор:** описание через существительное соответствует роли объекта, который содержит значения, но не выполняет
действие. Для класса, который сам применяет оформление, необходимо было бы описать его фактическое поведение. Нельзя
механически начинать комментарий любого класса с глагола.


---

## Calibrate by consequence, not size

Each authored declaration in the affected scope requires a documentation block or an explicit grouped-variable
explanation, even when its implementation is short. Some examples above focus on a fragment of a larger function; they
do **not** waive documentation for the enclosing function or other variables in real source. A complex public boundary
can need several paragraphs and a transition table. Keep every necessary fact, without filler or invented guarantees.
