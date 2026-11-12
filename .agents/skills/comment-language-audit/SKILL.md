---
name: comment-language-audit
description: "Use for auditing or editing code comments and docstrings against the natural-language policy in CODEX_PROJECT.md."
---
# Comment Language Audit

## Overview

Use this skill for portable language-policy work on code comments and code-adjacent prose across programming languages and frameworks.

This skill covers natural-language quality only: target-language consistency, mixed prose, partial translation, grammar, inflection, source-language calques, noun-phrase construction, and audit workflow. Combine it with the active language or framework skill for syntax-specific rules such as Python docstrings, JSDoc, TSDoc, XML documentation comments, or framework documentation conventions.

Semantic completeness, factual rationale, and documentation coverage belong to the separately activated
`code_comment_quality.md` + `code-comment-quality` pair. Neither skill activates the other, and this language audit does
not replace source-grounded technical review.

## Scope And Coordination

- Read `CODEX_PROJECT.md` before editing code prose. Use its declared target natural language for comments, docstrings, test comments, and documentation blocks.
- Apply this skill when it is listed in `CODEX_PROJECT.md` active skills and the task creates, edits, reviews, translates, or audits comments, docstrings, doc comments, JSDoc/TSDoc blocks, XML documentation comments, or other explanatory code-adjacent prose.
- Keep language-specific syntax, placement, tags, and formatting rules in the active programming-language or framework skill.
- Do not add language-policy checks to linters, formatters, type checkers, or tests unless the project already has approved tooling for that purpose.

## Target-Language Policy

- Treat each comment/docstring/doc comment as full prose in the repository target natural language.
- Foreign-language tokens are allowed only when they are exact code identifiers, API fields, class/function/module/package names, commands, paths, protocols, standards, external product names, or real contract values.
- Do not partially translate explanatory prose. After editing a sentence, reread the complete final sentence and rewrite remaining explanatory foreign-language words into the target language unless they match an allowed exact-token category.
- Do not copy mixed-language task, backlog, issue, design-note, or documentation phrasing into comments/docstrings/doc comments. Convert explanatory wording into the repository target language while preserving exact identifiers and contract tokens.
- Comments and docstrings in the target language must read as grammatically correct prose, not as a word-by-word translation.
- For languages with inflection and agreement, check case, government, word agreement, verb-form consistency, and complete sentence structure.
- Rewrite awkward literal translations into simple natural sentences while preserving exact code names and contract tokens.
- For target languages where noun modifiers require case, agreement, hyphenation, adjective forms, or genitive constructions, do not keep source-language noun stacks as-is. Rewrite them into natural target-language noun phrases.

## Meaning-sensitive language review

- Literal translations can be grammatically correct yet useless. Recover the verified declaration purpose before
  translating expressions such as English "owns transport" or "settings for one graph" into Russian.
- For a resource owner, say who **creates, uses and closes** it only to the extent these facts are established. For a
  configuration reader, describe what it actually reads or returns. Avoid imperative fragments like "Владеть транспортом
  интеграции" and topic-only labels such as "Настройки одного графа" where the role is a reader.
- Do not blacklist grammatical forms. A noun phrase is appropriate for some data containers; an infinitive can be
  natural in context. For Russian docstrings, a method's present-tense action ("Открывает...", "Возвращает...") often
  explains behavior more naturally than a task-like infinitive ("Открыть...", "Вернуть..."). A data class may
  legitimately use "Хранит..." or a noun phrase if that matches its role; an adapter should describe its real operation
  rather than claiming to store values. Judge the completeness, naturalness, and truth of the whole explanation.
- This skill audits natural language when independently active; the source-comment quality pair must still check
  explanatory meaning when this language skill is inactive.

## Audit Workflow

Use this workflow when the task asks to clean, review, or enforce comment/docstring language policy.

1. Do not rely on searches for known bad phrases as the final audit gate. Phrase searches are only locators.
2. Build a complete inventory of comments/docstrings/doc comments in the affected scope. Prefer language-aware extraction when available, such as AST extraction for docstrings and tokenizer-based extraction for comments.
3. Review every extracted entry containing foreign-language words.
4. Keep foreign-language tokens only when they match the allowed exact-token categories.
5. Rewrite explanatory prose as complete sentences in the target natural language. Partial translation is not sufficient.
6. Review edited entries as complete target-language sentences, not only as translated token sequences.
7. For languages with inflection and agreement, check case, government, word agreement, verb-form consistency, and sentence structure after translation or rewrite.
8. Rewrite source-language noun stacks into natural target-language noun phrases when required by target-language grammar.
9. In the final report for a language-policy task, state that all comments/docstrings/doc comments with foreign-language tokens in the affected scope were reviewed, and state what category of tokens was intentionally left.
