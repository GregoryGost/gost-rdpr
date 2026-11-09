# Git work rules

Apply this rule only when `CODEX_PROJECT.md` lists `git.md` in `Active Rules`.
The source file remains `.codex/rules/git.md`; activation uses the bare rule
filename used by `.codex/project.template.md`. For direct commit-text requests,
also apply `.codex/rules/request_routing.md` and use `commit-text-only` mode.

## Direct request activation

Treat short direct phrases such as `дай гит коммит`, `дай git commit`,
`сформируй коммит`, `напиши коммит`, and `provide a commit message` as direct
commit-text requests. Treat semantically equivalent phrases the same way.

Reclassify each such follow-up request independently as `commit-text-only`, even
when it immediately follows implementation, review, or discussion.

## Change-set verification

Before writing the commit message:

- establish the verified change set from read-only inspection of the current
  repository Git status and relevant diffs, or from a diff or patch explicitly
  provided by the user
- inspect staged, unstaged, and untracked changes that may belong to the next
  commit without mutating Git state
- do not infer completed changes from the conversation, planned work, task
  description, or an earlier implementation summary
- cover the complete verified change set since the last commit, including
  changes not discussed in the current conversation
- if neither repository inspection nor a user-provided diff or patch is
  available, do not present a commit message as complete; request the missing
  diff or state that the change set cannot be verified

When requested to provide a Git commit, it must be:

- the commit must be in markdown format
- the title must not be in Markdown style
- must be output as a code block
- include changes since the last Git commit
- display in the commit language declared by `CODEX_PROJECT.md`
- do not use the infinitive
- there should be NO extra git add, git rm or git commit -m commands, only the
  text of the commit itself
- a commit must have a title and then a list of changes
- if the changes were made as part of work on tasks committed to Obsidian, then
  the commit must indicate the numbers of these tasks
- do not commit the pull request itself to Obsidian
- to prepare a commit, do not create any context or task
- the direction of time in the text should reflect what has already been done,
  not what needs to be done
