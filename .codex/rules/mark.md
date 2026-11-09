# Markdown files

Apply this rule when creating or editing non-Obsidian Markdown files.

Obsidian vault content remains governed by the active Obsidian rules and the configured MCP-only boundary.

## Source of truth

Before changing a Markdown file:

1. Read `CODEX_PROJECT.md` when it exists and resolve the active documentation, formatting, linting, and
   validation policies.
1. Inspect the repository scope containing the target file for project-declared Markdown configuration and
   commands. In particular, read `.markdownlint.json` when it exists.
1. Treat the applicable project markdownlint configuration as the source of truth for Markdown style and linting.
   Do not copy project-specific markdownlint rule values into this reusable rule or replace them with generic
   preferences.
1. In nested workspaces, use the configuration and command that apply to the target file instead of assuming that
   a repository-root configuration applies everywhere.
1. Use only project-declared validation commands and file scopes.

## Constraints

- Before creating any non-Obsidian-specific documentation in Markdown format, ask the user if it should be
  created.
- Under no circumstances should you create a `docs` folder or documentation files within it.
- Follow existing markdownlint configuration without silently modifying it.
- Change markdownlint configuration only when the user explicitly requests a configuration change or the
  requested project-policy change requires it.
- Do not add or install Markdown formatter or linter dependencies unless the user explicitly approves it or the
  project dependency policy already permits it.
- Avoid broad formatting changes in unrelated Markdown files.
- When Prettier or another formatter also handles Markdown, follow the project-declared workflow instead of
  inventing a tool order.

## Validation

- Run the project-declared Markdown lint or check command for changed files when it is available.
- If no validation command is declared, review changed Markdown against the applicable project configuration and
  report that no automated command was run. Do not rely on an unapproved global tool.
