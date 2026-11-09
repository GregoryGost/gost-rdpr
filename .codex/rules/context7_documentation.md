# Context7 documentation retrieval rules

Apply this rule only when `CODEX_PROJECT.md` lists `context7_documentation.md`
in `Active Rules`.

Context7 is an optional read-only documentation source. It supplements active
subject-matter rules and skills and is not a hard dependency of them. If
Context7 is unavailable, do not invalidate otherwise active materials.

## Use Context7 for

Use Context7 when the current task depends on library, framework, SDK, tooling,
or API behavior that may differ by version.

Determine what actually applies from project evidence first, including
manifests, lockfiles, installed/runtime versions, project configuration, and
`CODEX_PROJECT.md`.

Context7 is especially useful with active materials for:

- Python, testing, FastAPI, SQLAlchemy, HTTPX, `cashews`, and `nats-py`;
- TypeScript, Jest, ESLint, and Prettier;
- Node-RED contrib modules and `node-red-node-test-helper` when a reliable
  matching source/version is available;
- Vue, Vite, Vue Router, Pinia, VueUse, Vitest, and Playwright;
- Tailwind CSS, Sass, CSS/SVG, and browser APIs when an appropriate source is
  available.

For `python-backend-security` and `ui-ux-review`, use Context7 only for concrete
library or browser API behavior, not as the sole source of security or UX
policy.

For `jira-data-center`, preserve the declared Jira Data Center version boundary,
runtime `/rest/api/2/serverInfo` verification, and curated Jira sources. Do not
substitute Jira Cloud or generic Jira documentation.

For Obsidian materials, Context7 does not replace the configured Semantic Notes
Vault MCP boundary, Templater policy, or project-specific wiki/taskbook workflow.

## Source precedence

Use sources in this order:

1. Project and runtime evidence determines the applicable product, dependency,
   version, and configuration.
2. Context7 is the preferred retrieval path when it resolves documentation for
   the correct project and applicable version.
3. Curated official-source references shipped with active materials remain valid
   when they are more specific or deliberately version-locked.
4. If Context7 does not provide a reliable match, use primary official
   documentation directly when network access is allowed.
5. Do not let model knowledge override verified project evidence or retrieved
   primary documentation.

Runtime state and documentation answer different questions. Do not use
Context7 to infer the actual deployed version or configuration of a database,
Jira, NATS, or another service when that state can be verified directly.

## Retrieval workflow

Before querying Context7:

1. Identify the exact library, framework, SDK, tool, or product.
2. Determine the applicable version from project evidence when version can
   affect the answer.
3. Resolve the Context7 library ID unless a previously verified, unambiguous ID
   for the same source is explicitly available.
4. Verify that the resolved result is the intended project rather than a
   namesake or unrelated package.
5. Prefer official, verified, or otherwise high-confidence source entries when
   Context7 exposes source-quality metadata.
6. Query only the topic needed for the current task.

For version-sensitive behavior, do not silently substitute `latest` when the
applicable version is unavailable. Use another primary source only when
compatibility is established; otherwise report the verification gap.

Cross-check a primary source when the Context7 result is ambiguous, unexpectedly
stale, or consequential to security, persistence, concurrency, protocol
guarantees, destructive operations, or compatibility boundaries.

## Availability and fallback

When Context7 is unavailable, rate-limited, cannot resolve the correct source, or
lacks the required version/topic:

- fall back to curated official-source references or direct official
  documentation when allowed;
- do not invent missing documentation;
- do not disable or invalidate otherwise active subject-matter rules or skills;
- report the verification gap when no reliable source establishes the fact.

If the user explicitly requires Context7 itself as the verification mechanism,
report its unavailability instead of silently replacing it with another source.

## Privacy

Do not include API keys, OAuth tokens, passwords, secrets, private source code,
personal data, or proprietary payloads in Context7 queries. Keep Context7
credentials in the configured MCP authentication boundary.

## Official Context7 references

Use the current official Context7 documentation when validating Context7 itself:

- `https://context7.com/docs/overview`;
- `https://context7.com/docs/resources/all-clients`;
- `https://context7.com/docs/tips`;
- `https://context7.com/docs/security/data-privacy`.
