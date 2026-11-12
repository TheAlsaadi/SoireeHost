# Third-party skills: vetting record

Plan section 8 lists three third-party skill sets. Each was downloaded and read before installation, as section 8 "Vetting third-party skills" requires. Only the skills named in the plan are to be installed, at project scope. A skill's instructions never override plan section 1 or section 5.

**Reviewed:** 12 Nov 2026, by Claude Code, from shallow clones of each repository's default branch.

## Commits reviewed

| Marketplace / repository | Commit | Commit date |
| --- | --- | --- |
| `trailofbits/skills` | `e4dd0bb5b15535f7c5a0834187dffba6ac37e4ff` | 2026-11-06 |
| `samber/cc` (marketplace index only) | `798628ffea78a712f0bd51a372fa58baaa201c06` | 2026-09-13 |
| `samber/cc-skills-golang` (plugin v2.0.1) | `d68d80aec298e1b74b37c2a472c002b5217248b3` | 2026-11-08 |
| `spf13/go-skills` | `c6ea8841a542d3a6f953e8b9b0ad596229163c1c` | 2026-11-05 |

If the commit installed differs from the one above, re-review the diff before using it.

## Findings

### Trail of Bits (`trailofbits/skills`, CC BY-SA 4.0)

| Plugin | Contents | Hooks / MCP | Network | Verdict |
| --- | --- | --- | --- | --- |
| `insecure-defaults` | Markdown, JSON pattern lists, a JS workflow that spawns review agents | None | None | Approved |
| `sharp-edges` | Markdown only | None | None | Approved |
| `supply-chain-risk-auditor` | Markdown + Python scripts | None | **Yes**: `api.deps.dev`, `api.github.com`, `api.osv.dev`, `api.scorecard.dev`, `proxy.golang.org`, `registry.npmjs.org`, `pypi.org`, `api.npmjs.org`. Sends public package names only. Reads `gh auth token` if the GitHub CLI is installed and signed in | Approved by the owner on 12 Nov 2026, with this network use disclosed |
| `static-analysis` | Markdown + shell/Python wrappers for Semgrep and CodeQL | None | Semgrep fetches public rule packs from the Semgrep registry; the wrapper passes `--metrics=off`. Needs Semgrep and CodeQL installed locally | Approved for use; locally optional because CodeQL and Semgrep also run in CI |
| `semgrep-rule-creator` | Markdown only | None | None (needs Semgrep to test rules) | Approved |
| `differential-review` | Markdown only | None | None | Approved |
| `audit-context-building` | Markdown + JS workflow | None | None | Approved |
| `fp-check` | Markdown | **Yes**: prompt-type `Stop` and `SubagentStop` hooks with matcher `*`. They run an extra model check every time Claude stops in this project, answering "ok" when the conversation is not an fp-check run. No commands executed | Approved, with the cost noted: a small extra model call at the end of every turn. Disable the plugin between uses if that matters |
| `spec-to-code-compliance` | Markdown + JS workflow | None | None | Approved |
| `variant-analysis` | Markdown + JS workflow; test scripts not used at runtime | None | Test fixtures only | Approved |
| `testing-handbook-skills` | Markdown + a local validation script | None | Some guides show download commands for other languages' fuzzers; not relevant to Go | Approved; use the Go fuzzing guidance only |

Other plugins in the same marketplace (for example `gh-cli`, `modern-python`, which install command shims through hooks, and `zeroize-audit`, which adds an MCP server) are **not** to be installed.

### samber (`samber/cc` marketplace, `cc-skills-golang`, MIT)

All ten named skills are present and are Markdown only. No hooks, no MCP servers, no scripts run by the skills. Some skills suggest `go install ...@latest`; in this project, tools are pinned instead (CLAUDE.md, plan S-70). The marketplace also lists other plugins (`cc-caffeine`, `cc-skills`); do **not** install them. Verdict: approved.

### spf13 (`spf13/go-skills`, MIT)

`wails` and `go-release` are a single `SKILL.md` each. No hooks, MCP servers or scripts. The `wails` skill still calls v3 "alpha" and recommends nightly tags; Wails v3.1.0 is stable, so where the skill and the current Wails docs disagree, the docs win (plan section 8). Verdict: approved.

## Installation

The approved plugins are declared at project scope in `.claude/settings.json` (`extraKnownMarketplaces` and `enabledPlugins`). Claude Code reads that file when a session starts in this folder and offers to install the marketplaces and plugins listed there; accept the prompts. Nothing outside that list is enabled. The marketplaces follow their default branches; Claude Code settings cannot pin a marketplace to a commit, so re-check the commits above against what gets installed.

In the Claude desktop app, `/plugin` opens the Settings > Customize > Plugins screen rather than the terminal command. The equivalent terminal commands, for the `claude` CLI, are:

```
/plugin marketplace add trailofbits/skills
/plugin marketplace add samber/cc
/plugin marketplace add spf13/go-skills
```

and then `/plugin install <name>@<marketplace>`, choosing project scope, for only:

- From `trailofbits/skills`: `insecure-defaults`, `sharp-edges`, `static-analysis`, `semgrep-rule-creator`, `differential-review`, `audit-context-building`, `fp-check`, `spec-to-code-compliance`, `variant-analysis`, `testing-handbook-skills`, `supply-chain-risk-auditor`.
- `cc-skills-golang@samber`
- `wails@go-skills` and `go-release@go-skills`

`frontend-design` is not loaded in this environment; install it before Phase 5 with `/plugin install frontend-design@claude-plugins-official`, after the same review.

## Installation status (checked 12 Nov 2026, after Phase 2)

- The three marketplaces are added, at exactly the commits reviewed above: `trailofbits/skills` `e4dd0bb5…`, `samber/cc` `798628ff…`, `spf13/go-skills` `c6ea8841…`.
- **No plugin from them is installed yet.** `.claude/settings.json` lists them as enabled, but an enabled plugin that was never installed does nothing, so none of their skills load.
- Installing them now fetches exactly the reviewed code: the Trail of Bits and spf13 plugins come from inside their marketplace repositories, which are at the reviewed commits, and `samber/cc-skills-golang` (fetched from its own repository) is still at the reviewed commit `d68d80ae…`. No new review is needed unless a commit changes before installation.

## Project skill

`.claude/skills/soireehost-conventions/` is SoiréeHost's own skill, written after Phase 2 as plan section 8 ("Gaps") asks, with `skill-creator`. It records the Windows and Go conventions and pitfalls found in Phases 1 and 2 (security descriptors, named pipes, running a service alongside Caddy, append-only files, the CI isolation job, lint suppressions) and the way a phase is run and recorded. It is plain Markdown with no scripts or hooks, and loads in any session started in this folder. Update it whenever a later phase finds a new trap.
