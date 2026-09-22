- **`flair-client`: signing operations now refuse to run without an explicit agent identity.**

  `memory write`, `soul set`, and `memory delete` resolve their identity from
  `FLAIR_AGENT_ID` or the new `--agent <id>` flag and exit non-zero naming both
  when neither is set, instead of silently signing as the shipped `flint`
  default. Read-only actions (`list`, `get`, `search`) keep the default. The
  old behaviour let a caller that forgot one environment variable author
  records as `flint`, with ownership-scoped operations then binding to an
  identity nobody chose.

  > **Heads-up:** scripted writes that relied on the default identity now fail
  > closed — set `FLAIR_AGENT_ID` or pass `--agent <id>` at those call sites.

  (Refs #1816)
