- **`flair federation pair` names a local `/FederationInstance` 403 instead of dumping raw AccessViolation.**

  Pair's first step is a signed GET of the local instance identity
  (`allowAdmin`). A 403 now throws `FederationPairLocalAccessError` naming
  the LOCAL side, the missing admin role/grant, `FLAIR_ADMIN_AGENTS` /
  `flair principal promote`, and the hub pairing-role restore
  (`flair init --remote` → `flair_pair_initiator`). A hub POST 403 gets
  the same named treatment. Refs #820.

  > **Heads-up:** a 403 on pair is usually the local identity read, not the
  > hub. Check `FLAIR_ADMIN_AGENTS` in the *server* process env, or grant
  > the admin role, before chasing hub tokens.
