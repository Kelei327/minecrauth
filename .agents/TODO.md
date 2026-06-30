# TODO - minecrauth

Only open work is tracked here. Everything shipped (MVP, Phase 2 textures/interop, Phase 3 OIDC + Web UI, Phase 4 Docker/pipelines/docs, plus the tooling + observability round) has been removed from this list. For the full scope and the historical plan see OBJECTIVES.md; for the rationale of closed decisions see DECISIONS.md.

## In Progress
- [ ] Nothing in progress.

## Open - prioritised

### Protocol validation (biggest open risk)
- [ ] Verify the SERVER side of the Yggdrasil handshake (`join` / `hasJoined`) against a real vanilla Minecraft server running authlib-injector. The CLIENT side is now confirmed live: a real launcher (Freesm/Fjord) authenticates, the multi-player profile selection works, and the signed texture profile is verified by the launcher (skin renders). What is still untested end to end is a game client actually joining a server through minecrauth. Needs a human with a vanilla server + the authlib-injector javaagent.

### Account features (committed scope still open + nice-to-haves)
- [ ] Import existing player / register-from-existing-player (+ skin-based ownership verification). There is no `ImportPlayer` code yet. Lets an operator migrate a Mojang account keeping its UUID/name.

## Possible future scope (from OBJECTIVES, never committed)
Not promised to the owner; listed so they are not forgotten. Confirm before building.
- [ ] Automatic DB backup before running schema migrations.
- [ ] Configurable CORS.

## Closed, do not reopen without a decision change
- authlib-injector spec coverage is complete: uploadableTextures, dynamic metadata + meta.links, ALI header, in-game texture upload, and player certificates for 1.19+ signed chat are all shipped. See DECISIONS.md.
- Login by profile name (`feature.non_email_login`) is deliberately out of scope (collision risk against the email-is-the-login model; not needed to play). See DECISIONS.md.
- The Mojang host mirror integration path is out of scope. See DECISIONS.md.
