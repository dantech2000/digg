# CLAUDE.md

Read [AGENTS.md](AGENTS.md). It is the single source of truth for how to build,
test, commit, and release in this repo, and it applies to Claude Code exactly as
it does to any other agent or human.

This file exists only because Claude Code looks for it by name. Everything of
substance lives in AGENTS.md — please do not copy content here, because two
copies of a convention become two *different* conventions the first time one is
updated.

The three things most often gotten wrong, as a pointer to the right sections:

- **Commit prefixes decide releases.** `feat:`/`fix:`/`perf:` cut a version and
  land in the changelog; `refactor:`/`test:`/`ci:`/`chore:`/`docs:` do not.
  Choose by user-visible effect, not by effort. See *Commit / release policy*.
- **`cargo test` passing is not enough.** CI also enforces
  `clippy --all-targets -- -D warnings`, `fmt --check`, two flag-drift scripts,
  and a coverage floor. Plain `cargo test` passes while `-D warnings` fails.
  See *Run what CI runs, before pushing*.
- **No AI co-authoring trailers** on commits, PRs, or release notes.
