---
name: backlog
description: Run a backlog-grooming session for this project — talk through ideas with the user, then turn the ones they accept into well-structured GitHub issues (agile user-story format, verified file references, acceptance criteria, correct labels) and/or wiki updates. Use when the user says "/backlog", asks to do a backlog meeting/session, or wants to turn a list of ideas into tracked work.
---

# Backlog grooming session

This walks through the same process used to build out digg's initial
backlog: discuss ideas conversationally, let the user accept/reject/refine
each one, then convert accepted ideas into properly-written GitHub issues
(and occasionally wiki pages) — not a one-shot dump of issues from a vague
prompt.

## 1. Figure out the repo

Don't hardcode a repo slug. Derive it:

```sh
gh repo view --json nameWithOwner -q .nameWithOwner
```

Use this for every `gh issue create` / `gh label` / wiki clone below.

## 2. Gather the list of ideas

If the user already gave you a list, work from that. Otherwise ask what
they want to cover — bugs noticed, feature ideas, tech debt, docs gaps,
tooling/CI wants. It's fine for this to be a short back-and-forth rather
than one big prompt.

For each idea:
- If it's underspecified or you can see a real tradeoff (e.g. "should
  this be a wiki page or a GitHub Pages site", "should this be one issue
  or three"), say so in 2-3 sentences with a recommendation, and let the
  user redirect — don't just pick silently and don't over-explain either.
- If an idea overlaps with or blocks/depends on an already-filed issue,
  say so and cross-reference it (`#N`) rather than filing a duplicate.

Only write issues for ideas the user has actually confirmed — this is a
grooming session, not a brainstorm-to-issue pipeline.

## 3. Before writing an issue: verify, don't guess

Every issue should read like it was written by someone who actually
opened the files. Before citing a file, function name, or line number:

- `grep`/`Read` the actual code to confirm the reference is real and the
  line number is current. Stale line numbers from memory are worse than
  no line number.
- If you're describing current behavior ("there is no test suite",
  "there is no CHANGELOG"), confirm it (`cargo test`, `ls CHANGELOG*`,
  etc.) rather than assuming.
- Check for related/duplicate open issues first: `gh issue list --repo
  <slug> --state all`.

## 4. Issue format

Write issues as agile user stories, with concrete grounding — this is the
template that's worked well for this project:

```md
## User story
As a developer/user, I should be able to <do X>, so that <why>.

## Problem
What's true today, with file:line references to back it up. Quote the
relevant code if it clarifies the problem.

## Expected use case
A short example of the feature/fix in use (a shell snippet, a code
sketch, a before/after) — not just prose.

## Acceptance criteria
Bullet list of what "done" looks like. Concrete and checkable, not vague
("works well", "is fast").

## Scope (optional)
Files/areas touched, and anything explicitly out of scope.
```

Cross-reference related issues inline (`See #7`, `Depends on #5`) instead
of repeating context.

## 5. Labels

Check existing labels first — reuse them, don't create near-duplicates:

```sh
gh label list --repo <slug>
```

This repo's convention (adjust for other repos): GitHub's defaults
(`bug`, `enhancement`, `documentation`, `question`, ...) plus two added
during backlog sessions — `ci` (build/release tooling, GitHub Actions)
and `chore` (maintenance / dev-experience work with no user-facing
behavior change). Only create a new label if nothing existing genuinely
fits; if you do, add it with `gh label create` before tagging issues with
it, and mention to the user that you added a new label and why.

## 6. Creating the issues

```sh
gh issue create --repo <slug> --title "<type>: <short imperative title>" \
  --label <label> --body "$(cat <<'EOF'
...
EOF
)"
```

Title prefix should match conventional-commit style (`fix:`, `feat:`,
`chore:`, `docs:`, `refactor:`, `test:`, `ci:`) since that's what the
eventual commit/PR title will reuse in this project.

Do not add an AI co-authoring trailer to issues, commits, or PRs in this
repo (see AGENTS.md) — this applies to issue bodies too.

## 7. Wiki updates, if the session calls for one

If an idea is a docs page rather than a code change:

- Draft the content locally first as a normal markdown file, and let the
  user review before pushing — wiki edits are directly live, there's no
  PR/review step.
- **Bootstrap gotcha**: `<repo>.wiki.git` does not exist as a clonable
  remote until a page has been created at least once through the GitHub
  web UI (Wiki tab → "Create the first page"). There is no API to do this
  programmatically. If `git clone git@github.com:<slug>.wiki.git` fails
  with "Repository not found" and this is a brand-new wiki, tell the user
  to create one placeholder page via the web UI, then retry the clone —
  don't loop on it yourself.
- Once cloned, add/edit `.md` files, commit, and push directly to
  `master` (or whatever branch `git clone` checked out) — wikis aren't
  branch-protected by default.

## 8. Wrap-up

End with a short table: issue number, title, label, for everything filed
this session. Ask if anything needs re-prioritizing, splitting, or
merging before moving on — don't assume the session is over just because
you've filed everything discussed.
