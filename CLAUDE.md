# mod_dims

An Apache httpd module that resizes, crops, and reformats images on request.

## Commit messages

Write one short line in the imperative mood. State the change and nothing else.

- No history. Do not describe the previous behavior.
- No attribution. No sign-off, co-author, or tool reference.
- No commentary. No reasoning and no apology.
- Add a body only when a commit carries several changes. Use plain statements, one per
  line.

```
Close every MagickWand before returning
```

```
Validate query parameters

- Compare the full parameter name, not four bytes.
- Check the remaining length before indexing into a token.
```

## Pull requests

A pull request describes the change. It does not address a reader.

- Never write "you", "we", "I", "our", "let's", "please", or "thanks".
- No greeting, no closing, no apology, no commentary about the work.
- No emoji. No attribution, sign-off, or tool reference.
- The title follows the commit message rules: one short line, imperative mood.
- Do not wrap lines. Write each paragraph as one line and let the renderer wrap
  it. Hard wrapping reflows badly in a browser and makes an edit rewrite the
  whole paragraph. Code blocks keep their own line breaks.

Use this body structure. Drop a heading that has nothing under it.

```
## What

One or two sentences. What the code does now.

## Why

The defect or the requirement. Link finding IDs and issue numbers.

## Verify

The exact command a reviewer runs, and what a pass looks like.

## Breaking

What a caller must change. Omit when nothing breaks.
```

Keep the whole body under 300 words. A long body means the pull request is too large.

## Prose

For the README, `docs/`, comments, error messages, and pull request bodies.

- US English. US spelling: license, behavior, color, catalog, analyze.
- Plain language grammar. Short, complete sentences.
- One idea per sentence. 20 words for instructions, 25 for descriptions.
- Active voice, present tense.
- One word, one meaning. No synonym for a term already used.
- No metaphor, idiom, or slang.
- Finite verbs, not gerund or participle phrases.
- Keep the articles. Three words maximum in a noun cluster.
- Positive statements. Instructions as commands.
- Six sentences per paragraph. Lists for sequences and sets.
- Keep technical names and technical verbs unchanged.

## Branches

Work targets `main`. `master` is version 3.3.31 and takes hotfixes only.

Every pull request bases on `main`. Do not stack one pull request on another.

A stacked pull request points at a branch, and merging its parent into `main`
does not carry it along: the parent branch is already absorbed, so merging the
child into it changes nothing that ships. GitHub only retargets a child when
the parent branch is deleted. Waiting for `main` to move and branching again
costs a few minutes and cannot go wrong.

Never commit to `master` as part of this work. When a hotfix lands on `master`,
merge `master` into `main`. Do not cherry-pick: a cherry-pick leaves the merge
base behind and every open branch then rebases onto a moving target.

Write `main` into every workflow trigger, badge, and documentation link.

## Compatibility

`/dims3/` and `/dims4/` are frozen. A change that alters which URLs they accept, which
status codes they return, or which bytes they emit is not allowed.

New behavior goes on `/dims5/`, or behind a directive whose default reproduces today's
behavior. A pull request that adds a directive states its default and its `/dims5/`
default.

`/dims5/` matches the go-dims `/v5/` specification in
`../go-dims/docs/docs/endpoints/dims5.md`. Do not invent a variation. A signature is
portable between the two, and a test asserts it.

## Dependencies

The module links httpd, APR, libcurl, OpenSSL, and ImageMagick. The test harness links
the same set. Do not add another runtime, another language, or another package manager.
The build is CMake. The tests are C. There is no Python in this repository.

## Documentation

A pull request that adds or renames a configuration directive updates the matching page
in `docs/docs/configuration/`. The name must match the code exactly.

## Tests

The test cases are ported from go-dims (`https://github.com/beetlebugorg/go-dims`), which
is MIT licensed. Keep the copyright header on every ported file. `NOTICE` records the
credit; it does not replace the header.

Add a new case to the matching go-dims test file first where the behavior applies to both
projects, so the two suites stay in step.

## Working notes

`specs/` holds the code review and the remediation plan. It is ignored by git.

Never reference it from code, comments, commit messages, or pull requests. A
reader who clones the repository does not have it, so the reference is a dead
end. Describe the defect instead of pointing at a document that is not there.

