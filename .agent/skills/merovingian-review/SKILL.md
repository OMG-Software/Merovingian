---
name: merovingian-review
description: "Review a Merovingian pull request, branch or local diff against this project's binding rules: docs/coding-rules.md, the security coding rules, the per-module AGENTS.md invariants, the Matrix v1.19 spec, and the change obligations (CHANGELOG, docs, ADR, version bump, PR headings). It targets the defect classes this project has actually shipped. Use when asked to review a PR, branch, diff or commit in this repository, to check a change before merge, to verify a subagent's or another session's work, or to post review comments on a Merovingian PR."
---

# Merovingian review

Review the change against what it claims, against the code around it, and against the rules this project has
written down. Most of those rules exist because a defect shipped without them. A finding is reportable only when
you can name the inputs or state that produce the wrong outcome.

This skill is a checklist and a method. **It does not hold the rules.** The binding text is in
[docs/coding-rules.md](../../../docs/coding-rules.md),
[docs/security-coding-rules.md](../../../docs/security-coding-rules.md), the directory `AGENTS.md` files and the
spec under `docs/matrix-v1.19-spec/`. The reference files below point into those documents. If a reference here
disagrees with the document it cites, the document wins, and the disagreement goes in the report as a finding
against this skill.

| Reference | Use it for |
|---|---|
| [references/module-invariants.md](references/module-invariants.md) | What a diff in each `src/` module, `migrations/`, `packaging/` or `scripts/` must not break |
| [references/rule-checks.md](references/rule-checks.md) | Grep-able rule checks and judgement checks from the coding and security rules |
| [references/recurring-defects.md](references/recurring-defects.md) | Defect classes this project has shipped and fixed, as questions to ask of a diff |
| [references/tests.md](references/tests.md) | Where a test belongs, required structure, what the gates catch and miss, how to run and read tests |
| [references/obligations.md](references/obligations.md) | CHANGELOG, docs, ADR, version bump, PR description: rules and commands |

## Modes

- **Review** (default): read and report. Edit nothing, push nothing, post nothing.
- **Fix**: only when asked ("review and fix", "apply them"). Report first. Then make the change each finding
  needs, following `docs/coding-rules.md`. That means the correct change, not the smallest. Re-run the tests you
  cited and report the real counts.
- **Post**: only when asked to post. Finish Review first, then follow [Posting](#posting). Nothing is posted
  until the user has seen it and chosen it.

## Step 1: Pin the target

| Target | Commands |
|---|---|
| PR | `gh pr view <n> --json title,body,baseRefName,headRefName,headRefOid,commits,files` then `gh pr diff <n>` |
| Branch | `git fetch origin` then `git diff --stat origin/main...HEAD` |
| Local work | `git diff` and `git diff --staged` |
| Another session's or subagent's work | Its branch or worktree, as a branch. Its report is a claim to test, not a summary to trust |

Record the base and head SHAs. GitHub rewrites PR head commits after a squash or rebase, so take the SHA from the
PR, not from a local branch with the same name. A stacked PR is reviewed against its base PR's head, not
`main`. Say so in the report, and check that its merge order is stated.

Read the PR description, linked issue and the commit messages before the code. Write down each claim the change
makes ("fixes X", "adds a cap", "tests pass on all platforms"). Every claim is either supported by the diff and
the evidence, or listed in the report as unsupported.

## Step 2: Map the diff to the rules that govern it

1. List the changed files: `git diff --name-only <base>...<head>`.
2. For each top-level area the diff touches, read that directory's `AGENTS.md`: `src/<module>/AGENTS.md`,
   `include/merovingian/AGENTS.md`, `src/AGENTS.md`, `migrations/AGENTS.md`, `tests/<kind>/AGENTS.md`,
   `packaging/AGENTS.md`, `scripts/AGENTS.md`, `docs/AGENTS.md`. Then take that module's section from
   [module-invariants.md](references/module-invariants.md). The AGENTS file is binding. The section here is the
   shortlist of what has gone wrong before.
3. Read the sections of `docs/coding-rules.md` and `docs/security-coding-rules.md` that
   [rule-checks.md](references/rule-checks.md) names for the kinds of code in the diff.
4. For every Matrix-visible behaviour the change touches (endpoint, status code, errcode, event field, auth rule,
   federation exchange), find the spec section in `docs/matrix-v1.19-spec/` **before** judging the code. Read the
   passage for each actor involved: client, server, remote server, appservice. Something is an owner decision
   only when the spec is silent or genuinely ambiguous, and you have read the conflicting passages.
5. Find the ADRs the change touches or contradicts. Search `docs/adr/index.md` for the subsystem's terms. A diff
   that undoes an ADR's decision without superseding that ADR is a finding.

## Step 3: Understand before critiquing

- Read every hunk in its file, not on its own. Read the callers of every changed signature or semantic.
- Note which process each changed line runs in. The **main process** holds the signing key, the database, the
  appservice registrations and email. The **federation worker** has none of these and is the most exposed process.
  The **thumbnail worker** decodes untrusted images under a sandbox. Code that moves from one to another changes
  its trust.
- Note which locks each changed line runs under: `runtime.mutex` via `RuntimeLock`, the federation state mutex
  (not recursive), the store mutexes, the leaf mutexes in the parker and registries. A network call, SMTP send,
  Argon2id hash or IPC round trip under one of these is the most common serious defect in this project's history.
- Flag scope creep: unrelated refactors, whole-file reformatting, a fix bundled with a feature. Reformatting churn
  hides the real change and has been introduced by delegated work before.
- A new function, type, config key or handler must be **wired**: reachable from a real call path, registered
  where the dispatch tables are built, and present in both processes where it must be. Declared-but-unwired code
  has been reported as "done" before. Find the call site.

## Step 4: Discover, with an evidence log

Find first. Rank later (Step 7). A finding judged minor while you are still looking is one you stop
investigating.

Every dimension gets a row, whether or not it produced anything. A dimension with no row is unexamined, not
clean. A row whose Method is "looked at it" is the same thing.

| ID | Dimension | Examined | Method | Result |
|---|---|---|---|---|
| C1 | Correctness | `src/sync/SlidingSync.cpp:210-340` | every branch; partial failure; empty and max-size input | D1 |
| S1 | Security / trust boundary | `src/homeserver/WorkerPool.cpp:88-140` | relay path re-verifies signature before `runtime.mutex`? | clean |
| L1 | Locks and concurrency | same | every call under `RuntimeLock`; any I/O inside? | D2 |
| B1 | Bounds and cost | request arrays, regex, scans | who controls the size; cap and errcode; cost under lock | clean |
| SP1 | Spec | `client-server-api.md#...` | status, errcode and fields against the cited section | D3 |
| R1 | Rules | changed `.cpp`/`.hpp` | rule-checks greps; judgement checks | clean |
| T1 | Tests | new scenarios | fails if fix reverted? placement; tags; gates | gap, D4 |
| O1 | Obligations | CHANGELOG, docs, ADR, version, PR text | obligations.md commands | D5 |
| H1 | Recurring defects | whole diff | each class in recurring-defects.md that applies | clean |

Work through:

- **Correctness**: every branch and early return; state after step N of M fails; empty, one, maximum, zero,
  negative; byte versus character length; percent-encoded versus decoded identifiers; time from the right clock.
- **Trust boundaries**: each input crossing one. That includes client bodies, headers and query strings, federation
  PDUs, EDUs and queries, worker IPC frames, appservice and identity-server responses, config files, and database
  rows written from any of these. Authorisation is checked at the operation, not only at the route. Defaults fail
  closed.
- **Locks and concurrency**: the lock-scope questions above, plus check-then-act across a `RuntimeLockRelease`.
  After re-locking, is everything the code relies on re-validated? Are pointers kept across the release? Check lock
  order, and `std::terminate` from an exception escaping a pool task.
- **Bounds and algorithmic cost**: anything a client or remote can grow must be capped and refused at the cap,
  never evicted, and never scanned in full under the runtime lock. Regex, glob and substring matching on
  caller-chosen input. Comparators that rescan. Per-row work multiplied by per-member work.
- **Spec**: status codes and errcodes as the spec states them, field names and presence. Every event in a sync
  or sliding-sync response carries `event_id`, and so on.
- **Rules**: run the greps in [rule-checks.md](references/rule-checks.md) over the changed lines, then the
  judgement checks. Do not re-report what `scripts/reject-unsafe.sh` and the meson gate tests already fail on,
  unless the diff shows the gate was bypassed or edited. The list is in rule-checks.md.
- **Reuse**: every new helper claims nothing equivalent exists. Search `src/core/`, the module's own files and
  the standard library by name and by concept before accepting it. This project has single-source helpers that
  must not be re-derived: `EventId.hpp`, `RoomVersionPolicy`, `HistoryVisibility`, `room_read_access_for`,
  `parse_size_limit`, `QueryParams`, `request_header`, `FoldedSubstringMatcher`, `merge_visible_key_signatures`,
  `OutboundClient`. A helper used by a second file moves to its own file. It is never copied.
- **Tests**: see [tests.md](references/tests.md) and Step 5.
- **Obligations**: see [obligations.md](references/obligations.md).
- **Recurring defects**: go through [recurring-defects.md](references/recurring-defects.md) and ask each
  applicable question of the diff.

### Delegating discovery

The root `AGENTS.md` asks the orchestrator to delegate reading and keep judgement. For a diff larger than a few
hundred lines:

- Give each lower-tier reviewer one area: a module, or the tests, or the obligations. Its brief holds the base and
  head SHAs, the files, the matching section of `module-invariants.md` or `rule-checks.md`, and the instruction
  to read `docs/coding-rules.md` and the directory `AGENTS.md`. It returns discoveries with `file:line`, trigger
  and outcome. It assigns no severity.
- Keep these for yourself: spec interpretation, security and trust-boundary verdicts, lock and concurrency
  correctness, migration numbering, severity, and whether the change is done.
- **Verify every delegated discovery against the code before it becomes a finding.** Delegates invent APIs,
  misread lock scopes, and write confident rationales for wrong conclusions. A discovery you have not confirmed
  at its `file:line` is not reported.

## Step 5: Tests: map behaviour to assertions

For each new or changed behaviour (a status code, an errcode, a cap, a validation, a changed default, a new
relay), name the scenario that asserts it:

| Behaviour | Scenario (`file:line`, tag) | Assertion | Fails if reverted? |
|---|---|---|---|
| Oversized `rooms` array, 400 `M_INVALID_PARAM` | `tests/integration/test_sliding_sync_flow.cpp:512` `[sliding-sync]` | status and errcode | yes, checked |
| Worker relay with a bad signature is refused | none | — | gap |

- "Fails if reverted" is a check, not a guess. Apply the test change alone to a worktree at the base commit,
  build, and run the binary with the tag filter. Otherwise write "not checked". A regression test that passes
  without the fix proves nothing. This project has shipped such tests.
- A changed behaviour must update the test that pinned the old behaviour. An unchanged test asserting the old
  behaviour means one of the two is wrong. Earlier tests have pinned leaks as correct behaviour.
- In conformance tests, a weakened, removed or commented-out `REQUIRE`, or an expected value changed without
  citing the spec, is a Blocker.
- Placement, structure, tags and the pitfalls (Catch2 assertions off the main thread, live threads next to a
  failing `REQUIRE` or `SKIP`, untagged PostgreSQL scenarios, minimum-cost Argon2 in a race test) are in
  [tests.md](references/tests.md).

## Step 6: Audit coverage independently

"I reviewed every file" is self-certifying. Enumerate the hunks:

```bash
git diff --unified=0 <base>...<head> | grep '^@@'
git diff --stat <base>...<head>
```

For a diff of more than about ten files, hand the enumeration to a fresh agent that has **not** seen your
findings. It lists every hunk with `file:line` and the dimension it belongs to, and returns every hunk and file
that has no evidence-log row. It does not hunt for bugs. Every uncovered hunk is either examined now or listed
under Verification as not reviewed.

## Step 7: Severity, as a separate pass

| Tag | Meaning in this project | Blocks merge |
|---|---|---|
| **[Blocker]** | Wrong result, auth or signature bypass, a worker-trust violation, data loss, a crash, a deadlock or timeout, an unbounded cost reachable by an unprivileged client or remote, a weakened conformance assertion, a broken build or test | Yes |
| **[Major]** | Real defect on a plausible path; incomplete fix; behaviour without a test that fails if reverted; missing CHANGELOG, docs, ADR or version bump the project rules require | Yes, unless the author shows it is wrong |
| **[Minor]** | Correct but fragile, unclear or wasteful; a missing negative-path test on non-security code; doc drift | No |
| **[Nit]** | Wording, naming, or style no tool owns | Never; collapse them |

Calibration from this project's history:

- **Availability is security here.** Every high finding in the 1.0.0 release-candidate audit was availability:
  lock-held cost, uncapped growth, scans. Do not rank a client-reachable lock-held network call or an unbounded
  scan under `runtime.mutex` below Blocker because "it's only DoS".
- Anything that lets the federation worker cause main to act without main's own verification is a Blocker.
- A finding whose outcome is security, authorisation or data loss and that ranks below Major is re-examined.
- Every severity has a one-sentence justification naming impact and likelihood. A severity without one is a guess.
- Never raise a nit to look thorough. Never soften a blocker to be agreeable.

Do not report:

- Formatting or include order that `scripts/format_code.py` or `tests/tooling/test_include_order.py` would settle.
  You may note in one line that the format tool was not run on the changed files.
- A code reshape to satisfy a metric tool, such as dropping digit separators for CodeQL. That is a false
  positive to dismiss, not a change to request.
- Design you merely disagree with, where an ADR records the decision and its rejected alternatives. Review the
  implementation of the decision. Raise the design only when it causes a concrete defect.

## Step 8: Verify

Claims about tests are worth only what they were checked against. The rules come from the root `AGENTS.md`
"Verifying Work" section. Read that section. The short form:

- The build and test command is the one the root `AGENTS.md` names: `python build.py vm` at the time of writing
  (ADR-0752). It runs past ten minutes, so run it in the background and wait for it to finish. A run in progress
  is not a result. The VM runs one suite at a time, and a second run from any worktree waits for its lock. The
  VM builds the tree of the worktree you run it from, so run it from the worktree under review.
- `build.py`'s exit code is not evidence. Read the `Ok:`, `Fail:` and `Timeout:` counts at the end of
  `build-vm/meson-logs/testlog.txt` (`build-vm-<name>/` for `--vm <name>`). `build.py vm` deletes the old copy
  first, so a missing file is no result, never a pass; its output says whether the run never reached the tests
  or the log could not be copied back. **A timeout is a failure.**
- `testlog.txt` holds output only for failing tests, so it cannot prove a passing scenario ran. Run the binary
  with a tag filter: `python build.py vm --exec ./build-vm/tests/merovingian-unit-tests "[push]"` (`--exec` sets
  the hardening opt-out). Catch2 registers `SCENARIO("x")` as `Scenario: x`, so filter by tag, not by name.
  Confirm the reported test count is not zero. A zero-byte or missing binary "passes" silently.
- A sanitizer or fuzz run that aborted at startup is not clean.
- CI green on the PR is evidence only for the head SHA it ran on, and only for the jobs that ran. Name them.

If you cannot run something, say what and why: no PostgreSQL, no BSD host, the suite too long for the session.
Never round a partial check up.

## Step 9: Report

```markdown
## Summary
Verdict: approve | approve with comments | request changes
Reviewed <base sha> → <head sha>.
One or two sentences: what the change does, and whether the diff supports what it claims.

## Blockers
- **[Blocker]** `path:line` — defect. Trigger: … Outcome: … Fix: … Rule/spec: `doc#heading` or ADR-NNNN.

## Major
## Minor and nits

## Claims checked
| Claim (from PR/commit) | Supported? | Evidence |

## Behaviour → test
| Behaviour | Scenario | Fails if reverted? |

## Obligations
| Item | State | Evidence |
| CHANGELOG bullet in current version, right section | | |
| Docs per docs/AGENTS.md table | | |
| ADR (needed? numbered above all branches? index line?) | | |
| Version bump (or docs-only exemption) and all places agree | | |
| PR description headings | | |

## Evidence log
| ID | Dimension | Examined | Method | Result |

## Verification
- Commands, verbatim, and the counts read from the log.
- Not verified, and why.

## Questions
```

Order findings by severity, then file order. Each cites the rule, spec section or ADR it rests on, so the author
can check it. Report only findings you confirmed at `file:line`. Report unverified suspicions as questions,
labelled as such.

When this review is part of finishing your own change (`AGENTS.md`: "check the change against those rules and
report any unresolved conflict or unmet requirement"), the Obligations table and unresolved findings go in your
completion report.

## Posting

Posting is outward-facing and hard to retract.

1. Give every drafted comment an ID: `B1`, `M1`, `m1`, `N1`, `Q1`.
2. Show every draft in full: ID, tag, anchor, exact text.
3. Ask which to post. Suggest blockers and majors as the default, but do not pre-apply it. Post only the IDs the
   user names, and read the selection back before posting.
4. Each comment is one finding. The severity tag comes first, then the defect in one sentence with its trigger
   and outcome, then the fix. Cite the rule or spec section. Questions carry `**[Question]**` and no severity.
5. Anchor to a changed line. GitHub rejects the whole review (HTTP 422) if any anchor is outside the diff.
   Missing-code findings anchor to the nearest changed line and say what is missing.
6. Post with `gh api repos/{owner}/{repo}/pulls/<n>/reviews --input review.json`. Set `commit_id` to the PR head
   SHA. Use `event` `REQUEST_CHANGES` only if a selected comment is a Blocker; otherwise use `COMMENT`. Check that
   the returned comment count matches the selection.
7. Do not mention withheld findings or their counts in the review body.

Write a bare `@name` only for a real GitHub login you mean to notify. Put `@`-prefixed code in backticks.

## Anti-patterns

- Reviewing the diff without its file, its callers or its process and lock context.
- Trusting a report, a green check or an exit code instead of reading the log and running the filtered binary.
- Accepting a test without checking it fails when the fix is reverted.
- Calling something an owner decision before reading the spec passages for every actor.
- Reporting what a gate already fails on, or asking for a reshape to satisfy a metric.
- Ranking an availability defect low because it "only" denies service.
- Copying rule text into findings instead of citing `doc#heading`, so the finding drifts with the doc.
- Posting anything the user did not select.
