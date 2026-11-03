# Push glob matching spends a bounded budget per recipient and event

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2, F-39 (`sp01.push-glob-body-times-pattern-times-rules-unmetered`)

## Context and Problem Statement

ADR-0175 made the `content.body` glob matcher a single pass, O(body x pattern) for each rule, and ADR-0204 accepted that
cost as "linear in the event, with a factor the server chooses". Neither bounded the product. The sender chooses
`content.body` (up to the 65,536-byte event limit), the recipient chooses up to `max_push_rules_per_user` (200) rules of
up to 512 bytes, and every enabled content rule is tried against the body until one matches. Each local recipient of
each stored event is evaluated under `runtime.mutex`, so one 64 KiB message could cost about 1.3e10 steps for a
recipient who installed 200 non-matching 512-byte patterns, and the same again for each such recipient in the room.
`PushRuleUnreadClassifier` repeats the evaluation on `/sync` and sliding sync. How is the cost of one evaluation bounded
without changing what a normal rule set matches?

## Decision Drivers

* Work under `runtime.mutex` must not grow with the product of two principals' input sizes.
* The spec states no bound on `content.body` matching, so any bound is the server's and must be written down.
* A typical body and the spec's default rules must match exactly as before.

## Considered Options

* A step budget for each (recipient, event) evaluation, shared by every rule, plus a cap on the body prefix searched
* A cap on the body length alone
* A lower `max_push_rule_pattern_bytes` or a separate cap on content rules

## Decision Outcome

Chosen option: "a shared step budget and a body prefix cap", because it bounds the product directly, wherever the
cost comes from.

* `evaluate_push_rules` gives each call one `GlobBudget` of `max_push_glob_steps_per_evaluation` (2^21) steps. Every
  `content.body` match draws from it: content rules, `event_match` conditions on `content.body`, and
  `contains_display_name` (charged at its worst case, prefix length times display-name length). One step is one turn of
  a matcher inner loop.
* `glob_matches_word_boundary_substring` and `contains_literal_word_boundary_substring` search only the first
  `max_push_glob_body_bytes` (4096) bytes. A match must end inside them, at a real word boundary: the cut is never taken
  for the end of the value, so a longer word is not matched by its prefix.
* The glob matcher also skips both pattern loops while no candidate is active, so a body of mostly non-matching words
  costs about one step per byte.
* When the budget runs out the glob that needed more does not match (it fails closed: the rule does not apply) and
  the result carries `glob_budget_exhausted` and `glob_steps_used`. Rules that need no body glob (room, sender, rules on
  other keys) are unaffected. `send_event`'s push delivery logs `push.glob_budget.exhausted` at warning level.
  `PushRuleUnreadClassifier` calls the same function, so it has the same bound; it does not log.

### Positive Consequences

* A recipient's evaluation of an event costs at most about 2 million steps however long the body and many the rules.
* The numbers are constants in `push_rules.hpp`; the equivalence test against the reference matcher still holds, because
  bodies under the cap with budget to spare match as before.

### Negative Consequences

* A keyword after the first 4 KiB of a message is not found, and a recipient whose rules together need more than the
  budget on a long body loses the matches the budget could not pay for (for example a highlight). Both are visible in
  the log. A user with many rules and 4 KiB bodies is rare.

## Pros and Cons of the Options

### A cap on the body length alone

* Good, because it is simple.
* Bad, because 200 rules x 512 bytes x 4096 bytes is still 4e8 steps per recipient per event.

### Lower the pattern or rule caps

* Good, because it also shrinks the cost.
* Bad, because it takes working rules from users who send short messages, to defend against long ones.
