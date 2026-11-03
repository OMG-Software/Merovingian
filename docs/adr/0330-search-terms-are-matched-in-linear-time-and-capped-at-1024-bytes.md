# Search terms are matched in linear time and capped at 1024 bytes

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2 F-28, F-29 and F-34: three search endpoints ran a quadratic substring search over a text the caller chose, with `runtime.mutex` held

## Context and Problem Statement

`POST /publicRooms` (`generic_search_term`), `POST /search` (`search_term`) and `POST /user_directory/search`
(`search_term`) each looked for a client-supplied term inside text a client can also size: a room name or topic or
a message body (up to the 65,536-byte event limit) and a display name (bounded only by the 1 MiB body). They used
`std::search` with a per-byte `tolower` predicate and `std::string_view::find` / `std::string::find`, which restart
the comparison at every offset. A text of `a` x 60,000 and a term of `a` x 30,000 then `b` costs about 9e8
comparisons per text, 2.5e11 for a 1 MiB display name, all under `runtime.mutex`. The spec defines both terms as
plain strings with no length limit and no algorithm.

## Considered Options

* One linear-time matcher (Knuth-Morris-Pratt over ASCII-case-folded bytes) for all three endpoints, plus one cap on the term
* Keep the library searches and cap only the term
* A different library search that is faster in practice (`std::boyer_moore_horspool_searcher`, `std::string_view::find`)
* Match only a bounded prefix of each text
* Truncate an over-long term instead of refusing it

## Decision Outcome

Chosen option: "One linear-time matcher plus one cap". `core::FoldedSubstringMatcher` (`core/folded_substring.hpp`)
is built once per request from the term and reused for every text; it takes at most two steps per byte of text
however term and text are chosen, and counts them (`steps()`) so a test can hold it to that. Folding is ASCII only
(`A-Z`), which is what the three endpoints did before (`tolower` in the C locale and `to_lower`), so results are
unchanged. `/search` counts non-overlapping occurrences with it for `rank`, as before.

A term over `core::max_search_term_bytes` (1024) is refused with `400 M_TOO_LARGE` at parse time, before any work
and before `POST /publicRooms` would forward the term to another server. The cap is one constant for all three
endpoints. The refusal follows the project's other caps (`createRoom` entries, push rules, account data: 400
`M_TOO_LARGE`; the spec defines `M_TOO_LARGE` as "The request or entity was too large"); `M_INVALID_PARAM` is for a
parameter of the wrong type or value and the term is neither. 413 is kept for a whole body or event over its limit.

With a linear matcher and a capped term, the work for a text is the bytes of that text. That is data the server
already holds and the caller already paid for, as for any other read of it, so the text is not truncated.

Rejected:

* Capping the term alone leaves up to 1024 x 64 KiB = 6.5e7 comparisons per text, and 1024 x 1 MiB for a display
  name, still superlinear and multiplied by every room, event or profile.
* `std::string_view::find`, `std::search` and Boyer-Moore-Horspool are not worst-case linear, so they only move the
  constant.
* Searching a bounded prefix of each text gives wrong answers (a term in the tail is never found), the same fault as
  truncating the term, and is unnecessary once the search is linear.
* Truncating a term returns results for a term the client did not send; refusing is honest.

### Positive Consequences

* The three endpoints cannot be made to hold `runtime.mutex` for longer than a pass over the text they search.
* One implementation, one test, one cap.

### Negative Consequences

* A client that sends a term over 1024 bytes now gets an error where it got results. No real search term is that long.
* Matching is byte-wise on ASCII case, as before: it does not fold non-ASCII letters.

## Links

* Refined by [ADR-0332](0332-search-filter-lists-are-prepared-once-per-request.md) and [ADR-0334](0334-the-user-directory-reads-the-accounts-once-and-caps-its-results.md)
* Follows the lock rule in `src/homeserver/AGENTS.md` ("Work under the runtime lock is bounded by the request") and [ADR-0176](0176-federation-media-multipart-is-parsed-under-the-lock-with-a-linear-scan.md)
