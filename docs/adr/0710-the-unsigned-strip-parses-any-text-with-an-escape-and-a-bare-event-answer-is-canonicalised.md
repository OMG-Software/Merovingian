# The unsigned strip parses any text with a unicode escape, and a bare /event answer is stored as canonical JSON

* Status: accepted
* Date: 2026-11-12

## Context and Problem Statement

ADR-0402 stores every received PDU without its top-level `unsigned`. `events::without_unsigned_json` returned its input
unchanged when the literal bytes `"unsigned"` were absent. Most paths pass canonical bytes, but the event-fetch path kept a
remote server's bare PDU answer verbatim, so a key written `unsigned` (the same key once decoded) was stored, then
served to other servers as this server's copy (run-3 finding C43).

## Considered Options

* Parse any text that holds a `\u` escape, and re-serialise a bare answer canonically
* Drop the literal prefilter and always parse
* Only re-serialise the bare answer

## Decision Outcome

Chosen option: "Parse any text that holds a `\u` escape, and re-serialise a bare answer canonically". Both: the second
makes every stored remote event canonical bytes, which the other literal prefilters (the relation index, push badge,
read markers) also assume; the first makes the strip itself safe for any other caller that passes verbatim text.

Why not always parse: the common case is a canonical PDU of up to 64 KiB on every ingestion; a letter in a key can be
written only as `\u`, so a search for it is exact and keeps the fast path. Why not only re-serialise: the helper's
contract is "no member whose decoded key is unsigned", which should not depend on every caller's input being canonical.

Raw-body inputs of `send_join`, `send_leave`, `send_knock` and a resident's signed membership event are re-parsed and
stripped by their own writers; with the escape rule they no longer depend on canonical spelling.
