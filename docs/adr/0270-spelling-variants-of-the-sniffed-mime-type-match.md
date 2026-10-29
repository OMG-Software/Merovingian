# Spelling variants of the sniffed MIME type match

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-29

Technical Story: Complement run 10 (`TestContentCSAPIMediaV1`, `TestContentMediaV1`,
`TestAsyncUpload/Cannot_upload_to_a_media_ID_that_has_already_been_uploaded_to`)

## Context and Problem Statement

An upload whose declared Content-Type differs from the type sniffed from its bytes is
quarantined (451). Complement uploads a PNG declared as `img/png`, so the plain spelling
variant of a safe image was quarantined. MIME types compare case-insensitively (RFC 2045
section 5.1, RFC 6838 section 4.2), and `img/` is a common misspelling of `image/`. The owner
chose to keep the hardening and accept spelling variants only.

Separately, an empty-body `PUT /_matrix/media/v3/upload/{serverName}/{mediaId}` to a filled
media ID answered 400 from the local router's pipe splitter, which refused an empty last field,
before the media service could answer the spec's 409 `M_CANNOT_OVERWRITE_MEDIA`.

## Considered Options

* Ignore a declared/sniffed mismatch whenever the top-level types agree.
* Store a separate served type in a column of its own (a migration).
* One rule, `media::media_types_are_equivalent`: case-insensitive type and subtype, and a
  declared top-level `img` read as `image`, nothing else.

## Decision Outcome

Chosen option: one rule, `media_types_are_equivalent`, because it accepts exactly the spelling
variants and keeps every safety decision in one function.

* The allow-list still judges the sniffed type, never the declared string.
* A record keeps the declared spelling only when it is equivalent to the sniffed type, and is
  served under it (the spec: "exactly the same as the original upload, or reasonably close").
* Every decision made on a stored type (inline-safe, thumbnailable, the thumbnail worker's
  source type) uses this function and never compares against a literal.
* The pipe splitter validates only the three wrapper fields. The last field is the client's
  body and may be empty: whether an empty body or a filled media ID is refused is the media
  service's answer, so the spec's status codes come before any framing error.

### Negative Consequences

* `content_type_is_inline_safe` now classes `IMAGE/PNG` and `img/png` as inline-safe for every
  caller. Served with `X-Content-Type-Options: nosniff`, this is the same file type.
