# Media file names are validated and encoded before they reach a header

* Status: accepted
* Date: 2026-10-22

Technical Story: conformance audit R17 (2026-10-17)

## Context and Problem Statement

The `/download/{serverName}/{mediaId}/{fileName}` routes must answer with a
`Content-Disposition` that "MUST contain the file name requested in the path". The name is text
a client chose, percent-decoded from the path, and it ends up inside a response header, so it is
a header-injection surface. How is it written, and what happens to a name that a header cannot
carry safely?

## Decision Drivers

* A CR, LF or NUL in a header value is a response-splitting bug.
* The spec gives the named download no `400`: the media exists and should be served.
* Every client and every language uses non-ASCII file names.

## Considered Options

* Write the decoded name into a quoted string as it is
* Refuse a named download whose name is unsafe with `400 M_INVALID_PARAM`
* Validate the name, encode a valid one per RFC 6266, and leave an invalid one out

## Decision Outcome

Chosen option: "validate, encode, leave out". `media::media_filename_is_valid` accepts at most
255 bytes of well-formed UTF-8 with no control characters (so no CR, LF or NUL) and no `/` or
`\`. `media::media_content_disposition` writes a valid name as `filename="..."` (escaping `"`
and `\`) when it is printable ASCII and as `filename*=utf-8''<percent-encoded>` (RFC 5987
`attr-char` kept, every other byte encoded) otherwise, so the header value is always printable
ASCII. A name that fails validation is left out and the media is served with a bare `inline` or
`attachment`. No other code writes a file name into `Content-Disposition`.

### Positive Consequences

* The named routes work (R17), including non-ASCII names.
* There is no path by which a file-name byte reaches a header unencoded.

### Negative Consequences

* A request whose `{fileName}` holds a control character or a path separator gets the content
  without the name it asked for.

## Pros and Cons of the Options

### Write the decoded name as it is

* Bad, because `%0D%0A` in the path becomes a header line break.

### Refuse an unsafe name with 400

* Good, because the client learns its name was not used.
* Bad, because the spec lists no `400` for the download, and the content exists.

## Links

* Related to [ADR-0068](0068-random-media-ids-and-legacy-endpoint-freeze.md): the deprecated
  named route is frozen like the unnamed one.
