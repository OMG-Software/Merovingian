# Media file names are validated and encoded before they reach a header

* Status: accepted
* Date: 2026-10-22

Technical Story: conformance audit R17 (2026-10-17)

## Context and Problem Statement

Three file names reach a download's `Content-Disposition`. The
`/download/{serverName}/{mediaId}/{fileName}` routes "MUST contain the file name requested in the
path". An unnamed download "MUST contain the same `filename`" the upload was made with. A remote
copy uses "the remote server's `filename`". Each is text that a client or a remote server chose,
and each ends up inside a response header, so each is a header-injection surface. How is a name
checked, how is it written, and what happens to one that a header cannot carry safely?

## Decision Drivers

* A CR, LF or NUL in a header value is a response-splitting bug.
* The spec requires the *same* upload filename back, so silently rewriting it is non-conformant.
* The spec gives a download no `400`: the media exists and should be served.
* Every client and every language uses non-ASCII file names.

## Considered Options

* Write a name into a quoted string as it is
* Store or serve anything, and sanitise only when writing the header
* Validate every name with one check; refuse an invalid upload `filename`, leave out an invalid
  path or remote name; encode a valid one per RFC 6266

## Decision Outcome

Chosen option: "validate, refuse or leave out, encode".

* `media::media_filename_is_valid` accepts at most 255 bytes of well-formed UTF-8 with no control
  characters (so no CR, LF or NUL) and no `/` or `\`.
* An upload (`POST /upload`, `PUT /upload/{serverName}/{mediaId}`) whose `filename` fails it is
  refused with `400 M_INVALID_PARAM`, so what is stored (`media.upload_name`) is always what the
  client sent.
* A `{fileName}` path segment that fails it is left out, and the media is served with a bare
  `inline` or `attachment`.
* A remote server's `Content-Disposition` is read by `media::content_disposition_filename`
  (quoted, token or RFC 5987 form, at most 1 KiB scanned, one linear pass). A name that fails the
  check is left out.
* `media::media_content_disposition` writes a valid name as `filename="..."` (escaping `"` and
  `\`) when it is printable ASCII. Otherwise it writes `filename*=utf-8''<percent-encoded>`,
  keeping RFC 5987 `attr-char` and encoding every other byte. The header value is therefore
  always printable ASCII.
* Inside the process the stored name crosses from the local router to the client API
  percent-encoded, in an internal header the client API never copies to the wire. No other code
  writes a file name into `Content-Disposition`.

### Positive Consequences

* The named routes work (R17), and downloads carry the uploader's filename as the spec requires.
* There is no path by which a file-name byte reaches a header unencoded.

### Negative Consequences

* A client that uploads with a filename containing a control character gets a `400` instead of a
  silently cleaned name.
* A request whose `{fileName}` holds a control character or a path separator gets the content
  without the name it asked for.

## Pros and Cons of the Options

### Write the name as it is

* Bad, because `%0D%0A` in the path becomes a header line break.

### Sanitise only when writing

* Good, because no upload is refused.
* Bad, because the stored name and the served name then differ, and the spec requires the same
  name back.

### Refuse an unsafe `{fileName}` with 400 as well

* Good, because the client learns its name was not used.
* Bad, because the spec lists no `400` for the download, and the content exists.

## Links

* Related to [ADR-0068](0068-random-media-ids-and-legacy-endpoint-freeze.md): the deprecated
  named route is frozen like the unnamed one.
