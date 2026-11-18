# OAuth addresses are read by a strict reader of our own and matched byte for byte

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-15

## Context and Problem Statement

A redirect URI decides where an authorisation code is sent; the spec calls its validation critical and requires
exact matching against the registered value, except that a native loopback URI registered without a port matches any
port. Client URIs, terms and policy links reach pages and headers. The server already reads URLs with
`http::parse_outbound_url`, which canonicalises through libcurl and accepts only `http` and `https`. How are these
addresses read?

## Considered Options

* A reader in `oauth` (`ParsedUri::read`) for a strict subset of RFC 3986 that keeps the bytes as given.
* `http::parse_outbound_url`.
* RFC 3986 normalisation before comparison (case of scheme and host, default ports, percent-encoding).

## Decision Outcome

Chosen option: "a strict reader of our own". It accepts 1 to 2048 bytes of printable ASCII; a scheme of RFC 3986
characters; an optional authority with no userinfo, a host of LDH labels (no empty label, so no trailing dot, and no
`%`) or a bracketed IPv6 literal, and a port of 1 to 65535 with no leading zero; a path and query of `pchar` with
valid `%XX`. It refuses every fragment, a bare `#` included, and every `\`, quote, angle bracket and other byte
RFC 3986 does not allow raw. Nothing is decoded or normalised.

Matching is byte for byte: `https://APP.example.com/cb` does not match `https://app.example.com/cb`, and an explicit
`:443` does not match its absence. `http` and `https` must be written in lower case wherever this module tests for
them; a private-use scheme is compared with the reversed client host in ASCII lower case, as the spec's rule is about
the name, not its spelling. Only a native client's loopback URI (`http`, host exactly `localhost`, `127.0.0.1` or
`[::1]`, no port at registration) matches the same bytes with `:<port>` after the host.

### Positive Consequences

* No two spellings of one URI exist, so no check can pass on one spelling while the browser follows another.
* What the reader accepts is safe in a `Content-Security-Policy` source and, escaped, in an `href`.

### Negative Consequences

* A client must send its redirect URI exactly as registered; a client that changes the case of its host, or adds a
  default port, is refused.
* Internationalised hosts must be sent in their ASCII (`xn--`) form.

## Pros and Cons of the Options

### `http::parse_outbound_url`

* Bad, because it rewrites the URI through libcurl, so the value checked is not the value compared or sent.
* Bad, because it refuses the private-use schemes native clients need.

### Normalisation

* Bad, because every normalisation step is a place where the server and the browser can disagree.
