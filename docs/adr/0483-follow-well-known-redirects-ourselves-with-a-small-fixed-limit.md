# Follow `.well-known/matrix/server` redirects ourselves, four at most, checked on every hop

* Status: accepted
* Date: 2026-11-04

Technical Story: November project analysis, SS3

## Context and Problem Statement

Server-Server API v1.19, "Resolving server names", step 3: "30x redirects should be followed, however redirection loops
should be avoided." `OutboundClient` never follows redirects (libcurl's `CURLOPT_FOLLOWLOCATION` is off, and a 3xx
surfaces as `redirect_rejected`), so a server whose operator serves its delegation document through a redirect (a common
static-hosting set-up) could not be reached. The refusal was a property of the shared client, not a decision about
well-known, and no ADR recorded it. Turning on libcurl's redirect following would send the next request to an address
nobody checked against the deny-list and would bypass the address pin (ADR-0097).

## Decision Drivers

* The delegation document is named by a remote operator, so a redirect target is attacker-chosen input.
* Every connection must go to addresses that passed the SSRF deny-list and the private-range rule (ADR-0231).
* A hostile server must not be able to hold a discovery thread: the hop count and the total time are bounded.

## Considered Options

* Enable `CURLOPT_FOLLOWLOCATION` with a redirect limit
* Follow redirects in `fetch_well_known_following_redirects`, one pinned request per hop
* Keep refusing redirects

## Decision Outcome

Chosen option: "follow redirects in `fetch_well_known_following_redirects`". For each hop it:

1. parses the URL with `http::parse_outbound_url` (https only: no userinfo, fragment, encoded authority; a `http://`
   redirect is refused);
2. resolves the host and refuses it unless every address passes the network's deny-list and the private-range
   allowance, exactly as for the first request;
3. asks the transport for one request pinned to those addresses, with a timeout of what is left of one deadline shared
   by all hops (a chain cannot take longer than the single fetch did);
4. on a 301, 302, 303, 307 or 308 resolves `Location` against the current URL (an absolute `https://` URL, `//host/...`
   or an absolute path; a relative path or any other scheme is refused) and repeats.

At most `well_known_max_redirects` (4) redirects are followed; a URL seen already ends the chain as a loop. The method
is always GET and no header or credential is carried across hops. The shared client keeps refusing redirects.

### Negative Consequences

* A relative `Location` such as `other.json` is refused, although RFC 9110 allows it. Resolving relative paths needs
  dot-segment handling nobody has asked for, and refusing is the safe side.

## Links

* [ADR-0097](0097-check-outbound-socket-peers-against-request-pins.md)
* [ADR-0213](0213-url-previews-fetch-through-one-ssrf-gate.md) follows redirects the same way for previews
* [ADR-0231](0231-federation-may-reach-operator-named-private-networks-and-nothing-else.md)
