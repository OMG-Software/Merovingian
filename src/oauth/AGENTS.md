# src/oauth/ — OAuth 2.0 API building blocks

Pure functions and value types for the built-in OAuth 2.0 API
([ADR-0760](../../docs/adr/0760-the-oauth-2-0-api-is-built-into-the-homeserver.md),
[spec](../../docs/matrix-v1.19-spec/client-server-api.md#oauth-20-api)). The handlers, stores and routes live in
`src/homeserver/`; they call what is here. The plan is `docs/todos/oauth-2-0-api.md`.

## Key files

| File | Responsibility |
|---|---|
| `OAuthRefusal.hpp`, `OAuthErrorCodes.hpp` | `OAuthRefusal`: the wire `error` code beside a `core::Error` whose message is fixed text, safe as `error_description` (ADR-0768) |
| `Pkce.cpp` | `pkce_challenge_is_valid`, `pkce_verifier_is_valid`, `pkce_s256_matches`: RFC 7636 with `S256` only, compared in constant time |
| `ScopeParser.cpp` | `parse_scope` and `oauth_device_id_is_valid`: the API token and exactly one device token, unknown tokens dropped (ADR-0769) |
| `ParsedUri.cpp` | `ParsedUri::read`: the strict URI reader for every address a client supplies and every page link (ADR-0770) |
| `ClientUri.cpp` | `ClientUri::read`: `https` on a DNS name of two or more labels whose last label does not end in a number by the WHATWG rule (all digits, or `0x` and hex digits) (ADR-0771) |
| `RedirectUriRules.cpp` | `validate_redirect_uri` (registration), `match_redirect_uri` (authorisation and token requests), `https_uri_is_on_client_host` |
| `ClientMetadata.cpp` | `ClientMetadata::validate`, `to_json`, `canonical_bytes`: RFC 7591 registration rules (ADR-0771) |
| `HtmlText.cpp`, `HtmlLiteral.hpp`, `HtmlName.hpp`, `PagePath.hpp` | Page text: escaped at run time, or fixed and checked at compile time (ADR-0772) |
| `Page.cpp`, `PageForm.cpp`, `PageDetail.hpp`, `TextInput.hpp`, `SubmitButton.hpp` | The one page renderer and its parts |
| `PageHeaders.cpp` | `page_style`, `page_headers`: the fixed style block and the headers every page carries, with the `form-action` source of a validated redirect target |
| `OAuthPaths.hpp` | Every OAuth route path: the `PagePath` constants under `/_merovingian/oauth2/` and `/_merovingian/account`, and the two `auth_metadata` paths (ADR-0773) |
| `OAuthBaseUrl.cpp` | `OAuthBaseUrl::read`: `server.public_baseurl` as an `https` URL with a host and no query; `issuer()` (one trailing slash) and `url(PagePath)` (ADR-0773) |
| `ServerMetadata.cpp`, `ServerMetadataOptions.hpp` | `server_metadata`: the `auth_metadata` document, device grant, `prompt=create` and account management fields only when their option is on |
| `AuthorizationRedirect.cpp` | `percent_encode_redirect_value`, `authorization_redirect_address`: the answer's parameters percent-encoded (everything but the unreserved characters) into the query or the fragment of a matched redirect URI |
| `AuthorizationPages.cpp`, `AccountFormInput.hpp`, `ConsentPageInput.hpp`, `DeviceConsentPageInput.hpp` | The login, registration, consent and error pages of `/_merovingian/oauth2/authorize`, the device grant's link, consent and answer pages (ADR-0806: the consent page's warning comes first), and the form field and action names they post. A value `HtmlText::escape` refuses is replaced by fixed text |
| `AccountPages.cpp`, `AccountPageFrame.hpp`, `AccountDeviceRow.hpp`, `AccountSignInInput.hpp` | The account pages of `/_merovingian/account` (ADR-0796): sign-in, overview, devices, one device, device sign-out, password, deactivation, cross-signing reset and result pages; the six spec actions (`account_management_actions`, `account_management_action`, `account_action_takes_device`), `account_action_address` (every link, the post-sign-in redirect and the `m.oauth` URL), and the form field and action names. Every signed-in form carries `form_token`; a page whose token cannot be shown holds no form |
| `UserCode.cpp` | The device authorization grant's user code (ADR-0805): `user_code_from_bytes` (rejection sampling over `BCDFGHJKLMNPQRSTVWXZ`), `normalise_user_code` (the rule 2 exception below) and `display_user_code` (`XXXX-XXXX`) |
| `FormPostOrigin.cpp` | `form_post_origin`, `form_post_origin_is_accepted`: a page's form post must name this server's origin exactly, and `Sec-Fetch-Site`, when sent, `same-origin` (ADR-0784) |
| `HandOffRedirect.cpp` | `hand_off_redirect_target` (`https`, loopback `http` or a private-use scheme with no authority, then the allowlist) and `hand_off_return_address` (every `loginToken` removed, the new one added) for the legacy SSO redirect's hand-off (ADR-0802) |
| `HandOffAllowlist.cpp` | `hand_off_allowlist_entry_error`, `hand_off_allowlist_error`: an https origin or a bare private-use scheme, at most 32, each once (ADR-0774) |
| `FormContentType.cpp` | `api_form_content_type_is_accepted`: the token and revocation endpoints take `application/x-www-form-urlencoded` only, with at most a `charset=utf-8` parameter |
| `AccessTokenLifetime.hpp` | `access_token_lifetime_ms` (the configured lifetime, or one hour when it is 0: an OAuth access token always expires, ADR-0791) and `expires_in_seconds` |
| `DisplayText.cpp`, `AsciiCase.cpp` | Module-internal: `display_text_is_safe` (no control, bidirectional formatting or invisible character, by code point) and `ascii_lower` |

## Rules

1. **Nothing here holds state, does I/O or logs.** Every input is attacker-chosen and may be a secret (a verifier,
   a password typed into a page). A function that needs the runtime, the database or the clock belongs in
   `src/homeserver/`.
2. **Refuse, never repair.** Every reader has a hard cap with its reason beside it, refuses instead of truncating,
   stripping or normalising, and its error text is fixed: it never quotes the input. The one exception is
   `normalise_user_code`, because RFC 8628 section 6.1 asks the server to accept a user code however it is typed: it
   reads lower case as upper and skips `-`, space, `.` and `_`, and still refuses every other byte and anything over
   its cap (ADR-0805). Do not add another.
3. **Every address a client supplies is read with `ParsedUri::read`.** Never `http::parse_outbound_url`, which
   canonicalises through libcurl and knows no private-use scheme, and never a private parser. A redirect URI is
   checked with `validate_redirect_uri` at registration and found with `match_redirect_uri` on every request; the
   match is byte for byte, except a native loopback URI's port.
4. **A redirect happens only after the client and its redirect URI are validated.** A failure of either is shown as
   a page, never sent to the URI.
5. **HTML is built only by `Page`.** Text reaches a page only as `HtmlText` (`HtmlText::escape`) or a compile-time
   `HtmlLiteral`, `HtmlName` or `PagePath`. Never concatenate a value into markup, add a `<script>`, an event-handler
   attribute, a `style=` attribute or a resource from another origin, or link to a scheme other than `https`
   (ADR-0763, ADR-0772).
6. **Every page response carries `page_headers()`** (`Referrer-Policy: same-origin`, as the page's own meta element
   says; ADR-0784), **and the handler marks it `LocalHttpResponse::page`** (ADR-0785). A form post is accepted only
   when `form_post_origin_is_accepted` says so. A page whose form post is answered with a redirect to the client
   passes the matched `ParsedUri` to `page_headers(target)`; nothing else adds a policy source.
7. **The style block and its hash are one text.** Change `page_style()` only in `PageHeaders.cpp`; the hash is
   computed from it, and `test_oauth_page.cpp` proves the policy names it.
8. **PKCE is `S256` only and compared in constant time** (`crypto::constant_time_equal`). SHA-256 and base64 come from
   `crypto`; this module never calls libsodium.
9. **Every absolute OAuth address comes from `OAuthBaseUrl`.** The issuer is `issuer()` and every endpoint is
   `url(path)` with a constant from `OAuthPaths.hpp`; never join `public_baseurl` and a path by hand (ADR-0773).
10. **A hand-off allowlist entry is an origin or a bare scheme, never a prefix** (ADR-0774).
11. **Client metadata is validated once, by `ClientMetadata::validate`,** also when a stored registration is read back.
    The client ID is a keyed hash of `canonical_bytes()` (phase 4); do not hash anything else for it.
12. **No default member initialiser holds page text** (ADR-0800). Clang 18 does not constant-evaluate a consteval call
    in a default member initialiser: it compiles `HtmlText message{"..."}` there and runs the `HtmlLiteral` check when
    the member is initialised, so a bad literal throws during a request instead of failing the build. No data member
    whose type names `HtmlText`, `HtmlLiteral`, `HtmlName` or `PagePath` may have an initialiser other than empty
    braces; give the text where the object is built. `page-text-member-initialiser-tooling`
    (`tests/tooling/test_page_text_member_initialisers.py`) scans `src/` and `include/` for it.

## Tests

`tests/unit/test_oauth_pkce.cpp` (`[oauth][pkce]`), `test_oauth_scope.cpp` (`[oauth][scope]`),
`test_oauth_redirect_uri.cpp` (`[oauth][uri]`, `[oauth][redirect]`), `test_oauth_client_metadata.cpp`
(`[oauth][metadata]`), `test_oauth_page.cpp` (`[oauth][page]`), `test_oauth_server_metadata.cpp` (`[oauth][urls]`,
`[oauth][server_metadata]`), `test_oauth_hand_off_allowlist.cpp` (`[oauth][allowlist]`),
`test_oauth_form_post_origin.cpp` (`[oauth][form-origin]`), `test_oauth_page_response.cpp`
(`[oauth][page-response]`), `test_oauth_authorization_redirect.cpp` (`[oauth][redirect-address]`),
`test_oauth_authorization_pages.cpp` (`[oauth][authorize-page]`, the device pages `[device]`),
`test_oauth_user_code.cpp` (`[oauth][user-code]`), `test_oauth_hand_off_redirect.cpp`
(`[oauth][hand-off-redirect]`), `test_oauth_account_pages.cpp` (`[oauth][account-page]`). The account pages:
`tests/conformance/test_oauth_account_management_conformance.cpp` and
`tests/integration/test_oauth_account_pages_flow.cpp` (`[oauth-account]`, `[oauth-uia]`). The hand-off:
`tests/conformance/test_oauth_aware_clients_conformance.cpp` and `tests/integration/test_oauth_login_hand_off_flow.cpp`
(`[hand-off]`). The authorisation endpoint:
`tests/conformance/test_oauth_authorization_conformance.cpp` and `tests/integration/test_oauth_authorization_flow.cpp`
(`[oauth-authorize]`). The device grant: `tests/unit/test_oauth_device_authorisation_store.cpp`,
`tests/conformance/test_oauth_device_grant_conformance.cpp` and `tests/integration/test_oauth_device_grant_flow.cpp`
(`[oauth-device]`). The served document:
`tests/conformance/test_oauth_metadata_conformance.cpp` and `tests/integration/test_oauth_metadata_flow.cpp`
(`[oauth]`). Fuzz targets: `fuzz_oauth_redirect_uri.cpp`, `fuzz_oauth_scope.cpp`, `fuzz_oauth_client_metadata.cpp`.
