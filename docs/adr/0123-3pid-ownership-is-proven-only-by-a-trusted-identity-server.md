# 3PID ownership is proven only by a trusted identity server

* Status: accepted
* Date: 2026-10-07

Technical Story: 29 September 2026 security audit, finding AUTH-5 (3PID ownership is never
validated).

## Context and Problem Statement

`requestToken` without an identity server created a validation session already marked
validated and sent nothing. `/account/3pid/add` and `/bind` accepted any session whose `sid`
and `client_secret` matched, so a user could bind someone else's email address or phone
number, and the real owner was then refused with `M_THREEPID_IN_USE`. The spec says the
homeserver "should validate the email itself, either by sending a validation email itself or
by using a service it has control over".

Merovingian cannot send email or SMS. How should ownership be proven?

## Considered Options

* **Only through a trusted identity server (chosen).**
* Add an SMTP client and validate email locally. Rejected for now: a new dependency, mail
  templates and outbound-mail security, and phone numbers would still need an identity server.
* Disable 3PID management entirely. Rejected: it removes the identity-server flow that works.

## Decision Outcome

Chosen option: only through a trusted identity server.

* `requestToken` (`register` and `account/3pid`, email and msisdn) without a trusted
  `id_server` and `id_access_token` is refused with `400 M_THREEPID_MEDIUM_NOT_SUPPORTED`, and no
  session is created. An untrusted `id_server` is refused as before.
* A delegated session starts unvalidated. It keeps the identity server's base URL and the
  client's identity access token in memory only, for the session's lifetime, and the token is
  zeroed when the session is pruned or consumed.
* `/account/3pid/add`, `/account/3pid/bind` and the legacy `POST /account/3pid` confirm with the
  identity server (`getValidated3pid`) before binding. Only a validation of the same medium and
  address as the session counts; anything else is `400 M_SESSION_NOT_VALIDATED`, and an
  unreachable or malformed identity server is `502`. The call runs with the runtime mutex
  released, and the session and the "address in use" check are re-done afterwards.
* A consumed session is erased, so a `sid` cannot be replayed.
* **Rule for future code:** never mark a validation session validated locally. A new way to
  prove ownership (for example sending email) must produce a verifiable proof and get its own
  ADR.

### Negative Consequences

* A server with no trusted identity server cannot add 3PIDs at all.
* `/register` advertises no identity stage today, so `register/*/requestToken` sessions are
  recorded but nothing consumes them.
* A phone number the identity server reports in a different numeral form from the session's
  fails the match; that fails closed.
