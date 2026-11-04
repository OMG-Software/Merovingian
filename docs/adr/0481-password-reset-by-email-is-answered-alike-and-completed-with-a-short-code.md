# Password reset by email is answered alike and completed with a short code

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`POST /account/password` could only be used with an access token and the old password. A user who cannot sign in
needs the `m.login.email.identity` stage, which needs `POST /account/password/email/requestToken`. The spec says that
endpoint "may" answer `M_THREEPID_NOT_FOUND` for an address no account holds (the account-enumeration oracle), and
that the server may send the token itself, handing the client a `submit_url` to submit it to.

## Decision Outcome

* **Uniform answer.** requestToken answers every well-formed request `200` with a fresh `sid` and a `submit_url`,
  whether or not an active account holds the address. `M_THREEPID_NOT_FOUND` is never sent. A session is opened for an
  unknown address too (with no code), so a repeat of the request, the submit step and the reset all behave alike.
* **Timing, stated exactly.** The SMTP exchange (a connection, TLS, several round trips: the part that takes
  milliseconds to seconds) is sent from a background task (`send_password_reset_email`), never on the request thread.
  What remains on the request thread only for an address with an account is small and local: drawing a code, building
  the message and starting the task. That difference is not removed, only made small, and `requestToken` is
  rate-limited (`auth_sensitive`). Uniform work (building and discarding a message for unknown addresses too) was
  considered and left out: it would still leave the task start unmatched.
* **Sends are counted on their own.** At most 8 reset sends run at once
  (`HomeserverRuntime::password_reset_sends_in_flight_`, released by an RAII permit on every exit path of the task),
  more are dropped. They are not counted against `orphan_futures_`, which also holds federation race losers and push
  deliveries: under federation load that would drop every reset while the client still got `200`.
* **One email per address per 60 seconds, across all sessions.** `requestToken` is unauthenticated and mails an
  address the caller names, so a new `client_secret` or a higher `send_attempt` must not mean another email. The time
  of the last send is kept on the session (`reset_sent_at_ms`) and the check scans the session list, which is capped.
  A throttled request answers the same `200` and `sid`; a throttled resend on an existing session keeps its code and
  its tries; a new throttled session has no code and fails like a wrong code. A session that used up its tries is
  kept until it ages out, so burning one does not clear the throttle.
* **A short code, with a try cap.** The code is 8 characters of `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (40 bits), written
  by a person, matched case-insensitively (the Identity Service API allows it). A session accepts 5 wrong codes and is
  then dropped (`M_SESSION_EXPIRED`); sessions live 15 minutes. Guessing is bounded to 5 in 2^40 per session, and the
  `/requestToken` family and the submit path share the strict `auth_sensitive` rate-limit tier.
* **Comparison.** The code and the `client_secret` are compared in constant time
  (`crypto::constant_time_equal_variable_length`); an account-less session compares a fixed dummy so the work does not
  depend on whether a code exists. The `sid` is compared normally: it is returned to the client, and a lookup needs the
  `client_secret` too.
* **The submit step.** `submit_url` is `/_matrix/client/unstable/org.merovingian/account/password/email/submitToken`,
  with the Identity Service `POST /validate/email/submitToken` body and `{"success":true}` answer and its
  `M_TOKEN_INCORRECT`, `M_INVALID_PARAM` and `M_SESSION_EXPIRED` errors. It is this server's own path, not a spec
  path. The email carries the code only, no link: nothing to click, nothing to forward, no URL to forge.
* **Completion.** `POST /account/password` with no access token and `auth.type = m.login.email.identity` names the
  session in `threepid_creds`; only a validated session of an active account resets the password, and a successful
  reset consumes it (a weak password, `M_WEAK_PASSWORD`, keeps it for a retry). The session names the account that held
  the address when the code was sent; at completion the address is checked against `account_threepids` again, and an
  address that has left that account gives the unvalidated-session answer and spends the session. `logout_devices` defaults to true:
  every access token, refresh token, OpenID token and pusher of the account goes. With a token, the existing
  `m.login.password` stage is unchanged. With no relay configured the old behaviour stands (`M_MISSING_TOKEN`).
* `POST /account/password/msisdn/requestToken` answers `400 M_THREEPID_MEDIUM_NOT_SUPPORTED`: the server has no SMS.
* The message is a new kind beside the unread-count notice (ADR-0219), `build_password_reset_email`: it holds the
  code and the server name only.

Rejected: answering `M_THREEPID_NOT_FOUND` (enumerates accounts); sending the mail inline (timing); a link in the
mail (a link is a bearer credential that survives forwarding, scanners fetch links, and it needs a GET endpoint with
the token in a URL); a long code (the user types it); delegating to an identity server (the existing sibling
endpoints do; a reset must work without one, and the spec allows the homeserver to validate itself).
