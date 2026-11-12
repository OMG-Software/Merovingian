# A password reset address keeps one code per interval and a daily mail cap

* Status: accepted
* Date: 2026-11-12

Technical Story: security audit run-3, finding C17.

## Context and Problem Statement

ADR-0481 sends at most one reset mail per address per 60 seconds across all sessions. `requestToken` is unauthenticated,
so a caller who knows the owner's address could take the one send slot each minute with a session of their own: the code
went to the owner's mailbox but only into the caller's session, a session the owner opened inside the minute got no code,
and the owner could succeed only in the few seconds between the throttle ending and the caller's next request.

## Considered Options

* Keep one code per address per interval. A session throttled for that address is judged against the code already mailed
  (the latest one held by any session of the address), a code is spent from every session once one session proves it, and
  a submitted code validates only the session it is submitted to. Add a cap of 10 mails per address per day.
* Throttle per (address, client address) so each caller has a slot of their own, with a larger per-address daily cap.
* Give the throttled session a copy of the code at request time.

## Decision Outcome

Chosen option: the first. The caller never sees the mail, so the shared code gives them nothing; the owner can use the
code the caller caused to be sent. The code is compared in `submitToken` against the session's own code and the address's
latest code, both comparisons always run. A session that has the code from the shared latest still needs its own
`client_secret` and `sid`, and a wrong code still costs that session one of its five tries.

The per-(address, client) throttle was rejected: it multiplies the mail one address can be sent by the number of client
addresses an attacker controls, which is the mail bombing the throttle exists to stop. Copying the code into the throttled
session at request time was rejected because the session may belong to the caller, and the copy would have to be wiped
again when the next code is mailed; judging at submit time needs no copy.

The daily cap (`password_reset_address_daily_cap`, 10 in `password_reset_address_window_ms`) bounds the mail one address
receives whoever asks. Times are kept per mailed address in `ClientServerRuntime::password_reset_mail_times`; only an
address with an account is mailed, so the table is bounded by those accounts times the cap. Past the cap a request is
answered like a throttled one and the last code mailed stays valid until its session ages out (15 minutes).

Residual: an attacker with many client addresses can still request ten mails a day to the owner's address and make them
wait for the next day to ask again after those; they cannot stop the owner using any one of those codes.

## Links

* Refines [ADR-0481](0481-password-reset-by-email-is-answered-alike-and-completed-with-a-short-code.md)
