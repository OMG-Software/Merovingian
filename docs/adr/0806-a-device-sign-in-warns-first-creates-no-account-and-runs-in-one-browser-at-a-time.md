# A device sign-in warns first, creates no account, and runs in one browser at a time

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: plan P11 and phase 10 in `docs/todos/oauth-2-0-api.md`.

## Context and Problem Statement

After the user types a right code on the link page, the sign-in goes through the same login pages as the authorisation
code grant, then a consent page, and the user's answer is recorded for the device to collect. Three things differ from
the code grant. The person answering is not the person who started the flow: the device did, and anyone can start one
and send the user its code. The code is shared, not bound to one browser: anyone who reads it off the screen, or is
sent it, can type it too. And nothing is redirected afterwards. What does the consent page say, may the pages create
an account, and what happens when two browsers type the same code?

## Decision Drivers

* The grant's inherent attack is phishing: an attacker starts a sign-in on a device they hold and persuades the user
  to approve it (RFC 8628 section 5.4, plan "Risks"). The only defence in the flow is the user's informed refusal.
* A code typed in two browsers must not let one browser's sign-in decide for another browser's user, and must not
  leave a sign-in in progress that a later answer from the other browser silently overrides.
* A browser that typed the code and walked away must not lock the code for the rest of its ten minutes.

## Considered Options

For two browsers:

* One browser at a time, under a lease: the first holds the code for two minutes after each step it completes;
  another browser is answered 409 until the lease lapses, then takes over and the first can no longer answer.
* First come, first served for the whole lifetime.
* Any browser may answer; the first answer wins.

For the consent page:

* The warning first, as the page's error notice, before the code and the client.
* The warning after the details, as on the code grant's consent page.

## Decision Outcome

* **The warning is the first thing on the consent page**: it says a different device, not this browser, is being signed
  in, to continue only if the user started it on that device and the code matches, and to deny if someone sent the
  code or the link. Then the code (as `XXXX-XXXX`), the client's name (or "An application with no name") and its
  `client_uri` host, the account and the device ID, the full-access statement and, when the user already holds the
  device ID, the replacement notice. Placed first because the attack works on a user who reads the client's familiar
  name and stops reading.
* **A device sign-in creates no account.** The login page offers no registration, and `register` and `show_register`
  are refused with 403. A device is signed in to an account the user already has; an attacker gains nothing from an
  account the victim creates for them, and the page need not explain a second path.
* **One browser at a time, under a two-minute lease.** The right code attaches the browser (by its `__Host-mv-oauth`
  cookie, compared as a hash) to the device authorisation; the lease is renewed when its user signs in. Another browser
  typing the code is answered 409 with `Retry-After` until the lease lapses, then takes the code over. The first
  browser's sign-in then ends with the "Device sign-in ended" page at its next step, and its `approve` cannot decide.
  The same browser typing the code again gets a fresh attachment that ends its earlier one. Chosen over first come,
  first served, which lets a browser that walked away (or an attacker who saw the code) lock it out; chosen over
  "first answer wins", which lets a sign-in in another browser decide while this user is still reading.
* **An answer counts only from the latest attachment**, and only while the entry is pending: `decide` is refused
  otherwise and the user sees the ended page. An approval judges the account again (`account_sign_in_gate`); a refused
  account releases the attachment so another browser need not wait, and the device stays pending.
* **Nothing is redirected.** The answer pages say to return to the other device (approved) or that it was not let in
  (denied), and carry no form; the device learns the answer by polling (ADR-0804).

### Positive Consequences

* A user who reads the first line of the page knows what they are approving.
* A code seen by a second person cannot be answered behind the first user's back, and a walked-away browser holds it
  for two minutes at most.

### Negative Consequences

* A user who takes more than two minutes to type the password while someone else types the same code loses the
  sign-in and starts again from the code.
* The warning cannot stop a user who approves anyway.

## Links

* [ADR-0788](0788-the-oauth-browser-binding-is-one-host-cookie-and-the-pending-identifier-is-the-form-token.md),
  [ADR-0802](0802-the-legacy-sso-redirect-hands-off-to-the-built-in-pages-confirms-and-mints-a-30-second-login-token.md),
  [ADR-0804](0804-the-device-authorization-grant-answers-rfc-8628-and-a-redeemed-device-code-is-expired.md),
  [ADR-0805](0805-device-authorisations-and-user-codes-are-held-in-memory-capped-and-guessing-is-throttled-per-address.md)
* RFC 8628 sections 3.3 and 5.4
