# Email pushers mail only the account's own addresses, an unread count, in a delayed digest

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-24

Technical Story: email pusher delivery (0.12.44)

## Context and Problem Statement

Matrix v1.19 defines `kind: "email"` for `POST /_matrix/client/v3/pushers/set` as "a pusher
that emails the user with unread notifications", whose `pushkey` "is the email address to send
notifications to". That is all it says. Which addresses may be named, what an email contains and
how often one is sent are left to the server. Until 0.12.44 this server had no email transport and
refused the kind outright (0.12.3). With an SMTP relay now configurable, each of those three
questions needs an answer that a later change could otherwise undo by accident.

## Decision Drivers

* Security first: the server must not become a relay that any account can point at a stranger's
  inbox.
* Message content leaves the server's control once it is handed to a mail relay, and it stays in
  mailboxes, backups and mail-provider indexes.
* An email per message floods an inbox, and the user cannot take back one already sent.

## Considered Options

Recipients:

* Any address the client names.
* Only an email 3PID already on the account, checked at registration and again before each send.

Content:

* The unread count only.
* Room names, sender names and the unread count per room.
* Message bodies too, from unencrypted rooms.

Cadence:

* One email per notifying event, sent at once.
* A delayed, throttled digest.

## Decision Outcome

Chosen:

* **Recipients: the account's own email 3PIDs only.** `POST /pushers/set` refuses `kind: "email"`
  with 400 `M_INVALID_PARAM` unless the `pushkey` (compared case-insensitively) is an email
  address in the account's `account_threepids`. A 3PID gets there only through a validation its
  owner completed. The email job checks again before every send. A pusher whose address has left
  the account is deleted rather than sent to. `POST /account/3pid/delete` deletes the email
  pushers for the address it removes. A deactivated account is never mailed.
* **Content: the unread count and the server name.** For example, "3 unread notifications on
  example.org". No room, sender or message text. The count is the Push Gateway badge count
  (ADR-0207), taken when the email is sent, so it is already judged by history visibility and
  push rules.
* **Cadence: a delayed, throttled digest.** A notification schedules an email
  `server.email.notification_delay_seconds` later (default 600). The email is never sooner than
  `notification_throttle_seconds` (default 3600) after the last one to that pusher. Further
  notifications fold into the email already due. An email that finds nothing unread when it falls
  due, because the user read everything on another device, is not sent.

The digest queue (`push::EmailDigestQueue`) is in memory only, as the push retry queue is
(ADR-0206). A restart forgets emails that were due and the throttle history. That means at most
one email is lost or one arrives sooner than the throttle would allow, and every notification is
still in `GET /notifications`. The queue holds at most 4096 pushers. A notification past that is
dropped and logged, as push deliveries past their caps are (ADR-0028).

### Positive Consequences

* No account can make this server send mail to an address its owner did not prove they hold.
* Nothing a user was sent passes through a mail relay or sits in a mailbox.
* A burst of messages produces one email, and reading them anywhere cancels it.

### Negative Consequences

* The email cannot say which room or who, so the user must open a client to find out.
* An email pusher requires the address to be added as a 3PID first. That in turn requires an
  identity server (AUTH-5: this server sends no validation email itself).
* A restart can drop one due email per pusher.

## Pros and Cons of the Options

### Any address the client names

* Good, because it is all the spec text requires.
* Bad, because any account (including one registered by a spammer) can make the server mail
  arbitrary addresses, and the server's sending reputation pays for it.

### Room names, sender names and per-room counts

* Good, because the email is more useful.
* Bad, because room names and display names are user-chosen content and can be sensitive. They
  would leave the server for every pusher.

### Message bodies from unencrypted rooms

* Good, because it matches what some other homeservers send.
* Bad, because message content is copied into third-party infrastructure that this server cannot
  delete from.

### One email per notifying event

* Good, because it is simple and immediate.
* Bad, because it floods the inbox and cannot be cancelled by reading on another device.

## Links

* Builds on [ADR-0207](0207-saturate-the-push-badge-unread-count.md) (the unread count it
  reports) and [ADR-0206](0206-retry-failed-push-notifications-from-a-bounded-in-memory-queue.md)
  (the in-memory, one-job delivery shape).
* Same drop policy as [ADR-0028](0028-drop-push-deliveries-at-the-concurrency-cap.md).
* Transport: [ADR-0220](0220-smtp-goes-through-libcurl-with-tls-required-except-to-a-loopback-literal.md)
