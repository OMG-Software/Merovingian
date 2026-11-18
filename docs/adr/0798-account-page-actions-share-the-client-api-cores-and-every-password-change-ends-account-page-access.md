# Account-page actions share the client API's cores, and every password change ends account-page access

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 8 of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md)

## Context and Problem Statement

The account pages (ADR-0796) sign out a device, change the password and deactivate the account. The client API does
the same through `DELETE /devices/{deviceId}`, `POST /account/password` and `POST /account/deactivate`, each with
bookkeeping that is easy to forget: device-list announcements, pusher removal, 3PID unbinds, login tokens. And
`change_local_user_password` keeps the calling device, which a page does not have. What does each page action call,
and what does a password change do to the user's other sessions?

## Decision Drivers

* A second copy of an action drifts from the first; the copy is the one that misses a later fix.
* A password change is what a user does after a compromise: nothing an attacker may hold should survive it.
* A browser left signed in to the pages must not outlive the credential that opened it.

## Considered Options

* Each page action calls the function the client API calls; a session-less password change shares the password
  reset's core and keeps no device; every password change, reset and deactivation ends account-page access.
* Copy the client handlers' steps into the page handler.
* Have the page call `change_local_user_password` with a made-up device.

## Decision Outcome

Chosen option: the first.

* `DELETE /devices/{deviceId}` and the page's device sign-out both call `delete_device_and_announce`
  (`ClientDeviceSessions.hpp`): `remote_servers_for_user`, `delete_local_device`, the runtime's device list,
  `record_shared_room_device_changes` and `announce_deleted_devices`. An OAuth device's `oauth_sessions` row goes with
  it.
* `POST /account/deactivate` and the page's deactivation both call `deactivate_user_account` and then
  `finish_account_deactivation` (login tokens erased, 3PIDs unbound at their identity servers with `runtime.mutex`
  released). The page has no `id_server` and passes none.
* The page's password change is `change_password_on_account_page`, which shares `replace_password_without_device`
  with `reset_local_user_password` (the email reset). It always logs out: every access, refresh and OpenID token and
  every pusher of the account goes, because the page holds no device to keep. Devices are kept (the client API's
  `logout_devices` revokes, it does not delete). The page also erases the user's login tokens. Audited as
  `auth.password_changed` with the reason "changed on the account page; revoked all devices".
* `end_account_page_access` (`AuthService.cpp`) ends every account-page session of the user and withdraws any
  cross-signing reset approval. `change_local_user_password`, `replace_password_without_device` (so both the reset and
  the page change) and `deactivate_user_account` call it on success. A new path that changes a password or closes an
  account calls it too.
* The page re-verifies the current password with `verify_password_login` before a change or a deactivation, and
  re-reads its session after (the check releases `runtime.mutex`).

### Negative Consequences

* After a page password change every client signs in again, including the one the user came from. The page says so.
* An OAuth session's refresh token is revoked by the change while its `oauth_sessions` row and device stay; the client
  must authorise again, which replaces the row.

## Pros and Cons of the Options

### Copy the client handlers' steps

* Bad, because the device-list announcement and the 3PID unbinds would exist twice and drift.

### `change_local_user_password` with a made-up device

* Bad, because it keeps one device's tokens: the page would leave a device signed in that the user never chose.

## Links

* Builds on [ADR-0796](0796-the-account-pages-keep-a-fixed-15-minute-session-in-memory-bound-to-a-strict-cookie-and-a-form-token.md)
  and [ADR-0797](0797-an-oauth-session-replaces-its-cross-signing-keys-through-the-m-oauth-stage-and-a-one-use-approval.md)
