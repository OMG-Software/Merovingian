# Report a failed device-list write where the client can retry, and finish where access is being revoked

* Status: accepted
* Date: 2026-11-02

Technical Story: review of PR #549, `record_shared_room_device_changes` ignored the result of its batched write

## Context and Problem Statement

A device or key change commits, and then the rows that put it in other local users' `device_lists.changed` are written
in a separate transaction. If that write failed, the result was ignored: the client got 200, nothing was logged, and
those users kept a stale device list until the next change. A stale list means an encrypted message can omit a new
device, or trust a key that has been replaced. The spec expects the change to appear in `changed` and says nothing about
a server that fails to record it, so how to fail is ours to choose.

## Considered Options

* Report the failure to the client, which retries
* Write the rows in the same transaction as the change
* Record a durable retry with the change and replay it later
* Log only

## Decision Outcome

Chosen option: "Report the failure to the client, which retries", for key, signature and device-name uploads. Each
overwrites what it stored, so a retry repeats safely and records the rows. The answer is a 500 that says the change was
stored, because the client must not conclude it was undone. Remote servers are told before that answer, since the
change stands either way.

Logout, logout-all and device deletion do not report it. They finish and log `device_list.change_undelivered`, because
refusing or failing them would leave credentials a user is trying to revoke, and a retry finds nothing left to do.

Writing the rows in the same transaction was rejected because the changes are made in several layers: logout and device
deletion commit inside the auth service, which does not compute observers. A durable retry was rejected because it
needs a table, a replay job and its own failure handling, for a write that fails right after the one before it succeeded.

### Positive Consequences

* A failed write can no longer pass unnoticed, and the common cases heal on the client's retry.

### Negative Consequences

* A client that does not retry leaves observers stale until the next change, though it did see the error.
* A logout or device deletion can leave observers stale until the next change. They hold a device that no longer
  exists, and the log line is the only record of it.
