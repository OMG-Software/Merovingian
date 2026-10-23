# Retry failed push notifications from a bounded in-memory queue on one job thread

* Status: accepted
* Date: 2026-10-22

Technical Story: conformance audit 2026-10-17, finding R14 (failed push notifications are never
retried)

## Context and Problem Statement

Push Gateway API: "If the endpoint returns an HTTP error code, the homeserver SHOULD retry for a
reasonable amount of time using exponential backoff." Each notification was sent once, from a
background task (ADR-0010), and a failure was only logged. A retry must not ride on a client
request, must not hold `runtime.mutex` across the network call, must keep the existing delivery
caps (ADR-0028, ADR-0029) and the gateway circuit breaker (ADR-0151) meaningful, and must stop for
a pushkey the gateway rejects.

## Considered Options

* A bounded in-memory queue (`push::PushRetryQueue`) drained by one `PeriodicJob` thread
* Sleep and retry inside the delivery task
* A durable queue table, drained like the appservice outbox (ADR-0163)

## Decision Outcome

Chosen option: the in-memory queue and one job thread.

* Every attempt, first or retry, goes through `homeserver::attempt_push_delivery`. A gateway that
  answers with a non-2xx status, or cannot be reached, gets the notification again; one that
  accepts it, a URL or response this server refuses, and disabled delivery do not
  (`push::push_delivery_should_retry`). A gateway whose circuit is open is not contacted, and the
  skipped notification is retried like a failed one.
* Backoff: 5 seconds after the first failure, doubling to at most 10 minutes. After 8 retries
  (about 20 minutes) the notification is given up and logged (`push.delivery.gave_up`).
* A pushkey the gateway rejects, on any attempt, loses its pusher and every queued retry to that
  (app ID, pushkey): "Homeservers must cease sending notification requests for these pushkeys".
  A retry whose pusher was removed, or now points at another URL, is dropped without sending.
* The queue holds at most 1024 notifications, and 32 per recipient. A retry past either bound is
  dropped and logged (`push.delivery.retry_dropped`), as deliveries past the in-flight cap are
  (ADR-0028). A notification carries the event's content, so the bound is on memory as well as
  work.
* `PushRetryJob` (from `main.cpp`) sends at most 32 due retries per run, one at a time, and sleeps
  until the next one is due. Scheduling a retry wakes it. It takes `runtime.mutex` only to check
  the pusher and to delete a rejected one, never across `notify`.
* A retry is the same notification: same event ID, which gateways use for duplicate suppression
  ("perform duplicate suppression for such notifications using the event_id field"), and the
  counts it carried the first time.

### Positive Consequences

* A brief gateway outage no longer loses notifications.
* Retries never compete with first deliveries for the in-flight budget, and never run on a
  request thread.

### Negative Consequences

* Queued retries are lost on restart. A notification that has waited through a restart is
  usually stale; the event still reaches the user through `/sync`.
* Retries are sent one at a time, so a slow gateway delays the retries queued behind it, by at
  most the gateway client's timeout each. The circuit breaker skips hosts that keep failing.

## Pros and Cons of the Options

### Sleep and retry inside the delivery task

* Good, because it needs no queue.
* Bad, because a sleeping task holds an in-flight delivery slot, so a failing gateway would block
  new notifications for every user, and shutdown would wait out the backoff.

### A durable queue table

* Good, because retries would survive a restart.
* Bad, because it needs a migration and stores message content at rest a second time, for
  notifications that are stale by the time a restart has finished.

## Links

* Related to [ADR-0028](0028-drop-push-deliveries-at-the-concurrency-cap.md) (drop at the cap)
* Related to [ADR-0151](0151-cap-pusher-registration-and-break-the-circuit-to-failing-gateways.md) (gateway circuit breaker)
* Related to [ADR-0163](0163-appservice-delivery-is-a-durable-outbox-drained-by-one-thread.md) (a durable queue, for comparison)
