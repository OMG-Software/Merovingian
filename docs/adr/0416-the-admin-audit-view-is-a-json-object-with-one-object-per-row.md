# The admin audit view is a JSON object with one object per row

* Status: accepted
* Date: 2026-11-03

Technical Story: security audit run 2, finding F-62 (`obs.admin-audit-summary-unescaped-field-concatenation`)

## Context and Problem Statement

`GET /_merovingian/admin/audit` answered one `text/plain` line: `audit events=<n>`, then
` entry=<category>:<event_type>:<actor>:<target>:<reason>` for every retained row, with nothing escaped.
A failed login records the client's claimed user ID as the actor and its device ID as the target, and
the caller is unauthenticated. Spaces, `:` and `=` survive the field bounding (`bounded_utf8`,
`sanitized_audit_target`), so one `login.rejected` row could be rendered as several well-formed entries,
among them a fabricated `auth:auth.login:@admin:...:accepted`. The stored rows were never wrong; the
view was ambiguous.

## Decision Drivers

* An audit row must read as exactly one entry whatever its fields contain.
* The fields are text chosen by unauthenticated callers, so the view must not rely on every writer
  filtering its input.
* The safety-report listing (`safety_reports_json`) already serialises the same columns as JSON.

## Considered Options

* Escape ` `, `:` and `=` in the text line
* Keep the text line and reject delimiters at the writers
* Render a JSON object: counts and filters as members, `entries` as an array with one object per row

## Decision Outcome

Chosen option: "render a JSON object". `admin_audit_summary` builds `{"audit_events":<n>,
["evicted":<n>,] ["filter_category":..., "filter_event_type":...,] "entries":[{"category", "event_type",
"actor", "target", "reason"}, ...]}` with the canonical JSON serializer, and the route answers
`application/json`. JSON string quoting is the one escaping rule a reader needs, and a field's text can
no longer start another entry. A field that could not be written as a JSON string (not valid UTF-8,
which the writers already prevent) turns the whole answer into `{"error":...}` rather than a view with
rows missing.

A failed login also records the claimed user ID and device ID as audit actor and target only when they
are well-formed identifiers (`audit_claimed_user_id`, `audit_claimed_device_id` in `auth_service.cpp`);
otherwise a fixed marker is recorded. The client's answer is the same either way. This narrows what an
unauthenticated caller can put into a durable row; it is not what makes the view safe.

### Positive Consequences

* Delimiter forgery is impossible by construction, for every present and future writer.
* The view is machine-readable.

### Negative Consequences

* A script that parsed the old text line must change. Nothing in the repository did.
* The record of a failed login no longer shows a malformed claimed identifier; the diagnostic log line
  (one field value) still does.

## Pros and Cons of the Options

### Escape the delimiters in the text line

* Good, because the format stays the same for well-behaved rows.
* Bad, because every reader has to implement the escaping, and a missed character brings the forgery back.

### Reject delimiters at the writers

* Bad, because the view's safety would depend on every call site, present and future, that records
  client text.
* Bad, because a valid user ID contains `:`.

## Links

* Refines the AUTH-1 bounding rules in [ADR-0080](0080-rate-cap-audit-rows-for-unauthenticated-rejections.md)
