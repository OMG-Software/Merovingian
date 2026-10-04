# Escape log control characters once, at the sink

* Status: accepted
* Date: 2026-10-04

Technical Story: AUTH-9 in [security-audit-report-2026-09-29.md](../security-audit-report-2026-09-29.md)

## Context and Problem Statement

Logged values include client-controlled text, for example a login
`identifier.user` or `device_id`. A JSON `\n` in such a value wrote a second
physical line that looked like a genuine log record, and an ESC or C1 CSI
reached the operator's terminal raw. Log lines are built in several ways:
structured `diagnostic_message` fields, event names, keys, and plain `LOG_*`
message strings. Where should control characters be neutralised, and into
what form?

## Decision Drivers

* No call site may be able to bypass the protection, including future ones.
* A value must be escaped exactly once; double escaping makes logs unreadable.
* Ordinary log text, including UTF-8 and JSON bodies, should read as before.

## Considered Options

* Escape once in `SingleLog::make_log_line`, the one place every console and
  file record is composed (`escape_log_controls`).
* Escape each structured field value, key and event name in
  `diagnostic_message`.
* Additionally escape backslash as `\\`, making the escaping reversible.

## Decision Outcome

Chosen option: escape once in `SingleLog::make_log_line`, without escaping
backslash. It is the only option that covers every write path, including
`LOG_*` macros that never build a `StructuredLogField`, while touching each
byte once.

`\n`, `\r` and `\t` become those escapes, other C0 controls and DEL become
`\xHH`, UTF-8 encoded C1 controls become `\u00HH`, and every other byte passes
through. `redact_log_message`, which runs on the escaped line, treats every
whitespace character as a token boundary so a sensitive last field keeps the
record terminator.

### Positive Consequences

* One log record is one physical line, whatever any caller passes in.
* Call sites need no change and cannot opt out.

### Negative Consequences

* A value that literally contains the characters `\n` looks the same in the
  log as an escaped line feed. The record boundary is still unforgeable;
  only the rendering of that one value is ambiguous.
* Escaping at the sink means helpers such as `diagnostic_message` still return
  raw text. Code that sends those strings somewhere other than `SingleLog`
  must neutralise them itself.

## Pros and Cons of the Options

### Escape in `diagnostic_message`

* Good, because structured output is safe wherever the string is sent.
* Bad, because `LOG_*` macros and the module name bypass it.
* Bad, because adding the sink-level escape later would escape twice.

### Also escape backslash

* Good, because the log becomes unambiguous and reversible.
* Bad, because every backslash in existing log text doubles, notably in JSON
  bodies and diagnostics that quote escaped strings, and it buys no protection
  against record forging.
