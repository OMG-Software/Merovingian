# Media is scanned by a local clamd over INSTREAM, and any failure keeps it quarantined

* Status: accepted
* Deciders: repository owner
* Date: 2026-11-07

Technical Story: G15, optional malware scanning of media.

## Context and Problem Statement

Before this the only scan was the EICAR test-signature check on local uploads, and remote media was stored with `scanner_clean` false. An operator who runs ClamAV had no way to use it. How should a real scanner be added without a new library, a new network exposure, or a way for a scanner problem to let unscanned media through?

## Decision Outcome

`media::ClamdScanner` speaks clamd's `zINSTREAM` command over the AF_UNIX socket named by `security.media.clamd_socket_path`. It is off while that key is empty, and the default is empty. One deadline (`clamd_timeout_ms`) covers connect, send and reply. `stream: OK` is clean and `stream: <name> FOUND` is infected; every other outcome (connect failure, timeout, ERROR or malformed reply, a reply without its NUL terminator, no scan capacity before the deadline, media above `clamd_max_scan_size`) is a verdict that is not clean. The caller passes `scanner_clean=false` for it, and the existing policy then quarantines the media.

The scan runs only for media whose acceptance policy is `allow-after-scan` (local uploads: `local_upload_policy`; remote media: `remote_fetch_media_policy`). Under `allow` the repository ignores the verdict by definition, and under `quarantine` and `deny` the outcome is fixed, so asking clamd would only cost time. Remote media keeps `scanner_clean=false` when no scanner applies, exactly as before; with the default `quarantine` policy remote media stays held for review, and clamd matters only once an operator relaxes that to `allow-after-scan`. The EICAR check stays and is tried first: a file it refuses is not sent to clamd.

The scan always runs with `runtime.mutex` released (`RuntimeLockRelease`), in `homeserver::clamd_media_cleared`. At most `clamd_max_concurrent` scans are in flight; a further scan waits for a place until its own deadline and then fails closed. `clamd_socket_path` requires `enable_av_scanner=true`, because with it off the repository forces the verdict clean.

## Rejected alternatives

* Treating a clamd failure as clean or as "skip the scan": turns an outage or a hostile slow clamd into a bypass.
* Reaching clamd over TCP: a new network exposure and a new SSRF-style surface; clamd's local socket needs neither.
* Scanning under `allow`: the policy name promises no scan.
* Waiting for capacity without a bound: lets a slow clamd hold every request thread.

## Consequences

* Media between `clamd_max_scan_size` (default 25 MiB, clamd's usual StreamMaxLength) and `max_upload_size` (default 50 MiB) is never scanned and stays quarantined; startup logs a warning when the scan limit is lower.
* Under `allow-after-scan` the quarantine from a failed scan is an ordinary quarantined record that an administrator can release.
