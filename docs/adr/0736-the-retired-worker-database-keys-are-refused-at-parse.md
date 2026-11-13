# The retired worker database keys are refused at parse

* Status: accepted
* Deciders: owner (refuse at parse, 2026-11-12), workstream S8
* Date: 2026-11-12

Technical Story: run-3 audit finding C44,
`F-resource-exhaustion.sqlite-worker.read-lock-held-by-compromised-worker-fails-every-main-write`.

## Context and Problem Statement

Since [ADR-0733](0733-the-federation-worker-opens-no-database-main-sends-it-what-it-reads.md) the federation worker
opens no database. Two configuration keys existed only to give it one on PostgreSQL:
`federation.worker.database_uri_file` (a separate SELECT-only login, handed over `--db-uri-fd`) and
`federation.worker.allow_shared_database_credentials` (the opt-out that let it share main's login). 1.0.0 shipped them,
so an operator's configuration may set either. What does the server do with a configuration that still names them?

## Decision Drivers

* An operator who provisioned a worker login should learn that it is no longer used, and can drop the role.
* The configuration must not keep a key that does nothing: a reader would believe it still separates something.
* Nothing in the server may still read the URI file or hand its bytes to a child.

## Considered Options

* Refuse either key at parse, with an error naming the key
* Accept and ignore either key with a warning through 1.0.x, refuse from 1.1
* Accept and ignore silently

## Decision Outcome

Chosen option: refuse at parse (owner, 2026-11-12). Each key gets its own finding naming the key and saying that the
worker no longer opens a database (`config::parse_key_value_config`), so a server whose configuration still sets one does not
start until the line is removed. The rest of the arrangement goes with them: the `--db-uri-fd` argument and fd 5, the
worker's `DbUriFd` reader, `database.worker_conninfo_override`, main's read and validation of the URI file, the PostgreSQL
branch in `WorkerPool` that required it, the Landlock grant of the SQLite directory and the URI file in the worker's
secret list, and `packaging/postgresql/provision-federation-worker-role.sql`. The worker parses the same file, so it
refuses the keys too; `--db-uri-fd` is refused as an unknown argument. `build_worker_landlock_rules` derives no rule
from the database keys at all, so even a configuration that still names main's SQLite file grants nothing.

### Positive Consequences

* One configuration means one thing: no key is accepted that the server no longer acts on.
* main holds no second database credential, and no child is ever handed one.

### Negative Consequences

* A 1.0.0 PostgreSQL deployment with federation enabled set `database_uri_file` (it was required), so upgrading to 1.0.1
  needs the line removed before the server starts again. The error names the line. The worker role and its login can be
  dropped (`DROP ROLE`) once no worker uses it.

## Pros and Cons of the Options

### Accept with a warning through 1.0.x

* Good, because an upgrade starts without an edit.
* Bad, because a key that does nothing reads as a protection that is still there, and the warning is easy to miss.

### Accept silently

* Bad, because the operator never learns that the role they provisioned is unused.

## Links

* Follows [ADR-0733](0733-the-federation-worker-opens-no-database-main-sends-it-what-it-reads.md)
* Supersedes the configuration of part 2 of
  [ADR-0062](0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md)
