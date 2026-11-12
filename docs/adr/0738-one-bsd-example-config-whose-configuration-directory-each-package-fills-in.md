# One BSD example config whose configuration directory each package fills in

* Status: Accepted
* Date: 2026-11-12

Technical Story: the FreeBSD, OpenBSD and NetBSD packages installed the Linux example as their
`merovingian.conf.sample`, so its secret files pointed at `/etc/merovingian` and its SQLite path at
`/var/lib/merovingian`, neither of which the FreeBSD or NetBSD package uses.

## Context and Problem Statement

The three BSD packages agree on every state location: the service user's home and the SQLite directory is
`/var/db/merovingian` (hier(7) on each system), and the rc.d scripts create `/var/db`, `/var/log` and
`/var/run/merovingian`. Media is stored in the database, so there is no media directory. They differ only in the
configuration directory, which is each build's Meson `--sysconfdir` and the directory the binary reads its default
config from (`MEROVINGIAN_SYSCONFDIR`): `/usr/local/etc` on FreeBSD (ports `PREFIX/etc`), `/etc` on OpenBSD (ports
`SYSCONFDIR`), and `/usr/pkg/etc` on NetBSD (pkgsrc `PKG_SYSCONFDIR`). The example is about 900 lines and gains keys
often. How should the BSD packages get a config with their own paths?

## Decision Drivers

* Each package's sample must name the directory its rc.d script reads and its user's home, with no edit.
* A key added to the Linux example must not silently go missing from the BSD one.
* The owner asked for a BSD example file in the repository.

## Considered Options

* One BSD file, `config/merovingian.conf.bsd.example`, with an `@SYSCONFDIR@` placeholder each package fills in
* One file per BSD with literal paths
* No BSD file: rewrite the Linux example's paths with `sed` at package time
* One BSD file with FreeBSD's literal paths, rewritten for OpenBSD and NetBSD

## Decision Outcome

Chosen option: "One BSD file with an `@SYSCONFDIR@` placeholder", because the systems differ in exactly one directory,
and that directory is already a build parameter of each package. Each build script fills the placeholder with the
`--sysconfdir` it passes to Meson and fails if a placeholder is left; the pkgsrc recipe fills it with
`PKG_SYSCONFDIR` (`SUBST_SED`), the same way `packaging/netbsd/files/merovingian.sh` uses `@PKG_SYSCONFDIR@`, and the
OpenBSD port with `SYSCONFDIR`.

The BSD file is the Linux example below a comment-only header, with three mappings: `/etc/merovingian/` becomes
`@SYSCONFDIR@/merovingian/`, `/var/lib/merovingian/` becomes `/var/db/merovingian/`, and the commented
`security.media.clamd_socket_path` names no socket, because FreeBSD and OpenBSD refuse clamd at startup (ADR-0566) and
NetBSD does not start (ADR-0378). `tests/tooling/test_example_config.py` applies those mappings to the Linux example
and requires the result to equal the BSD file, so a change to one example fails until it is made to both.

The BSD file keeps the Linux example's security settings, including `federation.worker.apply_hardening=true`. On
FreeBSD and OpenBSD that worker refuses to start (ADR-0041). The header names the operator's two choices, and the file
makes neither of them, because weakening the sandbox is not a default an example may pick.

### Positive Consequences

* A packaged sample names the right paths on every BSD, and the user manual no longer needs a `sed` step.
* The drift test turns "add the key to both examples" from a convention into a failing check.

### Negative Consequences

* The source file is not a working config as it stands: `@SYSCONFDIR@` must be filled in first. Its header says so,
  and `scripts/validate-phase1-config.sh` dry-runs it filled in as FreeBSD's package fills it.
* A change to the Linux example must be repeated in the BSD file by hand.

## Pros and Cons of the Options

### One file per BSD with literal paths

* Good, because each file works as it stands.
* Bad, because three 900-line copies must be kept in step with the Linux example, where the only difference is one
  directory.

### No BSD file: rewrite the Linux example's paths at package time

* Good, because nothing is duplicated.
* Bad, because the owner asked for a BSD file, and a reader of the repository cannot see what a BSD package ships.
* Bad, because packaging would depend on how the Linux example happens to spell its paths.

### One BSD file with FreeBSD's literal paths, rewritten for OpenBSD and NetBSD

* Good, because the file works as it stands on FreeBSD.
* Bad, because a rewrite of `/usr/local/etc` cannot be told apart from an unrelated path that shares the prefix, and a
  missed path leaves a FreeBSD directory in an OpenBSD or NetBSD sample with no error. A placeholder that is left
  behind is detected.

## Links

* Relates to [ADR-0041](0041-refuse-to-start-the-federation-worker-unsandboxed.md)
* Relates to [ADR-0378](0378-probe-elf-hardening-in-memory-and-keep-netbsd-refused.md)
* Relates to [ADR-0566](0566-the-clamd-socket-is-refused-at-startup-where-the-sandbox-forbids-connecting-to-it.md)
