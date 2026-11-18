# The CI host fetches and caches NetBSD packages, and the VM installs them locally

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-18

## Context and Problem Statement

`netbsd-build-and-test` took 147 minutes, about 100 of them installing packages inside the `vmactions/netbsd-vm` guest. The
log shows some 30 pauses of about 3 minutes each after `Trying to reconnect https://cdn.netbsd.org/…`, each followed by a
`pkg_add` retry. The guest downloads through QEMU's user-mode network, and `cdn.netbsd.org` stalls on `.tgz` downloads while
`ftp.netbsd.org` answers in seconds. The NetBSD package job in `packages.yml` (93 minutes) installs the same way.

## Considered Options

* Keep installing from the mirrors inside the guest, with shorter timeouts.
* Cache the guest's installed `/usr/pkg` tree and restore it into the next VM.
* Resolve and download the packages on the Linux host, cache the files, and have the guest's `pkg_add` read them from the
  synced workspace before the mirrors.

## Decision Outcome

Chosen: the host fetches. `scripts/fetch-netbsd-packages.py` reads the release's `pkg_summary` over HTTPS, resolves the
DEPENDS closure of the job's package list, and downloads what the cache lacks, moving a stalled mirror to the back of the list.
Every file, restored or downloaded, is checked against `FILE_SIZE`, against `FILE_CKSUM` when the repository publishes one, and
by reading its whole compressed stream. A cached file that fails is downloaded again; a download is tried on each mirror in turn, and a file no mirror serves verified fails the step. The lockfile of resolved
names keys `actions/cache`. The guest runs `pkg_add` with `PKG_PATH` set to that directory alone, and only if that fails
again with the directory first and a mirror second, so a package the resolver missed still installs, more slowly, instead of
failing. Listing the directory before the mirrors is not enough by itself: `pkg_add` searches every `PKG_PATH` entry and
keeps the best match, so each package would still cost a mirror lookup. The package list, release and architecture are set once per
job and passed to the host script, the cache key and the guest; the VM's `release:` is pinned to match.

Each lockfile line is `<FILE_NAME> <FILE_SIZE> <FILE_CKSUM or ->`, so the cache key changes when a size or checksum does. A
package with no `FILE_SIZE` is refused. A file that fails verification moves the download to the next mirror. Packages marked
`--optional` (gdb) are best-effort: a failure to fetch one does not fail the step, and the lockfile is rewritten without it,
so the cache is never saved under the key of a set it does not hold. A summary, cached or downloaded, is usable only when it
decodes to at most 256 MiB, lists every required package and gives a `FILE_SIZE` for every package in their closure;
otherwise the next mirror's is tried. Of the usable ones, the first whose required closure resolves completely is used; when
none does, the first usable one is, with a warning naming what the guest must take from the mirrors. Version order follows
`pkg_install`'s `dewey.c`, case-insensitive like it. HTTPS redirects to any host are followed, as `pkg_add` does.

Only `main` saves the cache. NetBSD 11.0's repository publishes no `FILE_CKSUM`, so a restored file is checked for its size and
stream only; with saves limited to `main`, no other ref can write an entry that `main` or the merge queue restores.
The residual risk is a package replaced under the same name with the same size, which the cache would keep. Nothing here
authenticates an archive beyond what `pkg_add` did before.

Rejected:

* **Shorter timeouts in the guest.** The guest still pays for a slow network on every file, and a stalled mirror still costs a
  timeout per package.
* **Caching `/usr/pkg`.** It restores installed files and the package database with nothing to verify them against, and it
  goes stale silently when the repository moves.

## Consequences

* A cache miss downloads about 255 MiB on the host, from a mirror that answers, in minutes.
* If the guest cannot see the directory, or its release or architecture differs, it says so and installs from the mirrors as
  before.
* A package added to the job's list is resolved and cached on the next run; nothing else needs editing.
