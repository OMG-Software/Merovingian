# build.py vm syncs the working tree over ssh and runs build-linux.sh

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-14

Technical Story: build and test on a Linux VM instead of WSL, and on a FreeBSD VM from the same machine

## Context and Problem Statement

Windows development built and tested through `python build.py wsl`, on the NTFS-backed `/mnt/c` checkout. That path
needs its own workarounds (`build-wsl.sh`'s curl and `make` shim handling, ADR-0158's line endings) and shares the
Windows host's memory with the editor and agents. The owner wants builds and tests on a Linux VM instead. The VM runs
under Hyper-V, but the developer account is not in Hyper-V Administrators, so the Hyper-V PowerShell API (`Get-VM`,
PowerShell Direct) is unavailable. Only ssh over the network reaches it. How does a Windows checkout, with uncommitted
edits, get built and tested there, with results that the verification rules in `AGENTS.md` can read?

## Decision Drivers

* Uncommitted work has to be tested; that is what a local run is for.
* Several worktrees, and several sessions, build from the same machine; one run must not overwrite another's sources
  or its results, and two full suites at once time out unrelated tests.
* The verification rules read `<builddir>/meson-logs/testlog.txt`; a stale log read as a fresh result is a false pass.
* The host is reached over the network, so its identity must be checked and nothing may prompt in an unattended run.
* Windows has Python, Git and OpenSSH, but no rsync.

## Considered Options

* ssh plus a tar stream built by `build.py`, with a manifest for incremental sync
* rsync over ssh
* `git push` to a repository on the VM, then check out there
* A shared folder (SMB or Hyper-V file share) mounted on the VM
* Hyper-V PowerShell Direct

## Decision Outcome

Chosen option: "ssh plus a tar stream built by `build.py`", because it needs nothing on Windows that a checkout does
not already have, carries uncommitted edits, and keeps the build on the VM's own file system.

The rules this sets, each of which the code depends on:

* **What is sent.** Every tracked file as on disk, with Git's mode, and every untracked file Git does not ignore,
  except under a top-level name starting with `build` or `.`. The `--builddir` must therefore start with `build`, so
  the logs copied back are never sent. A symbolic link or submodule is refused, not followed.
* **Incremental sync.** The VM keeps `.vm-sync/manifest` (mode, size, mtime, path). Only files that differ are sent;
  files the old manifest lists and the new one does not are deleted before the archive is unpacked (so a file that
  became a directory, or the reverse, cannot block it), never a path that is absolute or contains `..`, and any
  directory that leaves empty goes too. A stale path that is now a real directory is left alone: only an interrupted
  sync that already unpacked files into it can make one, and the archive fills it again. Before anything is deleted
  or unpacked, the run zeroes the mode, size and mtime of every manifest line but keeps its path, so after an
  interruption no file is listed as present and current, yet the stale list the next run plans still names
  everything an earlier run sent. Deleting the manifest instead was rejected: a later run would then never delete
  the files the interrupted run had left. The new manifest arrives last in the archive and is installed only after
  extraction succeeds, so an interrupted sync resends what it missed.
* **The baseline is checked under the lock.** `build.py` reads the manifest, plans against it, and sends its SHA-256
  with the run; the remote script compares it once it holds the lock. If another run changed the manifest in between,
  the script touches nothing, leaves a marker in its run directory and exits 75, and `build.py` reads the manifest
  again and resends, three times at most. Reading the manifest inside the locked session instead was rejected: the
  archive would have to be planned mid-session over one ssh channel, a framing protocol the hash check does not need.
  The marker, not the exit status alone, says to retry, so an `--exec` command that exits 75 is not run again.
* **Isolation.** One VM-side checkout per local checkout, named after its directory and a hash of its full path, and
  one lock (`~/merovingian-vm/.lock`) held across sync, build and test for every run from every checkout.
  The lock is in the ssh user's home, so it orders the runs of one VM user; every developer and agent using a VM
  shares one VM user. A shared lock in `/tmp` was rejected: another local user could pre-create or replace it.
* **The lock is `flock(2)` taken through `python3`'s `fcntl`**, on a descriptor the remote shell holds open for the
  whole run. `flock(1)` was rejected because FreeBSD, OpenBSD and NetBSD do not ship it; `lockf(1)` because Linux
  does not, and because it locks only for the one command it runs. Both lock kinds are `flock(2)`, so a run with the
  older `flock(1)` script and a run with this one still exclude each other.
* **Results.** `build-linux.sh`, not `build-wsl.sh`, runs on a Linux VM: the NTFS workarounds have nothing to work
  around there. The remote host picks its build script from `uname -s`: `build-linux.sh` on Linux, `build-bsd.sh` on
  FreeBSD, OpenBSD, NetBSD and DragonFly, and any other system is refused, never built with a guessed script.
  Before a run that tests, both the local and the VM's `testlog.txt` and `testlog.json` are deleted, the VM's before
  anything is unpacked, so a run that fails before testing leaves no log. Still under the lock, the run copies its logs into `.vm-sync/run-<token>/`, a directory named by a random token of its own, and `build.py`
  fetches them from there and then deletes it: a run that takes the lock as soon as this one releases it cannot
  replace or delete them first. The exit status is the build's.
* **Host identity.** ssh runs with `StrictHostKeyChecking=yes` and `BatchMode=yes`: an unknown or changed host key
  stops the run, and nothing prompts. Settings come from flags, then `MEROVINGIAN_VM_*`, then
  `~/.config/merovingian/vm.ini`, outside the repository, so no host address is committed. A host or user that ssh
  could read as an option is refused.
* **Named VMs.** `--vm <name>` (or `MEROVINGIAN_VM_NAME`) reads the `[vm.<name>]` section and nothing from `[vm]`, so
  a named VM never inherits the default VM's host or key; a name with no section is an error, not a fallback. Its
  default build directory is `build-vm-<name>`, so each VM's copied-back logs have their own place locally.
* **Memory.** Without `--jobs`, a run uses one compile job and one test process per 1.5 GiB of VM memory
  (`/proc/meminfo` on Linux, `sysctl hw.physmem` on the BSDs), at most one per CPU, through the `--jobs` option this
  adds to `build-linux.sh` and `build-bsd.sh`; Meson's default of one per CPU runs a small VM out of memory.
* **Forwarded options.** `build.py` passes the build scripts only options they parse; `test_build_vm.py` runs
  both scripts with `--hardening` and `--jobs` and checks what reaches Meson, so an option one script refuses fails
  there, not on a developer's VM.
* **The VM is not CI.** A VM run meets what a root CI job does not: a non-root user, and a host where a package
  installed the system config. A smoke test that is not about the defaults passes `--config` with the example
  config; the one test of the defaults skips (exit 77) when a system config exists; and the live-binary startup
  test accepts the unsandboxed worker off Linux, as the startup hardening gate does (ADR-0041).
* **Setup.** `scripts/remote-host-setup.sh` prepares the remote host: on the Debian family, Meson 1.11+ in a virtual
  environment in `~/.local/bin`, which `build.py vm` puts first on `PATH`; on FreeBSD, the FreeBSD CI job's packages
  from `pkg`, whose Meson is current, plus `python3` for the lock. A VM without `python3` cannot be synced, so the
  script is copied over and run on its own before the first sync. `scripts/wsl-setup.sh` stays for WSL only.

### Positive Consequences

* A full suite runs on Linux-native ext4 with the VM's memory, from any worktree, without WSL.
* The local `build-vm/meson-logs/testlog.txt` is read exactly as any other build's log.

### Negative Consequences

* If ssh drops mid-run, the build keeps running on the VM and holds the lock until it ends.
* Test binaries stay on the VM; a tag-filtered run goes through `build.py vm --exec`.
* An mtime-and-size manifest misses a change that keeps both, such as an edit within the same second that keeps the
  size; `--clean` does not help there, but touching the file does.

## Pros and Cons of the Options

### ssh plus a tar stream built by build.py

* Good, because it needs only Python's `tarfile` and the OpenSSH client Windows ships.
* Good, because it sends uncommitted edits and only what changed.
* Bad, because `build.py` owns a small sync protocol, covered by `build-vm-tooling`.

### rsync over ssh

* Good, because it is the standard tool for the job.
* Bad, because Windows has no rsync; Git for Windows does not ship it, and a Cygwin or MSYS2 copy maps paths and
  modes in its own way.

### git push to a repository on the VM

* Good, because Git already moves exactly the tracked content.
* Bad, because it sends only commits, so every test run would need a commit, and untracked new files would be missed.

### A shared folder mounted on the VM

* Good, because nothing is copied.
* Bad, because the build would again run on a network or foreign file system, the problem WSL's `/mnt/c` has.

### Hyper-V PowerShell Direct

* Good, because it needs no network or ssh key.
* Bad, because it needs Hyper-V Administrators rights, which the developer account does not have, and works only for
  a VM on the same Windows host.

## Links

* Related to [ADR-0158](0158-check-out-every-text-file-with-lf-endings.md), the line endings the sync relies on
* Related to [ADR-0546](0546-ci-fails-on-a-catch2-skip-its-job-does-not-list.md); `build.py vm` passes no
  `--skip-job`, so its runs are not skip-gated
