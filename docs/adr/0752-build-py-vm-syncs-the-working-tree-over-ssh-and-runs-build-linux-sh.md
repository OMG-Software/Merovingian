# build.py vm syncs the working tree over ssh and runs build-linux.sh

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-14

Technical Story: build and test on a Linux VM instead of WSL

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
  files the old manifest lists and the new one does not are deleted, never a path that is absolute or contains `..`.
  The new manifest arrives last in the archive and is installed only after extraction succeeds, so an interrupted
  sync resends what it missed.
* **Isolation.** One VM-side checkout per local checkout, named after its directory and a hash of its full path, and
  one lock (`~/merovingian-vm/.lock`, `flock`) held across sync, build and test for every run from every checkout.
* **Results.** `build-linux.sh`, not `build-wsl.sh`, runs on the VM: the NTFS workarounds have nothing to work
  around there. Before a run that tests, both the local and the VM's `testlog.txt` and `testlog.json` are deleted,
  then copied back after it, so a build that fails before testing leaves no log. The exit status is the build's.
* **Host identity.** ssh runs with `StrictHostKeyChecking=yes` and `BatchMode=yes`: an unknown or changed host key
  stops the run, and nothing prompts. Settings come from flags, then `MEROVINGIAN_VM_*`, then
  `~/.config/merovingian/vm.ini`, outside the repository, so no host address is committed. A host or user that ssh
  could read as an option is refused.
* **Memory.** Without `--jobs`, a run uses one compile job and one test process per 1.5 GiB of VM memory, at most one
  per CPU, through the `--jobs` option this adds to `build-linux.sh`; Meson's default of one per CPU runs a small VM
  out of memory.
* **Setup.** `scripts/remote-host-setup.sh` prepares the remote host (Debian family, Meson 1.11+ in a virtual
  environment in `~/.local/bin`, which `build.py vm` puts first on `PATH`). `scripts/wsl-setup.sh` stays for WSL only.

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
