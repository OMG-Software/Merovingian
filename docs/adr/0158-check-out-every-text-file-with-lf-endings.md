# Check out every text file with LF endings on every platform

* Status: accepted
* Date: 2026-10-16

Technical Story: a full `python build.py wsl` run in a worktree created by Windows Git failed one unit
scenario ("The systemd unit confines address families and kernel interfaces") because the unit file
had been written with CRLF.

## Context and Problem Statement

Windows Git installs with `core.autocrlf=true` in its system configuration. Unless an attribute says
otherwise, it writes every text file into the working tree with CRLF. The repository stores LF and its
`.gitattributes` named only `*.sh` (LF) and `*.ps1`/`*.cmd` (CRLF), so everything else followed the
local setting. The project is built and tested under Linux, WSL and the BSDs from that working tree:

* tests read files as text and match exact lines (the systemd unit scenario searches for
  `"\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n"`, which a CRLF file never contains);
* packages ship files straight from the checkout, so a deb or RPM built from a CRLF tree would carry
  CRLF unit files and maintainer scripts, which systemd and `/bin/sh` misread;
* an edit made through a Windows tool can leave a file half CRLF, half LF.

Whether a run passed depended on how the checkout was made, not on the code.

## Considered Options

* **`* text=auto eol=lf` for the whole tree, with `*.ps1` and `*.cmd` kept CRLF (chosen).**
* Force LF only under `packaging/`. Rejected: the systemd unit was the first failure, not the only
  exposure. Tests also read C++ sources, docs and SQL as text, and the same trap would stay for each of
  them.
* Make the tests tolerate `\r`. Rejected: it hides the problem from the tests while packages still ship
  CRLF.
* Ask developers to set `core.autocrlf=false`. Rejected: a per-machine setting is exactly what failed;
  the repository has to carry the rule.

## Decision Outcome

Chosen option: `.gitattributes` begins with `* text=auto eol=lf`. Git still detects binaries
(`text=auto`) and leaves them alone. `*.ps1` and `*.cmd`, which only Windows runs, keep CRLF. The index
was already LF throughout, so the change rewrites no stored file.

`tests/tooling/test_line_endings.py` checks the rule through `git ls-files --eol`: every tracked text
file carries `eol=lf`, the Windows scripts carry `eol=crlf`, and nothing is stored with CRLF. Do not
narrow the rule to a directory, and do not drop it in favour of `core.autocrlf` advice.

### Positive Consequences

* A checkout behaves the same on every platform; the suite's result no longer depends on it.
* Packages built from a Windows-made checkout ship LF files.

### Negative Consequences

* Checkouts made before the change keep their CRLF files until they are checked out again
  ([dev-environment.md](../dev-environment.md#line-endings) gives the command).
* The test skips where Git cannot read the checkout (a Windows-created worktree opened from WSL). CI
  checks out on Linux, where it always runs.
