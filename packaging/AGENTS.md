# packaging/ — OS Package Definitions

Contains the package metadata and init scripts for each supported OS.

## Contents

| Directory | Platform |
|---|---|
| `deb/` | Debian / Ubuntu `.deb` control files |
| `rpm/` | Generic RPM spec |
| `rhel/` | RHEL / CentOS RPM spec |
| `opensuse/` | openSUSE RPM spec |
| `freebsd/` | FreeBSD port / pkg manifest |
| `netbsd/` | NetBSD pkgsrc files |
| `openbsd/` | OpenBSD port |
| `systemd/` | `merovingian.service` unit file; `merovingian-livekit.service`, the LiveKit SFU's unit, installed disabled (ADR-0859) |
| `openrc/` | OpenRC init scripts: `merovingian` and `merovingian-livekit` |
| `livekit/` | `merovingian-livekit-setup`, which writes the API secret LiveKit and the server share (ADR-0859) |
| `rc.d/` | BSD `rc.d` script |
| `postgresql/` | `provision-roles.sql` — provisions separate migration/runtime PostgreSQL roles for production deployments (the federation worker opens no database and has no role of its own, ADR-0733) |

## Rules

- **Version numbers in package files must match `meson.build`.**
  The version bump checklist in `docs/versioning.md` lists every file that needs updating —
  package files are included.
- **Service files must drop privileges.** The systemd unit and rc.d scripts must run
  merovingian as an unprivileged user (`merovingian` or `_merovingian`), never as root.
- **The FreeBSD rc.d script sets its own locked-memory limit** (`merovingian_limits`, default `-l 128m`), after
  `load_rc_config` so `rc.conf` can override it. Every secret needs a locked page and FreeBSD's default login class
  allows 64 KiB; do not remove the default or rely on the `daemon` class for it.
  `tests/tooling/test_rcd_locked_memory.py` checks it. See `docs/hardening.md`, "Locked memory".
- **Do not hardcode paths.** Use the install prefix from the build system (`/usr/local` on BSD,
  `/usr` on Linux distros). Paths are substituted at build time by `meson install`.
- **BSD packages install the BSD example config, never the Linux one.** The sample is
  `config/merovingian.conf.bsd.example` with `@SYSCONFDIR@` filled in from the package's own
  configuration directory, the one its rc.d script reads. A key added to
  `config/merovingian.conf.example` goes into the BSD example too; `tests/tooling/test_example_config.py`
  fails until it does (ADR-0738).
- **The LiveKit SFU runs as `merovingian-livekit`, never `merovingian`** (ADR-0859). No package script creates,
  reads or prints its API secret: only `merovingian-livekit-setup`, run by the operator, writes it. The unit, the OpenRC
  script, `config/livekit.yaml.example` and the helper must name the same account, paths and port;
  `tests/tooling/test_livekit_companion.py` checks them. The packages never ship `livekit-server` itself.
- The systemd units must set `PrivateTmp=true`, `NoNewPrivileges=true`, and
  `ProtectSystem=strict` at minimum. See `docs/hardening.md` for the full list.
