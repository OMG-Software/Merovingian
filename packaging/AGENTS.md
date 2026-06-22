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
| `systemd/` | `merovingian.service` unit file |
| `openrc/` | OpenRC init script |
| `rc.d/` | BSD `rc.d` script |

## Rules

- **Version numbers in package files must match `meson.build`.**
  The version bump checklist in `docs/versioning.md` lists every file that needs updating —
  package files are included.
- **Service files must drop privileges.** The systemd unit and rc.d scripts must run
  merovingian as an unprivileged user (`merovingian` or `_merovingian`), never as root.
- **Do not hardcode paths.** Use the install prefix from the build system (`/usr/local` on BSD,
  `/usr` on Linux distros). Paths are substituted at build time by `meson install`.
- The systemd unit must set `PrivateTmp=true`, `NoNewPrivileges=true`, and
  `ProtectSystem=strict` at minimum. See `docs/hardening.md` for the full list.
