# tests/complement/ — The Complement image

[Complement](https://github.com/matrix-org/complement) is the external Matrix
homeserver test suite. It is the only check on the federation implementation
that this project does not write itself (the 1.0.0 blocker "Federation
conformance is entirely self-attested"). This directory holds the Docker image
Complement starts as `COMPLEMENT_BASE_IMAGE`. Design and rejected alternatives:
[ADR-0233](../../docs/adr/0233-complement-runs-the-shipped-trixie-package-in-an-image-that-drops-its-own-privileges.md).

Not to be confused with `tests/fixtures/complement/`: those JSON flow fixtures
are this project's own tests.

## Files

| File | Role |
|---|---|
| `Dockerfile` | Installs `artifact/merovingian.deb` (the Debian trixie package) on the shipped image's pinned base, checked against `MEROVINGIAN_DEB_SHA256` |
| `entrypoint.sh` | Runs as root: render config, prepare state, mint TLS, trust the CA, start nginx, `exec setpriv` the server |
| `server-name.sh` | Sourced: the spec's server-name grammar, checked before `SERVER_NAME` is used anywhere |
| `render-config.sh` | Fills `merovingian.conf.template`; refuses a bad server name or Landlock waiver before printing anything |
| `merovingian.conf.template` | The config Complement runs with; each departure from the defaults says why |
| `prepare-state.sh` | Master key and database directories, kept across restarts and bound to one server name |
| `mint-tls.sh` | One-day P-256 certificate for the federation listener, from Complement's CA |
| `install-appservices.sh` | Copies the application service registrations Complement mounts at `/complement/appservice/` beside the master key and prints `appservice.registration_files`; refuses links, odd names and oversized files before writing |
| `nginx.conf` | Puts the loopback client listener (`127.0.0.1:8080`) on 8008 |
| `run.toml` | The pinned Complement commit, the Go it needs, and the maintainer key that must sign `SHA256SUMS` |
| `skip-list.toml` | Tests a green run may fail or not run, each with a category and evidence (ADR-0234) |

## Running Complement

`scripts/run_complement.py` does the whole run (prerequisites in
`docs/dev-environment.md`, "Complement"):

```bash
python3 scripts/run_complement.py \
    --package merovingian_<version>_amd64-debian.deb \
    --sha256sums SHA256SUMS --signature SHA256SUMS.asc \
    --work-dir ../complement-<version>
```

It verifies the package against the maintainer-signed `SHA256SUMS` and its
build provenance (`gh attestation verify`: built by `packages.yml` from one
commit on `main`, which the run records), builds
this directory into an image from a copy in the work directory, fetches
Complement at the commit in `run.toml`, and runs `go test -json ./tests ./tests/csapi`.
The `tests/msc*` packages test unstable proposals outside Matrix v1.19 and are
not run (ADR-0237).
`scripts/summarise_complement.py` judges the result against `skip-list.toml`,
and its verdict is the exit status: 0 green, 1 not green, 2 refused.
`--unsigned` runs a locally built package and `--run` a subset; neither is
release evidence. `--allow-without-landlock` passes
`MEROVINGIAN_COMPLEMENT_ALLOW_WITHOUT_LANDLOCK=true` to each container through
`COMPLEMENT_SHARE_ENV_PREFIX`, and the run records it.

To build the image by hand:

```bash
cp merovingian_<version>_amd64-debian.deb tests/complement/artifact/merovingian.deb
docker build --build-arg MEROVINGIAN_DEB_SHA256=<its SHA-256> --tag merovingian-complement tests/complement
```

## Release evidence

`scripts/record_complement_evidence.py` turns a run's work directory into
`complement-results-<version>.json` and `complement-<version>.jsonl`.
`scripts/publish_complement_evidence.py` signs them with the maintainer key and
attaches them, with the tested package and its signature, to the tag's release
(ADR-0235). The recorder refuses a run whose image did not hold the package's
own server binary, and the publisher refuses a tag at any commit other than
the one the package was built from. Only a signed, provenance-checked,
unfiltered, green run is release evidence. The sequence is in
`docs/release-process.md`, "Complement".

## The skip list

A green run is not "every test passed". It means nothing failed outside
`skip-list.toml`, every `expect-fail` entry still fails, and every entry names a
test that exists (ADR-0234). The file's header documents the format. In short:

- Prefer `expect-fail`. A `skip` entry never runs, so it cannot go stale. It is
  only for a top-level test that would harm the rest of the run, and it must
  say why.
- Each entry needs evidence for its category. `spec` and `non-spec` cite the
  pinned spec, `room-version` cites ADR-0076, and `known-gap` names its
  `docs/todos/` row.
- An entry hiding a test about auth, signatures, keys or ACLs needs the
  maintainer's `signed_off_by`.
- A failing parent test is explained when every failing leaf beneath it is
  listed. Subtest names can hold slashes ("test /_matrix/media/v3 endpoint"),
  so list the leaf itself, never a guess at its depth.
- When a fix lands, its test passes, its entry goes stale, and the run fails
  until the entry is removed. Remove it in the same change as the fix.
- Moving the pinned commit in `run.toml` can bring tests the list has never
  seen. Do it in its own change, with a full run.

## Rules

1. **Only the release package goes in.** Never compile in this image or copy a
   locally built binary over the package's. A run is evidence only about the
   bytes that ship. A package built locally is fine for development, by its own
   SHA-256, but its result is not release evidence.
2. **The server never runs with privileges.** The entrypoint starts as root
   only because Complement passes no `--cap-drop`. Its last command is the
   `exec setpriv` hand-over, with an empty bounding set and `no_new_privs`.
   Nothing runs after it, and the image has no `USER` or `VOLUME`.
3. **Check, then write.** `SERVER_NAME` and the Landlock waiver reach the
   config and the certificate, so they are checked first and refused, never
   cleaned. A script fails before it writes anything.
4. **Every start is a restart.** Complement snapshots containers and starts
   them again. Each step must succeed on a container that has started before.
   State stays in the container layer, and is never served under another
   server name.
5. **Departures from the defaults are few and stated.** The template may change
   only what Complement's contract forces (including a password policy that
   admits its users' passwords, ADR-0236), the optional parts of the
   encryption policy, and rate limits. Each change says why in a comment. A
   change that makes the server behave differently from a deployment needs an
   ADR. The rendered config must pass the real server's `--check-config`: what
   the server refuses to relax stays as shipped.
6. **Secrets stay out of the Landlock-granted directories.** The federation
   worker reads the config and database directories, so the master key and TLS
   key live in `/var/lib/merovingian/secrets`.
7. **Root never writes where the server's user can create entries.** The
   entrypoint writes in `/var/lib/merovingian`, `secrets/` and `/etc/merovingian`
   as root on every start. Those directories are root-owned and only
   `data/` belongs to `merovingian`. Otherwise a compromised server could plant
   a link that root follows on the next start. Temporary files are removed,
   never written through.

## Tests

`tests/tooling/test_complement_summary.py` and `test_run_complement.py` cover
the summariser and the run script (the latter against fake `docker`, `go`,
`git` and `gpg`). `tests/tooling/test_complement_image.py` (meson test `complement-image-tooling`)
runs these scripts directly. It covers server-name refusals, the rendered
config, restarts, and certificates from a throwaway CA. The real server's
`--check-config` must approve the rendered config. It also checks the
Dockerfile, the nginx config and the CI job. The `complement-image` job in
`.github/workflows/packages.yml` builds the image from the trixie package and
boots it as Complement does. It checks health, the `m.login.dummy` challenge,
federation over TLS through the worker, an empty bounding set, and a signing key
that survives `docker restart`.
