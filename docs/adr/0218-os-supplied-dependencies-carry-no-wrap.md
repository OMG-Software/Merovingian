# OS-supplied dependencies carry no wrap file

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-23

Technical Story: Meson wrap pin refresh (0.12.43)

## Context and Problem Statement

OpenSSL, LibSodium and PostgreSQL libpq are declared in `meson.build` with
`allow_fallback: false`, so every build links the operating system's package and
Meson never fetches a wrap for them, not even under the wrappers'
`--wrap-mode=forcefallback`. All three still had `subprojects/*.wrap` files and
`subprojects/packagefiles/` build definitions. Nothing built from them, so
nothing noticed when they went stale: `openssl.wrap` pinned 3.0.20 after
upstream support for the 3.0 line had ended, and `libpq.wrap` pinned
PostgreSQL 18.0 five point releases behind. A generated
`include/openssl/configuration.h` from one of those 3.0.20 builds had also been
committed, and because every target compiles with `-I include` ahead of the
system include path, it silently replaced the OS package's own header.

Should a dependency that only ever comes from the OS keep a wrap?

## Considered Options

* Delete the wraps and packagefiles of OS-supplied dependencies
* Keep them and bump them with the live pins
* Keep them untouched as a documented, unused fallback

## Decision Outcome

Chosen option: "Delete the wraps and packagefiles of OS-supplied dependencies",
because a pin that no build fetches is never exercised, so nobody finds out
when it goes stale or stops building, and a reader takes it for the version the
project ships. A dependency with `allow_fallback: false` has no wrap and no
packagefile, and nothing under `include/` may carry a third-party header.

libcurl is not an exception to the rule: its `allow_fallback` follows the
`static_curl_wrap` option, and the static musl build sets it, so `curl.wrap` is
fetched by a real build.

`tests/tooling/test_dependency_wraps.py` enforces both halves
(`test_os_supplied_libraries_carry_no_wrap`,
`test_project_include_root_does_not_shadow_os_openssl_headers`).

### Positive Consequences

* Every remaining wrap is used by at least one build, so every pin is checked
  by a build when it is bumped.
* The OS OpenSSL's `configuration.h` is the one the compiler sees.

### Negative Consequences

* Making one of these dependencies vendorable again (for example a static
  build that links OpenSSL from source) needs a new wrap and packagefile written
  from scratch, and a new ADR that supersedes this one for that dependency.

## Pros and Cons of the Options

### Keep them and bump them with the live pins

* Good, because a ready-made fallback would exist if one were ever wanted.
* Bad, because nothing would build them, so a bump could not be verified
  beyond its hash, and they would drift again the first time a bump forgot them.

### Keep them untouched as a documented, unused fallback

* Bad, because they already pinned an unsupported OpenSSL release and would
  keep looking like the project's chosen versions.

## Links

* [docs/dependencies/openssl.md](../dependencies/openssl.md)
* [docs/dependencies/index.md](../dependencies/index.md)
