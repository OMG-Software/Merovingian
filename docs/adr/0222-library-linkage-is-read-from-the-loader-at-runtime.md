# Library linkage is read from the loader at runtime, not from the build

* Status: accepted
* Date: 2026-10-24

Technical Story: log every library's version at startup, marked static or dynamic (0.12.45).

## Context and Problem Statement

Operators need to know which libraries a running Merovingian process uses. A dynamically linked
library (OpenSSL, libsodium, libpq and libcurl on a normal build) is replaced by an OS update at
the next start; a statically linked one (SQLite and yyjson from their wraps, and everything in the
static-PIE build) changes only with a rebuild. Each executable logs one line per library naming
its version and its linkage. Where should "static" or "dynamic" come from?

## Decision Drivers

* The line must describe the process that is running, since an OS update or a different build
  script can change what the binary loads.
* The answer must hold on every packaged build: glibc and musl Linux, static-PIE, and the BSDs.
* Each library is reported by the module that owns it (ADR-0014 keeps libsodium calls in crypto).

## Considered Options

* Ask the dynamic loader: `dladdr(3)` on an address inside the library.
* Have Meson write the linkage it chose into a generated header.
* Scan the loaded objects (`dl_iterate_phdr`) for each library's file name.

## Decision Outcome

Chosen option: "ask the dynamic loader". `core::describe_library` calls `dladdr` on an address
inside the library and compares the object holding it with the object holding Merovingian's own
code. The same object, or no object at all (a static executable has no loader to ask), means
static; another object means dynamic, and its path is logged. The address is the library's own
version string where it returns one (libsodium, OpenSSL, libcurl, SQLite, libpng), otherwise one
of its functions (libpq, yyjson, libjpeg-turbo), taken with `std::bit_cast`. A function address is
the library's own only in a position-independent executable, which every packaged build is.

### Positive Consequences

* A line reports what the process loaded, including the path of the shared object, which is what
  an operator checks against a security advisory.
* No list of file names to maintain per platform.

### Negative Consequences

* A non-PIE build could report a dynamically linked libpq, yyjson or libjpeg-turbo as static,
  because the executable's PLT entry would stand in for the function's address.
* The versions a library was built against still come from the build: header macros, or
  pkg-config for libpq and libjpeg-turbo, whose headers carry no version.

## Pros and Cons of the Options

### Meson writes the linkage into a generated header

* Good, because it needs no loader call.
* Bad, because it records what the build asked for, not what was linked. The Alpine package
  links static-PIE through link arguments the build scripts add, which Meson's dependency
  objects never see.

### Scan loaded objects for each library's file name

* Good, because it works for any library without an address inside it.
* Bad, because sonames differ by platform and version (`libssl.so.3`, LibreSSL's `libssl.so.53`,
  `libturbojpeg.so.0`), so every platform needs its own name list, and a match by name does not
  prove the code running is in that object.

## Links

* Related: [ADR-0218](0218-os-supplied-dependencies-carry-no-wrap.md): which dependencies come
  from the OS and which from wraps
