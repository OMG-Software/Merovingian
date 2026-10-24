// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::core
{

// How a library reached the running process.
enum class Linkage : std::uint8_t
{
    static_linked, // compiled into this executable: changes only with a rebuild
    dynamic,       // a shared object the loader opened: an OS update can replace it under the binary
};

// One library an executable depends on, as logged at startup (0.12.45). Each module that owns a
// library reports it (crypto: libsodium, database: SQLite and libpq, http: libcurl, canonicaljson:
// yyjson, homeserver: OpenSSL, the thumbnail worker: libpng and libjpeg-turbo).
struct LibraryVersion final
{
    std::string name{};
    Linkage linkage{Linkage::static_linked};
    // The version the running library reports; empty when it has no runtime version call.
    std::string runtime_version{};
    // The version its headers (or, for libpq and libjpeg-turbo, pkg-config) declared at build time.
    std::string build_version{};
    // The path the loader opened, for a dynamic library; empty for a static one.
    std::string shared_object{};

    [[nodiscard]] auto operator==(LibraryVersion const&) const -> bool = default;
};

// Describes a library from an address inside it: preferably data the library itself returns
// (its version string), otherwise one of its functions. dladdr(3) names the object holding the
// address; the library is dynamic when that is a shared object other than the one holding this
// function, and static otherwise, including when dladdr knows no object at all (a static
// executable has no dynamic linker to ask).
[[nodiscard]] auto describe_library(std::string_view name, std::string_view runtime_version,
                                    std::string_view build_version, void const* address_in_library) -> LibraryVersion;

// "libsodium 1.0.18 (dynamic, /usr/lib/libsodium.so.23; built against 1.0.18)" or
// "SQLite 3.54.1 (static)". A static library names its build version only when it differs from
// the running one or the running one is unknown; a missing runtime version reads "version not
// reported".
[[nodiscard]] auto library_version_log_line(LibraryVersion const& library) -> std::string;

} // namespace merovingian::core
