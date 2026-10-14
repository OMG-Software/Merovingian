// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/master_key.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/platform/file_metadata.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <ios>
#include <mutex>
#include <string>
#include <tuple>

#include <sodium.h>
#include <sys/stat.h>

namespace merovingian::crypto
{

auto master_key_material_is_acceptable(bool locked) noexcept -> bool
{
    return locked;
}

auto load_master_key_material(std::string_view path) -> std::optional<core::SecretBuffer>
{
    auto loaded = platform::read_secure_secret_file(path, 4096U);
    if (!loaded)
    {
        observability::log_diagnostic(
            "crypto", "master_key.load_failed",
            {
                {"reason", "master key requires a secure mode-0400 file containing 32 to 4096 bytes", false}
        },
            observability::LogEventSeverity::error);
        return std::nullopt;
    }
    auto material = std::move(*loaded);
    if (material.bytes().size() < 32U || std::ranges::all_of(material.bytes(), [](auto byte) {
            return byte == 0U;
        }))
    {
        observability::log_diagnostic(
            "crypto", "master_key.invalid_material",
            {
                {"reason", "master key must contain 32 to 4096 bytes and must not be all zero", false}
        },
            observability::LogEventSeverity::error);
        return std::nullopt;
    }
    // #487 first made this condition visible; the 0.12.5 audit (finding 2) made
    // it fatal. SecretBuffer records whether sodium_mlock succeeded and falls
    // back to plain zeroise-on-destruction when it did not. Continuing on that
    // fallback means the root secret — the key the access-token HMAC key, the
    // signing-secret box key and the IPC auth key are all derived from — is
    // swappable and lands in core dumps. That is a crypto-boundary failure, so
    // it fails closed: the caller gets nullopt and reports a fatal error. The
    // remedy is a deployment change (raise RLIMIT_MEMLOCK for the service, or
    // grant CAP_IPC_LOCK), not a silent downgrade of the key hierarchy.
    if (!master_key_material_is_acceptable(material.is_locked()))
    {
        static auto warned = std::atomic<bool>{false};
        if (!warned.exchange(true))
        {
            observability::log_diagnostic(
                "crypto", "master_key.not_mlocked",
                {
                    {"reason", "sodium_mlock failed; refusing to use a master key that may be paged to swap", false},
                    {"action", "raise RLIMIT_MEMLOCK for the service or grant CAP_IPC_LOCK",                   false}
            },
                observability::LogEventSeverity::error);
        }
        return std::nullopt;
    }
    return material;
}

auto master_key_file_identity(std::string_view path) -> std::string
{
    auto const path_string = std::string{path};
    auto const file = platform::open_secure_secret_file(path);
    struct stat info{};
    if (!file || ::fstat(file->get(), &info) != 0)
    {
        return {};
    }
    auto const field = [](auto value) {
        return std::to_string(static_cast<std::uint64_t>(value));
    };
    return path_string + '\0' + field(info.st_dev) + '\0' + field(info.st_ino) + '\0' + field(info.st_size) + '\0' +
           field(info.st_mtime) + '\0' + field(info.st_ctime) + '\0' + field(info.st_mode) + '\0' + field(info.st_uid)
#if defined(__APPLE__)
           + '\0' + field(info.st_mtimespec.tv_nsec) + '\0' + field(info.st_ctimespec.tv_nsec)
#else
           + '\0' + field(info.st_mtim.tv_nsec) + '\0' + field(info.st_ctim.tv_nsec)
#endif
        ;
}

auto signing_secret_box_key(std::string_view path) -> std::optional<SecretBoxKey>
try
{
    if (path.empty())
    {
        return std::nullopt;
    }

    // Guards the cache below. Held only across the derivation itself, which
    // blocks on nothing but this one file read.
    static auto cache_mutex = std::mutex{};
    static auto cached_identity = std::string{};
    static auto cached_key = std::optional<SecretBoxKey>{};

    auto const identity = master_key_file_identity(path);
    auto guard = std::lock_guard{cache_mutex};
    if (!identity.empty() && identity == cached_identity && cached_key.has_value())
    {
        return cached_key;
    }

    auto const material = load_master_key_material(path);
    if (!material.has_value())
    {
        // Drop the stale entry: the master key file has been removed, made
        // unreadable, or can no longer be locked into memory. Continuing to
        // serve a key derived from material we can no longer validate would be
        // exactly the fail-open behaviour the cache must not introduce.
        cached_identity.clear();
        cached_key.reset();
        return std::nullopt;
    }

    auto key = derive_secret_box_key(material->bytes());
    if (!key.has_value())
    {
        cached_identity.clear();
        cached_key.reset();
        return std::nullopt;
    }
    cached_key = std::move(key);
    cached_identity = identity;
    return cached_key;
}
catch (std::bad_alloc const&)
{
    // Cached keys also need an independently locked allocation on return.
    return std::nullopt;
}

} // namespace merovingian::crypto
