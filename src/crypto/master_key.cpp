// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/master_key.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

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
    if (path.empty())
    {
        return std::nullopt;
    }
    auto stream = std::ifstream{};
    // Unbuffer the stream *before* it is opened (finding 20). std::filebuf
    // otherwise keeps its own copy of every byte read in an ordinary heap
    // buffer that is freed without zeroisation, so wiping only our own read
    // buffer still left plaintext master-key bytes behind in the process.
    std::ignore = stream.rdbuf()->pubsetbuf(nullptr, 0);
    stream.open(std::string{path}, std::ios::binary);
    if (!stream)
    {
        return std::nullopt;
    }
    auto constexpr size_limit = std::size_t{4096U};
    // Read into a fixed-size, mlocked, zeroise-on-destruction scratch buffer
    // rather than an ordinary std::vector — the master key is the root secret
    // every derived key (access-token HMAC, secret-box, IPC auth) comes from,
    // so it must never sit unwiped in freed heap memory or swap.
    auto scratch = core::SecretBuffer{size_limit};
    auto const scratch_bytes = scratch.bytes();
    auto total = std::size_t{0U};
    auto read_buffer = std::array<char, 1024U>{};
    while (stream.good())
    {
        stream.read(read_buffer.data(), static_cast<std::streamsize>(read_buffer.size()));
        auto const count = stream.gcount();
        if (count <= 0)
        {
            break;
        }
        auto const added = static_cast<std::size_t>(count);
        if (total + added > size_limit)
        {
            sodium_memzero(read_buffer.data(), read_buffer.size());
            return std::nullopt;
        }
        std::copy_n(reinterpret_cast<std::uint8_t const*>(read_buffer.data()), added, scratch_bytes.data() + total);
        total += added;
        // The stack read buffer held plaintext key bytes for this iteration;
        // wipe it immediately rather than leaving residue until the next
        // iteration overwrites it or the function returns.
        sodium_memzero(read_buffer.data(), read_buffer.size());
    }
    if (total == 0U)
    {
        return std::nullopt;
    }
    // Copy down to a right-sized owner; `scratch`'s destructor wipes the
    // oversized 4096-byte working buffer (including any unused tail) when
    // this function returns.
    auto material = core::SecretBuffer{scratch_bytes.subspan(0U, total)};

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
    struct stat info{};
    if (path_string.empty() || ::stat(path_string.c_str(), &info) != 0)
    {
        return {};
    }
    auto const field = [](auto value) {
        return std::to_string(static_cast<std::uint64_t>(value));
    };
    return path_string + '\0' + field(info.st_dev) + '\0' + field(info.st_ino) + '\0' + field(info.st_size) + '\0' +
           field(info.st_mtime) + '\0' + field(info.st_ctime);
}

auto signing_secret_box_key(std::string_view path) -> std::optional<SecretBoxKey>
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
    cached_identity = identity;
    cached_key = key;
    return key;
}

} // namespace merovingian::crypto
