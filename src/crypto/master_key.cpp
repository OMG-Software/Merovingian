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

#include <sodium.h>

namespace merovingian::crypto
{

auto load_master_key_material(std::string_view path) -> std::optional<core::SecretBuffer>
{
    if (path.empty())
    {
        return std::nullopt;
    }
    auto stream = std::ifstream{std::string{path}, std::ios::binary};
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

    // #487: SecretBuffer records whether sodium_mlock succeeded and falls back to
    // plain zeroise-on-destruction when it did not, but nothing ever consulted
    // is_locked(). A server that had exhausted RLIMIT_MEMLOCK therefore held its
    // root secret — the key every derived key comes from — in swappable memory
    // with no indication anywhere. Warn once per process: the condition is a
    // deployment-level fault (raise RLIMIT_MEMLOCK, or grant CAP_IPC_LOCK), so
    // repeating it per load would be noise, and it must not be fatal — refusing
    // to start would turn a hardening shortfall into an outage.
    if (!material.is_locked())
    {
        static auto warned = std::atomic<bool>{false};
        if (!warned.exchange(true))
        {
            observability::log_diagnostic(
                "crypto", "master_key.not_mlocked",
                {
                    {"reason", "sodium_mlock failed; the master key may be paged to swap",   false},
                    {"action", "raise RLIMIT_MEMLOCK for the service or grant CAP_IPC_LOCK", false}
            },
                observability::LogEventSeverity::warning);
        }
    }
    return material;
}

} // namespace merovingian::crypto