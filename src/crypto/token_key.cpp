// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/token_key.hpp"

#include "merovingian/crypto/master_key.hpp"
#include "merovingian/observability/logger.hpp"

#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <utility>

#include <sodium.h>

namespace merovingian::crypto
{

namespace
{

    // Domain separation labels for deriving access-token HMAC keys from the
    // operator's master key material. The v4 label is the current scheme; the
    // v3 label is used only to validate legacy tokens after the key-separation
    // fix (issue #322), which moved the legacy v3 key off the Ed25519 signing
    // seed onto a master-key-derived key with a distinct label. Using distinct
    // labels from the signing-secret encryption key (and from each other)
    // prevents key reuse across cryptographic purposes.
    constexpr auto k_context_v4 = std::string_view{"merovingian:access-token-hmac:1"};
    constexpr auto k_context_v3 = std::string_view{"merovingian:access-token-hmac:legacy-v3:1"};

    [[nodiscard]] auto sodium_is_ready() noexcept -> bool
    {
        static auto const ready = sodium_init() >= 0;
        return ready;
    }

    // Shared derivation core parameterised by the domain-separation label so
    // v3 (legacy) and v4 (current) share identical crypto and differ only in
    // the label, guaranteeing the two keys are independent.
    [[nodiscard]] auto derive_with_label(std::span<std::uint8_t const> master_key_material,
                                         std::string_view label) noexcept -> std::optional<TokenHmacKey>
    try
    {
        if (!sodium_is_ready() || master_key_material.empty())
        {
            return std::nullopt;
        }
        auto key = TokenHmacKey{};
        if (crypto_generichash(key.bytes.data(), key.bytes.size(), master_key_material.data(),
                               master_key_material.size(), reinterpret_cast<unsigned char const*>(label.data()),
                               label.size()) != 0)
        {
            return std::nullopt;
        }
        return key;
    }
    catch (std::bad_alloc const&)
    {
        return std::nullopt;
    }

} // namespace

auto derive_token_hmac_key(std::span<std::uint8_t const> master_key_material) noexcept -> std::optional<TokenHmacKey>
{
    return derive_with_label(master_key_material, k_context_v4);
}

auto derive_token_hmac_key_v3(std::span<std::uint8_t const> master_key_material) noexcept -> std::optional<TokenHmacKey>
{
    return derive_with_label(master_key_material, k_context_v3);
}

auto cached_token_hmac_keys(std::string_view path)
    -> std::shared_ptr<TokenHmacKeys const> // SHARED_PTR: reviewed — locked keys shared by readers
try
{
    if (path.empty())
    {
        return nullptr;
    }

    // Guards the cache below. Held only across the derivation itself, which
    // blocks on nothing but this one file read.
    static auto cache_mutex = std::mutex{};
    static auto cached_identity = std::string{};
    static auto cached_keys =
        std::shared_ptr<TokenHmacKeys const>{}; // SHARED_PTR: reviewed — locked keys shared by readers
    static auto unreadable_reported = false;

    // ISO-7: identity and material from one open. Never fall back to a second
    // open by path: the keys would then be cached under an identity they were
    // not derived from (and, with no first open, under no identity at all).
    auto const opened = open_master_key_file(path);
    auto guard = std::lock_guard{cache_mutex};
    if (!opened.has_value())
    {
        cached_identity.clear();
        cached_keys.reset();
        if (!unreadable_reported)
        {
            unreadable_reported = true;
            observability::log_diagnostic(
                "crypto", "master_key.token_keys_unavailable",
                {
                    {"reason", "master key requires a secure mode-0400 file containing 32 to 4096 bytes", false}
            },
                observability::LogEventSeverity::error);
        }
        return nullptr;
    }
    unreadable_reported = false;
    if (cached_keys != nullptr && opened->identity == cached_identity)
    {
        return cached_keys;
    }

    auto const material = load_master_key_material(*opened);
    auto v3 = material.has_value() ? derive_token_hmac_key_v3(material->bytes()) : std::nullopt;
    auto v4 = material.has_value() ? derive_token_hmac_key(material->bytes()) : std::nullopt;
    if (!v3.has_value() || !v4.has_value())
    {
        cached_identity.clear();
        cached_keys.reset();
        return nullptr;
    }
    cached_keys = std::make_shared<TokenHmacKeys const>(TokenHmacKeys{std::move(v3), std::move(v4)});
    cached_identity = opened->identity;
    return cached_keys;
}
catch (std::bad_alloc const&)
{
    return nullptr;
}

} // namespace merovingian::crypto
