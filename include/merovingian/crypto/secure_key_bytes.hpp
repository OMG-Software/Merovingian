// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/crypto/constant_time.hpp"

#include <algorithm>
#include <cstddef>
#include <new>
#include <stdexcept>
#include <utility>

namespace merovingian::crypto
{
// Array-like API, but every key and copy owns isolated, locked sodium pages.
class SecureKeyBytes final
{
public:
    // Every key this type holds: the HMAC and secretbox keys are 32 bytes.
    static constexpr auto key_bytes = std::size_t{32U};

    SecureKeyBytes()
        : m_storage(key_bytes)
    {
        if (!m_storage.is_locked())
        {
            throw std::bad_alloc{};
        }
    }
    // A moved-from key holds no bytes. Copying it would otherwise produce a
    // valid, locked, all-zero key that a caller could use as an HMAC or
    // secretbox key without noticing; that is a programming error, so it throws.
    SecureKeyBytes(SecureKeyBytes const& other)
        : SecureKeyBytes()
    {
        if (other.m_storage.bytes().size() != key_bytes)
        {
            throw std::logic_error{"copy of a moved-from SecureKeyBytes"};
        }
        std::copy(other.m_storage.bytes().begin(), other.m_storage.bytes().end(), m_storage.bytes().begin());
    }
    auto operator=(SecureKeyBytes const& other) -> SecureKeyBytes&
    {
        if (this != &other)
        {
            auto copy = SecureKeyBytes{other};
            *this = std::move(copy);
        }
        return *this;
    }
    SecureKeyBytes(SecureKeyBytes&&) noexcept = default;
    auto operator=(SecureKeyBytes&&) noexcept -> SecureKeyBytes& = default;
    [[nodiscard]] auto data() noexcept
    {
        return m_storage.bytes().data();
    }
    [[nodiscard]] auto data() const noexcept
    {
        return m_storage.bytes().data();
    }
    [[nodiscard]] auto size() const noexcept
    {
        return m_storage.bytes().size();
    }
    [[nodiscard]] auto empty() const noexcept
    {
        return m_storage.bytes().empty();
    }
    [[nodiscard]] auto begin() noexcept
    {
        return m_storage.bytes().begin();
    }
    [[nodiscard]] auto begin() const noexcept
    {
        return m_storage.bytes().begin();
    }
    [[nodiscard]] auto end() noexcept
    {
        return m_storage.bytes().end();
    }
    [[nodiscard]] auto end() const noexcept
    {
        return m_storage.bytes().end();
    }
    [[nodiscard]] auto operator[](std::size_t index) noexcept -> std::uint8_t&
    {
        return m_storage.bytes()[index];
    }
    [[nodiscard]] auto operator[](std::size_t index) const noexcept -> std::uint8_t const&
    {
        return m_storage.bytes()[index];
    }
    auto fill(std::uint8_t value) noexcept -> void
    {
        std::fill(begin(), end(), value);
    }
    [[nodiscard]] auto operator==(SecureKeyBytes const& other) const noexcept -> bool
    {
        return constant_time_equal(std::string_view{reinterpret_cast<char const*>(data()), size()},
                                   std::string_view{reinterpret_cast<char const*>(other.data()), other.size()});
    }

private:
    core::SecretBuffer m_storage;
};
} // namespace merovingian::crypto
