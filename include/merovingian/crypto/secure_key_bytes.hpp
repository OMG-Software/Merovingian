// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/crypto/constant_time.hpp"

#include <algorithm>
#include <new>
#include <utility>

namespace merovingian::crypto
{
// Array-like API, but every key and copy owns isolated, locked sodium pages.
class SecureKeyBytes final
{
public:
    SecureKeyBytes()
        : m_storage(32U)
    {
        if (!m_storage.is_locked())
        {
            throw std::bad_alloc{};
        }
    }
    SecureKeyBytes(SecureKeyBytes const& other)
        : SecureKeyBytes()
    {
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
