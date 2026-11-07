// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/RandomBytesResult.hpp"

#include <cstddef>

namespace merovingian::crypto
{

class RandomSource
{
public:
    RandomSource() = default;
    RandomSource(RandomSource const& other) = delete;
    auto operator=(RandomSource const& other) -> RandomSource& = delete;
    RandomSource(RandomSource&& other) noexcept = delete;
    auto operator=(RandomSource&& other) noexcept -> RandomSource& = delete;
    virtual ~RandomSource() = default;

    [[nodiscard]] virtual auto bytes(std::size_t size) -> RandomBytesResult = 0;
};

} // namespace merovingian::crypto
