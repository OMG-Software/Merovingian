// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <memory>
#include <string>

namespace merovingian::canonicaljson
{

class Value;

struct ObjectMember final
{
    // NOLINTNEXTLINE(misc-non-private-member-variables-in-classes)
    std::string key{};
    // NOLINTNEXTLINE(misc-non-private-member-variables-in-classes)
    std::unique_ptr<Value> value{};

    ObjectMember() = default;
    ObjectMember(std::string key_value, std::unique_ptr<Value> owned_value);
    ObjectMember(ObjectMember&& other) noexcept = default;
    auto operator=(ObjectMember&& other) noexcept -> ObjectMember& = default;
    ObjectMember(ObjectMember const& other);
    auto operator=(ObjectMember const& other) -> ObjectMember&;
};

} // namespace merovingian::canonicaljson
