// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace merovingian::canonicaljson
{

class Value;

struct ObjectMember final
{
    std::string key{};
    std::unique_ptr<Value> value{};
};

using Array = std::vector<Value>;
using Object = std::vector<ObjectMember>;

class Value final
{
public:
    using Storage = std::variant<std::nullptr_t, bool, std::int64_t, std::string, Array, Object>;

    Value() = default;
    explicit Value(std::nullptr_t value);
    explicit Value(bool value);
    explicit Value(std::int64_t value);
    explicit Value(std::string value);
    explicit Value(Array value);
    explicit Value(Object value);

    Value(Value&& other) noexcept = default;
    auto operator=(Value&& other) noexcept -> Value& = default;

    Value(Value const& other);
    auto operator=(Value const& other) -> Value&;

    [[nodiscard]] auto storage() const noexcept -> Storage const&;

private:
    Storage m_storage{nullptr};
};

[[nodiscard]] auto make_member(std::string key, Value value) -> ObjectMember;

} // namespace merovingian::canonicaljson
