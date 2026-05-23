// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/key_query.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::federation
{
namespace
{

    [[nodiscard]] auto member_value(canonicaljson::Object const& object, std::string_view key)
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto as_object(canonicaljson::Value const* value) -> canonicaljson::Object const*
    {
        return value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&value->storage());
    }

    // Parses an opaque server-blind JSON payload (a stored device-key or
    // one-time-key blob) so it can be re-embedded verbatim in a response.
    [[nodiscard]] auto parsed_value(std::string_view json) -> std::optional<canonicaljson::Value>
    {
        auto parsed = canonicaljson::parse_lossless(json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        return std::move(parsed.value);
    }

    [[nodiscard]] auto serialize(canonicaljson::Object object) -> std::string
    {
        auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(object)});
        return serialized.error == canonicaljson::CanonicalJsonError::none ? serialized.output : std::string{};
    }

    // Appends the user's master / self_signing cross-signing keys to the
    // matching response objects when the store holds them.
    auto append_cross_signing(database::PersistentStore const& store, std::string_view user_id,
                              canonicaljson::Object& master_keys, canonicaljson::Object& self_signing_keys) -> void
    {
        for (auto const& key : store.cross_signing_keys)
        {
            if (key.user_id != user_id)
            {
                continue;
            }
            auto value = parsed_value(key.json);
            if (!value.has_value())
            {
                continue;
            }
            if (key.key_type == "master")
            {
                master_keys.push_back(canonicaljson::make_member(std::string{user_id}, std::move(*value)));
            }
            else if (key.key_type == "self_signing")
            {
                self_signing_keys.push_back(canonicaljson::make_member(std::string{user_id}, std::move(*value)));
            }
        }
    }

} // namespace

auto build_device_keys_query_response(database::PersistentStore const& store, std::string_view request_body)
    -> std::string
{
    auto request = parsed_value(request_body);
    if (!request.has_value())
    {
        return {};
    }
    auto const* root = std::get_if<canonicaljson::Object>(&request->storage());
    if (root == nullptr)
    {
        return {};
    }
    auto device_keys = canonicaljson::Object{};
    auto master_keys = canonicaljson::Object{};
    auto self_signing_keys = canonicaljson::Object{};
    if (auto const* requested = as_object(member_value(*root, "device_keys")); requested != nullptr)
    {
        for (auto const& user_member : *requested)
        {
            // The requested device-id filter; an empty array selects every
            // published device for the user.
            auto wanted = std::vector<std::string>{};
            if (auto const* list = std::get_if<canonicaljson::Array>(&user_member.value->storage());
                list != nullptr)
            {
                for (auto const& entry : *list)
                {
                    if (auto const* id = std::get_if<std::string>(&entry.storage()); id != nullptr)
                    {
                        wanted.push_back(*id);
                    }
                }
            }
            auto user_devices = canonicaljson::Object{};
            for (auto const& device_key : store.device_keys)
            {
                if (device_key.user_id != user_member.key)
                {
                    continue;
                }
                if (!wanted.empty() && std::ranges::find(wanted, device_key.device_id) == wanted.end())
                {
                    continue;
                }
                auto value = parsed_value(device_key.json);
                if (value.has_value())
                {
                    user_devices.push_back(canonicaljson::make_member(device_key.device_id, std::move(*value)));
                }
            }
            if (!user_devices.empty())
            {
                device_keys.push_back(
                    canonicaljson::make_member(user_member.key, canonicaljson::Value{std::move(user_devices)}));
            }
            append_cross_signing(store, user_member.key, master_keys, self_signing_keys);
        }
    }
    auto response = canonicaljson::Object{};
    response.push_back(canonicaljson::make_member("device_keys", canonicaljson::Value{std::move(device_keys)}));
    response.push_back(canonicaljson::make_member("master_keys", canonicaljson::Value{std::move(master_keys)}));
    response.push_back(
        canonicaljson::make_member("self_signing_keys", canonicaljson::Value{std::move(self_signing_keys)}));
    return serialize(std::move(response));
}

auto build_one_time_keys_claim_response(database::PersistentStore& store, std::string_view request_body)
    -> std::string
{
    auto request = parsed_value(request_body);
    if (!request.has_value())
    {
        return {};
    }
    auto const* root = std::get_if<canonicaljson::Object>(&request->storage());
    if (root == nullptr)
    {
        return {};
    }
    auto one_time_keys = canonicaljson::Object{};
    if (auto const* requested = as_object(member_value(*root, "one_time_keys")); requested != nullptr)
    {
        for (auto const& user_member : *requested)
        {
            auto const* devices = std::get_if<canonicaljson::Object>(&user_member.value->storage());
            if (devices == nullptr)
            {
                continue;
            }
            auto user_object = canonicaljson::Object{};
            for (auto const& device_member : *devices)
            {
                auto const* algorithm = std::get_if<std::string>(&device_member.value->storage());
                if (algorithm == nullptr)
                {
                    continue;
                }
                auto const claimed =
                    database::claim_one_time_key(store, user_member.key, device_member.key, *algorithm);
                if (!claimed.has_value())
                {
                    continue;
                }
                auto value = parsed_value(claimed->json);
                if (!value.has_value())
                {
                    continue;
                }
                auto key_object = canonicaljson::Object{};
                key_object.push_back(canonicaljson::make_member(claimed->key_id, std::move(*value)));
                user_object.push_back(
                    canonicaljson::make_member(device_member.key, canonicaljson::Value{std::move(key_object)}));
            }
            if (!user_object.empty())
            {
                one_time_keys.push_back(
                    canonicaljson::make_member(user_member.key, canonicaljson::Value{std::move(user_object)}));
            }
        }
    }
    auto response = canonicaljson::Object{};
    response.push_back(canonicaljson::make_member("one_time_keys", canonicaljson::Value{std::move(one_time_keys)}));
    return serialize(std::move(response));
}

auto build_user_devices_response(database::PersistentStore const& store, std::string_view user_id) -> std::string
{
    auto devices = canonicaljson::Array{};
    for (auto const& device_key : store.device_keys)
    {
        if (device_key.user_id != user_id)
        {
            continue;
        }
        auto keys = parsed_value(device_key.json);
        if (!keys.has_value())
        {
            continue;
        }
        auto device = canonicaljson::Object{};
        device.push_back(canonicaljson::make_member("device_id", canonicaljson::Value{device_key.device_id}));
        device.push_back(canonicaljson::make_member("keys", std::move(*keys)));
        devices.push_back(canonicaljson::Value{std::move(device)});
    }
    if (devices.empty())
    {
        return {};
    }
    auto response = canonicaljson::Object{};
    response.push_back(canonicaljson::make_member("user_id", canonicaljson::Value{std::string{user_id}}));
    response.push_back(canonicaljson::make_member("stream_id", canonicaljson::Value{std::int64_t{0}}));
    response.push_back(canonicaljson::make_member("devices", canonicaljson::Value{std::move(devices)}));
    auto master_keys = canonicaljson::Object{};
    auto self_signing_keys = canonicaljson::Object{};
    append_cross_signing(store, user_id, master_keys, self_signing_keys);
    for (auto& member : master_keys)
    {
        response.push_back(canonicaljson::make_member("master_key", std::move(*member.value)));
    }
    for (auto& member : self_signing_keys)
    {
        response.push_back(canonicaljson::make_member("self_signing_key", std::move(*member.value)));
    }
    return serialize(std::move(response));
}

} // namespace merovingian::federation
