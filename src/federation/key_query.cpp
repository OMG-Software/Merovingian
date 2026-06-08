// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/key_query.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

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

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("key_query", event, std::move(fields)));
    }

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
        log_diagnostic("key_query.rejected", {
                                                 {"reason", "request body parse failed", false}
        });
        return {};
    }
    auto const* root = std::get_if<canonicaljson::Object>(&request->storage());
    if (root == nullptr)
    {
        log_diagnostic("key_query.rejected", {
                                                 {"reason", "request root is not an object", false}
        });
        return {};
    }
    auto const* requested = as_object(member_value(*root, "device_keys"));
    if (requested == nullptr)
    {
        log_diagnostic("key_query.rejected", {
                                                 {"reason", "device_keys member missing or not an object", false}
        });
        return {};
    }

    auto device_keys = canonicaljson::Object{};
    auto master_keys = canonicaljson::Object{};
    auto self_signing_keys = canonicaljson::Object{};
    for (auto const& user_member : *requested)
    {
        auto const* list = std::get_if<canonicaljson::Array>(&user_member.value->storage());
        if (list == nullptr)
        {
            log_diagnostic("key_query.rejected", {
                                                     {"reason",  "device_keys user entry is not an array", false},
                                                     {"user_id", user_member.key,                          false}
            });
            return {};
        }

        // The requested device-id filter; an empty array selects every
        // published device for the user.
        auto wanted = std::vector<std::string>{};
        for (auto const& entry : *list)
        {
            auto const* id = std::get_if<std::string>(&entry.storage());
            if (id == nullptr)
            {
                log_diagnostic("key_query.rejected", {
                                                         {"reason",  "device_keys array entry is not a string", false},
                                                         {"user_id", user_member.key,                           false}
                });
                return {};
            }
            wanted.push_back(*id);
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
    auto const device_key_user_count = device_keys.size();
    auto response = canonicaljson::Object{};
    response.push_back(canonicaljson::make_member("device_keys", canonicaljson::Value{std::move(device_keys)}));
    response.push_back(canonicaljson::make_member("master_keys", canonicaljson::Value{std::move(master_keys)}));
    response.push_back(
        canonicaljson::make_member("self_signing_keys", canonicaljson::Value{std::move(self_signing_keys)}));
    log_diagnostic("key_query.accepted", {
                                             {"device_key_users", std::to_string(device_key_user_count), false}
    });
    return serialize(std::move(response));
}

auto build_one_time_keys_claim_response(database::PersistentStore& store, std::string_view request_body) -> std::string
{
    auto request = parsed_value(request_body);
    if (!request.has_value())
    {
        log_diagnostic("otk_claim.rejected", {
                                                 {"reason", "request body parse failed", false}
        });
        return {};
    }
    auto const* root = std::get_if<canonicaljson::Object>(&request->storage());
    if (root == nullptr)
    {
        log_diagnostic("otk_claim.rejected", {
                                                 {"reason", "request root is not an object", false}
        });
        return {};
    }
    auto const* requested = as_object(member_value(*root, "one_time_keys"));
    if (requested == nullptr)
    {
        log_diagnostic("otk_claim.rejected", {
                                                 {"reason", "one_time_keys member missing or not an object", false}
        });
        return {};
    }

    auto one_time_keys = canonicaljson::Object{};
    for (auto const& user_member : *requested)
    {
        auto const* devices = std::get_if<canonicaljson::Object>(&user_member.value->storage());
        if (devices == nullptr)
        {
            log_diagnostic("otk_claim.rejected", {
                                                     {"reason",  "one_time_keys user entry is not an object", false},
                                                     {"user_id", user_member.key,                             false}
            });
            return {};
        }

        auto user_object = canonicaljson::Object{};
        for (auto const& device_member : *devices)
        {
            auto const* algorithm = std::get_if<std::string>(&device_member.value->storage());
            if (algorithm == nullptr)
            {
                log_diagnostic("otk_claim.rejected",
                               {
                                   {"reason",    "one_time_keys device entry is not a string", false},
                                   {"user_id",   user_member.key,                              false},
                                   {"device_id", device_member.key,                            false}
                });
                return {};
            }

            auto const claimed = database::claim_one_time_key(store, user_member.key, device_member.key, *algorithm);
            if (claimed.has_value())
            {
                auto value = parsed_value(claimed->json);
                if (!value.has_value())
                {
                    continue;
                }
                auto key_object = canonicaljson::Object{};
                key_object.push_back(canonicaljson::make_member(claimed->key_id, std::move(*value)));
                user_object.push_back(
                    canonicaljson::make_member(device_member.key, canonicaljson::Value{std::move(key_object)}));
                continue;
            }

            auto const fallback = database::find_fallback_key(store, user_member.key, device_member.key, *algorithm);
            if (!fallback.has_value())
            {
                continue;
            }
            auto value = parsed_value(fallback->json);
            if (!value.has_value())
            {
                continue;
            }
            auto key_object = canonicaljson::Object{};
            key_object.push_back(canonicaljson::make_member(fallback->key_id, std::move(*value)));
            user_object.push_back(
                canonicaljson::make_member(device_member.key, canonicaljson::Value{std::move(key_object)}));
        }
        if (!user_object.empty())
        {
            one_time_keys.push_back(
                canonicaljson::make_member(user_member.key, canonicaljson::Value{std::move(user_object)}));
        }
    }
    auto const otk_user_count = one_time_keys.size();
    auto response = canonicaljson::Object{};
    response.push_back(canonicaljson::make_member("one_time_keys", canonicaljson::Value{std::move(one_time_keys)}));
    log_diagnostic("otk_claim.accepted", {
                                             {"users", std::to_string(otk_user_count), false}
    });
    return serialize(std::move(response));
}

auto build_user_devices_response(database::PersistentStore const& store, std::string_view user_id) -> std::string
{
    log_diagnostic("user_devices.dispatch", {
                                                {"user_id", std::string{user_id}, false}
    });
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
    auto response = canonicaljson::Object{};
    response.push_back(canonicaljson::make_member("user_id", canonicaljson::Value{std::string{user_id}}));
    response.push_back(canonicaljson::make_member("stream_id",
                                                  canonicaljson::Value{static_cast<std::int64_t>(store.next_sync_stream_id)}));
    if (devices.empty())
    {
        log_diagnostic("user_devices.empty", {
                                                 {"user_id", std::string{user_id}, false}
        });
        // Empty string signals "no published devices" to the HTTP handler, which
        // maps it to 404 M_NOT_FOUND per the Matrix SS API spec.
        return {};
    }
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
