// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/key_query.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/federation/key_signatures.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <cstddef>
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

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("key_query", event, fields, severity);
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

    // Appends the user's master / self_signing cross-signing keys, as
    // published to a remote server, to the matching response objects when
    // the store holds them. The user-signing key is never served over
    // federation: it is only ever returned to its owner.
    auto append_cross_signing(database::PersistentStore const& store, std::string_view user_id,
                              canonicaljson::Object& master_keys, canonicaljson::Object& self_signing_keys) -> void
    {
        if (auto master = published_cross_signing_key(store, user_id, "master", std::nullopt); master.has_value())
        {
            master_keys.push_back(
                canonicaljson::make_member(std::string{user_id}, canonicaljson::Value{std::move(*master)}));
        }
        if (auto self_signing = published_cross_signing_key(store, user_id, "self_signing", std::nullopt);
            self_signing.has_value())
        {
            self_signing_keys.push_back(
                canonicaljson::make_member(std::string{user_id}, canonicaljson::Value{std::move(*self_signing)}));
        }
    }

    [[nodiscard]] auto string_member_equals(canonicaljson::Object const& object, std::string_view key,
                                            std::string_view expected) -> bool
    {
        auto const* value = member_value(object, key);
        auto const* text = value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
        return text != nullptr && *text == expected;
    }

    [[nodiscard]] auto has_member(canonicaljson::Object const& object, std::string_view key) -> bool
    {
        return member_value(object, key) != nullptr;
    }

    // A remote cross-signing key is acceptable when it describes the user it
    // is filed under, names its role in `usage`, and holds one public key.
    [[nodiscard]] auto remote_cross_signing_key_is_valid(canonicaljson::Object const& key, std::string_view user_id,
                                                         std::string_view usage) -> bool
    {
        if (!string_member_equals(key, "user_id", user_id) || !cross_signing_key_id(key).has_value())
        {
            return false;
        }
        auto const* usages = member_value(key, "usage");
        auto const* list = usages == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&usages->storage());
        return list != nullptr && std::ranges::any_of(*list, [usage](canonicaljson::Value const& entry) {
                   auto const* text = std::get_if<std::string>(&entry.storage());
                   return text != nullptr && *text == usage;
               });
    }

    // Copies the acceptable entries of `root[section]` into `accepted`.
    // Returns how many entries were dropped.
    [[nodiscard]] auto accept_remote_cross_signing_keys(canonicaljson::Object const& root, std::string_view section,
                                                        std::string_view usage,
                                                        std::vector<std::string> const& requested_users,
                                                        canonicaljson::Object& accepted) -> std::size_t
    {
        auto const* keys = as_object(member_value(root, section));
        if (keys == nullptr)
        {
            return 0U;
        }
        auto dropped = std::size_t{0U};
        for (auto const& user_member : *keys)
        {
            auto const* key = user_member.value == nullptr
                                  ? nullptr
                                  : std::get_if<canonicaljson::Object>(&user_member.value->storage());
            if (key == nullptr || std::ranges::find(requested_users, user_member.key) == requested_users.end() ||
                has_member(accepted, user_member.key) ||
                !remote_cross_signing_key_is_valid(*key, user_member.key, usage))
            {
                ++dropped;
                continue;
            }
            accepted.push_back(user_member);
        }
        return dropped;
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
            // Published with the owner's self-signing signature: without it
            // the remote user cannot tell the device is trusted by its owner.
            auto published = published_device_keys(store, device_key, std::nullopt);
            if (published.has_value())
            {
                user_devices.push_back(
                    canonicaljson::make_member(device_key.device_id, canonicaljson::Value{std::move(*published)}));
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

auto accept_remote_key_query_response(std::string_view origin, std::string_view response_body,
                                      std::vector<std::string> const& requested_users)
    -> std::optional<RemoteKeyQueryKeys>
{
    auto const response = parsed_value(response_body);
    auto const* root = response.has_value() ? std::get_if<canonicaljson::Object>(&response->storage()) : nullptr;
    if (root == nullptr)
    {
        log_diagnostic("remote_key_query.rejected",
                       {
                           {"origin", std::string{origin},             false},
                           {"reason", "response is not a JSON object", false}
        },
                       observability::LogEventSeverity::warning);
        return std::nullopt;
    }

    auto accepted = RemoteKeyQueryKeys{};
    auto dropped = std::size_t{0U};
    if (auto const* device_keys = as_object(member_value(*root, "device_keys")); device_keys != nullptr)
    {
        for (auto const& user_member : *device_keys)
        {
            auto const* devices = user_member.value == nullptr
                                      ? nullptr
                                      : std::get_if<canonicaljson::Object>(&user_member.value->storage());
            if (devices == nullptr || std::ranges::find(requested_users, user_member.key) == requested_users.end() ||
                has_member(accepted.device_keys, user_member.key))
            {
                ++dropped;
                continue;
            }
            auto user_devices = canonicaljson::Object{};
            for (auto const& device_member : *devices)
            {
                auto const* device = device_member.value == nullptr
                                         ? nullptr
                                         : std::get_if<canonicaljson::Object>(&device_member.value->storage());
                // Spec: device_id and user_id "Must match" the device and
                // user the keys belong to.
                if (device == nullptr || has_member(user_devices, device_member.key) ||
                    !string_member_equals(*device, "user_id", user_member.key) ||
                    !string_member_equals(*device, "device_id", device_member.key))
                {
                    ++dropped;
                    continue;
                }
                user_devices.push_back(device_member);
            }
            accepted.device_keys.push_back(
                canonicaljson::make_member(user_member.key, canonicaljson::Value{std::move(user_devices)}));
        }
    }
    dropped += accept_remote_cross_signing_keys(*root, "master_keys", "master", requested_users, accepted.master_keys);
    dropped += accept_remote_cross_signing_keys(*root, "self_signing_keys", "self_signing", requested_users,
                                                accepted.self_signing_keys);
    if (dropped > 0U)
    {
        log_diagnostic("remote_key_query.entries_dropped",
                       {
                           {"origin",  std::string{origin},     false},
                           {"dropped", std::to_string(dropped), false}
        },
                       observability::LogEventSeverity::warning);
    }
    return accepted;
}

auto build_signing_key_update_content(database::PersistentStore const& store, std::string_view user_id)
    -> std::optional<std::string>
{
    auto master = published_cross_signing_key(store, user_id, "master", std::nullopt);
    auto self_signing = published_cross_signing_key(store, user_id, "self_signing", std::nullopt);
    if (!master.has_value() && !self_signing.has_value())
    {
        return std::nullopt;
    }
    auto content = canonicaljson::Object{};
    if (master.has_value())
    {
        content.push_back(canonicaljson::make_member("master_key", canonicaljson::Value{std::move(*master)}));
    }
    if (self_signing.has_value())
    {
        content.push_back(
            canonicaljson::make_member("self_signing_key", canonicaljson::Value{std::move(*self_signing)}));
    }
    content.push_back(canonicaljson::make_member("user_id", canonicaljson::Value{std::string{user_id}}));
    auto serialized = serialize(std::move(content));
    if (serialized.empty())
    {
        return std::nullopt;
    }
    return serialized;
}

auto build_device_list_update_content(database::PersistentStore const& store, std::string_view user_id,
                                      std::string_view device_id, std::int64_t stream_id) -> std::optional<std::string>
{
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("device_id", canonicaljson::Value{std::string{device_id}}));
    auto const device_key =
        std::ranges::find_if(store.device_keys, [user_id, device_id](database::PersistentDeviceKey const& key) {
            return key.user_id == user_id && key.device_id == device_id;
        });
    if (device_key != store.device_keys.end())
    {
        // A receiving server may apply these keys directly instead of
        // refetching, so they must be exactly what /user/keys/query serves.
        if (auto keys = published_device_keys(store, *device_key, std::nullopt); keys.has_value())
        {
            content.push_back(canonicaljson::make_member("keys", canonicaljson::Value{std::move(*keys)}));
        }
    }
    content.push_back(canonicaljson::make_member("prev_id", canonicaljson::Value{canonicaljson::Array{}}));
    content.push_back(canonicaljson::make_member("stream_id", canonicaljson::Value{stream_id}));
    content.push_back(canonicaljson::make_member("user_id", canonicaljson::Value{std::string{user_id}}));
    auto serialized = serialize(std::move(content));
    if (serialized.empty())
    {
        return std::nullopt;
    }
    return serialized;
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
        auto keys = published_device_keys(store, device_key, std::nullopt);
        if (!keys.has_value())
        {
            continue;
        }
        auto device = canonicaljson::Object{};
        device.push_back(canonicaljson::make_member("device_id", canonicaljson::Value{device_key.device_id}));
        device.push_back(canonicaljson::make_member("keys", canonicaljson::Value{std::move(*keys)}));
        devices.push_back(canonicaljson::Value{std::move(device)});
    }
    auto response = canonicaljson::Object{};
    response.push_back(canonicaljson::make_member("user_id", canonicaljson::Value{std::string{user_id}}));
    response.push_back(canonicaljson::make_member(
        "stream_id", canonicaljson::Value{static_cast<std::int64_t>(store.next_sync_stream_id)}));
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
