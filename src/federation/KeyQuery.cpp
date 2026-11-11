// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/KeyQuery.hpp"

#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ObjectMember.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/federation/DeviceDisplayNames.hpp"
#include "merovingian/federation/KeySignatures.hpp"
#include "merovingian/federation/RemoteKeyClaimKeys.hpp"
#include "merovingian/federation/RemoteKeyQueryKeys.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogField.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
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
                                                        std::set<std::string_view> const& requested_users,
                                                        canonicaljson::Object& accepted) -> std::size_t
    {
        auto const* keys = as_object(member_value(root, section));
        if (keys == nullptr)
        {
            return 0U;
        }
        auto dropped = std::size_t{0U};
        // Set lookups, not a search of `requested_users` and `accepted` per key: the answer's size is the
        // remote server's to choose (ADR-0604).
        auto seen = std::set<std::string_view>{};
        for (auto const& user_member : *keys)
        {
            auto const* key = user_member.value == nullptr
                                  ? nullptr
                                  : std::get_if<canonicaljson::Object>(&user_member.value->storage());
            if (key == nullptr || !requested_users.contains(user_member.key) || seen.contains(user_member.key) ||
                !remote_cross_signing_key_is_valid(*key, user_member.key, usage))
            {
                ++dropped;
                continue;
            }
            seen.insert(user_member.key);
            accepted.push_back(user_member);
        }
        return dropped;
    }

    [[nodiscard]] auto string_value(canonicaljson::Value const* value) -> std::string const*
    {
        return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto integer_value(canonicaljson::Value const* value) -> std::optional<std::int64_t>
    {
        auto const* number = value == nullptr ? nullptr : std::get_if<std::int64_t>(&value->storage());
        return number == nullptr ? std::nullopt : std::optional<std::int64_t>{*number};
    }

    constexpr auto max_cached_device_id_bytes = std::size_t{255U};

    [[nodiscard]] auto cached_device_id_is_usable(std::string const* device_id) -> bool
    {
        return device_id != nullptr && !device_id->empty() && device_id->size() <= max_cached_device_id_bytes;
    }

    // A device's keys as the remote device-list cache keeps them: canonical JSON without `unsigned`, which would
    // otherwise carry the remote server's own `unsigned` into every answer. std::nullopt when the keys are not filed
    // under `user_id` and `device_id`, or cannot be serialised.
    [[nodiscard]] auto cacheable_device_keys(canonicaljson::Object const& keys, std::string_view user_id,
                                             std::string_view device_id) -> std::optional<std::string>
    {
        if (!string_member_equals(keys, "user_id", user_id) || !string_member_equals(keys, "device_id", device_id))
        {
            return std::nullopt;
        }
        auto kept = canonicaljson::Object{};
        for (auto const& member : keys)
        {
            if (member.key != "unsigned")
            {
                kept.push_back(member);
            }
        }
        auto serialized = serialize(std::move(kept));
        return serialized.empty() ? std::nullopt : std::optional<std::string>{std::move(serialized)};
    }

    // The `unsigned.device_display_name` of a device's keys, when it is a string.
    [[nodiscard]] auto unsigned_display_name(canonicaljson::Object const& keys) -> std::optional<std::string>
    {
        auto const* unsigned_data = as_object(member_value(keys, "unsigned"));
        auto const* name =
            unsigned_data == nullptr ? nullptr : string_value(member_value(*unsigned_data, "device_display_name"));
        return name == nullptr ? std::nullopt : std::optional<std::string>{*name};
    }

    // `root[member]` as canonical JSON when it is the user's cross-signing key for `usage`; sets `refused` when the
    // member is present but is not.
    [[nodiscard]] auto cacheable_cross_signing_key(canonicaljson::Object const& root, std::string_view member,
                                                   std::string_view user_id, std::string_view usage, bool& refused)
        -> std::optional<std::string>
    {
        auto const* value = member_value(root, member);
        if (value == nullptr)
        {
            return std::nullopt;
        }
        auto const* key = as_object(value);
        if (key == nullptr || !remote_cross_signing_key_is_valid(*key, user_id, usage))
        {
            refused = true;
            return std::nullopt;
        }
        auto serialized = serialize(*key);
        if (serialized.empty())
        {
            refused = true;
            return std::nullopt;
        }
        return serialized;
    }

    auto log_refused_user_devices(std::string_view origin, std::string_view user_id, std::string_view reason) -> void
    {
        log_diagnostic("remote_user_devices.rejected",
                       {
                           {"origin",  std::string{origin},  false},
                           {"user_id", std::string{user_id}, false},
                           {"reason",  std::string{reason},  false}
        },
                       observability::LogEventSeverity::warning);
    }

    [[nodiscard]] auto parsed_object_json(std::string const& json) -> std::optional<canonicaljson::Object>
    {
        auto const value = parsed_value(json);
        auto const* object = value.has_value() ? std::get_if<canonicaljson::Object>(&value->storage()) : nullptr;
        if (object == nullptr)
        {
            return std::nullopt;
        }
        return *object;
    }

    // The content of one device's `m.device_list_update` EDU from a display-name lookup and the device's key row
    // (nullptr when it published none), both built by the caller, so announcing a user's devices does not scan the
    // device tables per device.
    [[nodiscard]] auto device_list_update_content(database::PersistentStore const& store, std::string_view user_id,
                                                  std::string_view device_id, std::int64_t stream_id,
                                                  DeviceDisplayNames const& display_names,
                                                  database::PersistentDeviceKey const* device_key)
        -> std::optional<std::string>
    {
        auto content = canonicaljson::Object{};
        // Spec (SS API, m.device_list_update): `device_display_name` is "the public human-readable
        // name of this device. Will be absent if the device has no name."
        if (auto const name = display_names.find(user_id, device_id); name.has_value() && !name->empty())
        {
            content.push_back(
                canonicaljson::make_member("device_display_name", canonicaljson::Value{std::string{*name}}));
        }
        content.push_back(canonicaljson::make_member("device_id", canonicaljson::Value{std::string{device_id}}));
        if (device_key != nullptr)
        {
            // A receiving server may apply these keys directly instead of
            // refetching, so they must be exactly what /user/keys/query serves.
            if (auto keys = published_device_keys(store, *device_key, std::nullopt, display_names); keys.has_value())
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

} // namespace

namespace
{

    // The number of entries a request's `section` object names: each user, plus each device ID (a query) or
    // device (a claim) under it, and at least one for a user whose value is neither.
    [[nodiscard]] auto key_request_entry_count(canonicaljson::Object const& section) -> std::size_t
    {
        auto count = std::size_t{0U};
        for (auto const& user_member : section)
        {
            ++count;
            if (user_member.value == nullptr)
            {
                continue;
            }
            if (auto const* list = std::get_if<canonicaljson::Array>(&user_member.value->storage()); list != nullptr)
            {
                count += list->size();
            }
            else if (auto const* devices = std::get_if<canonicaljson::Object>(&user_member.value->storage());
                     devices != nullptr)
            {
                count += devices->size();
            }
        }
        return count;
    }

    // True when `user_id` is `localpart:server_name` for this server. A user of another server is skipped before
    // any table is read.
    [[nodiscard]] auto user_is_on_server(std::string_view user_id, std::string_view server_name) -> bool
    {
        auto const colon = user_id.find(':');
        return user_id.starts_with('@') && colon != std::string_view::npos && colon > 1U &&
               user_id.substr(colon + 1U) == server_name;
    }

} // namespace

auto key_request_exceeds_entry_cap(std::string_view request_body, std::string_view section) -> bool
{
    auto const request = parsed_value(request_body);
    auto const* root = request.has_value() ? std::get_if<canonicaljson::Object>(&request->storage()) : nullptr;
    auto const* entries = root == nullptr ? nullptr : as_object(member_value(*root, section));
    return entries != nullptr && key_request_entry_count(*entries) > max_key_request_entries;
}

auto build_device_keys_query_response(database::PersistentStore const& store, std::string_view request_body,
                                      std::string_view local_server_name) -> std::string
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

    if (key_request_entry_count(*requested) > max_key_request_entries)
    {
        log_diagnostic("key_query.rejected", {
                                                 {"reason", "request names too many entries", false}
        });
        return {};
    }

    auto device_keys = canonicaljson::Object{};
    auto master_keys = canonicaljson::Object{};
    auto self_signing_keys = canonicaljson::Object{};
    // The display names of every queried local user's devices, read through the per-user device index. A user of
    // another server is not this server's to answer for and costs no lookup.
    auto const display_names = [&] {
        auto queried_users = std::vector<std::string_view>{};
        queried_users.reserve(requested->size());
        for (auto const& user_member : *requested)
        {
            if (user_is_on_server(user_member.key, local_server_name))
            {
                queried_users.emplace_back(user_member.key);
            }
        }
        return DeviceDisplayNames{store, queried_users};
    }();
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
        auto wanted = std::set<std::string, std::less<>>{};
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
            wanted.insert(*id);
        }

        // Only this server's own users have anything to publish.
        if (!user_is_on_server(user_member.key, local_server_name))
        {
            continue;
        }
        auto user_devices = canonicaljson::Object{};
        database::for_each_user_device_key(
            store, user_member.key, [&](database::PersistentDeviceKey const& device_key) {
                if (!wanted.empty() && !wanted.contains(device_key.device_id))
                {
                    return true;
                }
                // Published with the owner's self-signing signature: without it
                // the remote user cannot tell the device is trusted by its owner.
                auto published = published_device_keys(store, device_key, std::nullopt, display_names);
                if (published.has_value())
                {
                    user_devices.push_back(
                        canonicaljson::make_member(device_key.device_id, canonicaljson::Value{std::move(*published)}));
                }
                return true;
            });
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
    auto const requested = std::set<std::string_view>{requested_users.begin(), requested_users.end()};
    if (auto const* device_keys = as_object(member_value(*root, "device_keys")); device_keys != nullptr)
    {
        auto seen_users = std::set<std::string_view>{};
        for (auto const& user_member : *device_keys)
        {
            auto const* devices = user_member.value == nullptr
                                      ? nullptr
                                      : std::get_if<canonicaljson::Object>(&user_member.value->storage());
            if (devices == nullptr || !requested.contains(user_member.key) || seen_users.contains(user_member.key))
            {
                ++dropped;
                continue;
            }
            seen_users.insert(user_member.key);
            auto user_devices = canonicaljson::Object{};
            auto seen_devices = std::set<std::string_view>{};
            for (auto const& device_member : *devices)
            {
                auto const* device = device_member.value == nullptr
                                         ? nullptr
                                         : std::get_if<canonicaljson::Object>(&device_member.value->storage());
                // Spec: device_id and user_id "Must match" the device and
                // user the keys belong to.
                if (device == nullptr || seen_devices.contains(device_member.key) ||
                    !string_member_equals(*device, "user_id", user_member.key) ||
                    !string_member_equals(*device, "device_id", device_member.key))
                {
                    ++dropped;
                    continue;
                }
                seen_devices.insert(device_member.key);
                user_devices.push_back(device_member);
            }
            accepted.device_keys.push_back(
                canonicaljson::make_member(user_member.key, canonicaljson::Value{std::move(user_devices)}));
        }
    }
    dropped += accept_remote_cross_signing_keys(*root, "master_keys", "master", requested, accepted.master_keys);
    dropped += accept_remote_cross_signing_keys(*root, "self_signing_keys", "self_signing", requested,
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

auto accept_remote_key_claim_response(std::string_view origin, std::string_view response_body,
                                      std::vector<std::pair<std::string, std::vector<std::string>>> const& requested)
    -> std::optional<RemoteKeyClaimKeys>
{
    auto const response = parsed_value(response_body);
    auto const* root = response.has_value() ? std::get_if<canonicaljson::Object>(&response->storage()) : nullptr;
    auto const* claimed = root == nullptr ? nullptr : as_object(member_value(*root, "one_time_keys"));
    if (claimed == nullptr)
    {
        log_diagnostic("remote_key_claim.rejected",
                       {
                           {"origin", std::string{origin},                                         false},
                           {"reason", "response is not a JSON object with a one_time_keys object", false}
        },
                       observability::LogEventSeverity::warning);
        return std::nullopt;
    }

    auto accepted = RemoteKeyClaimKeys{};
    auto dropped = std::size_t{0U};
    // The users and devices asked for, and the users already answered, as sets: the answer's size is the remote
    // server's to choose, so nothing here searches a list per key (ADR-0604).
    auto asked = std::map<std::string_view, std::set<std::string_view>>{};
    for (auto const& [user, devices_asked] : requested)
    {
        asked[user].insert(devices_asked.begin(), devices_asked.end());
    }
    auto answered_users = std::set<std::string_view>{};
    for (auto const& user_member : *claimed)
    {
        auto const wanted = asked.find(user_member.key);
        auto const* devices =
            user_member.value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&user_member.value->storage());
        // A user that was not asked of this server, or is named twice, is not this server's to speak for.
        if (wanted == asked.end() || devices == nullptr || answered_users.contains(user_member.key))
        {
            ++dropped;
            continue;
        }
        answered_users.insert(user_member.key);
        auto user_devices = canonicaljson::Object{};
        auto answered_devices = std::set<std::string_view>{};
        for (auto const& device_member : *devices)
        {
            auto const* keys = device_member.value == nullptr
                                   ? nullptr
                                   : std::get_if<canonicaljson::Object>(&device_member.value->storage());
            // Spec (POST /keys/claim): a device maps `<algorithm>:<key_id>` to `string|KeyObject`.
            auto const well_formed = keys != nullptr && !keys->empty() &&
                                     std::ranges::all_of(*keys, [](canonicaljson::ObjectMember const& key) {
                                         return key.value != nullptr &&
                                                (std::get_if<std::string>(&key.value->storage()) != nullptr ||
                                                 std::get_if<canonicaljson::Object>(&key.value->storage()) != nullptr);
                                     });
            if (!well_formed || !wanted->second.contains(device_member.key) ||
                answered_devices.contains(device_member.key))
            {
                ++dropped;
                continue;
            }
            answered_devices.insert(device_member.key);
            user_devices.push_back(device_member);
        }
        if (!user_devices.empty())
        {
            accepted.one_time_keys.push_back(
                canonicaljson::make_member(user_member.key, canonicaljson::Value{std::move(user_devices)}));
        }
    }
    if (dropped > 0U)
    {
        log_diagnostic("remote_key_claim.entries_dropped",
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
    auto const owner = std::array<std::string_view, 1U>{user_id};
    auto const display_names = DeviceDisplayNames{store, owner};
    auto const device_key = database::find_device_key(store, user_id, device_id);
    return device_list_update_content(store, user_id, device_id, stream_id, display_names,
                                      device_key.has_value() ? &*device_key : nullptr);
}

auto build_device_list_update_batch(database::PersistentStore const& store, std::string_view user_id,
                                    std::optional<std::string_view> only_device, std::int64_t stream_id)
    -> DeviceListUpdateBatch
{
    auto batch = DeviceListUpdateBatch{};
    // One lookup of the display names of this user's devices (a pass over `store.devices`) ...
    auto const owner = std::array<std::string_view, 1U>{user_id};
    auto const display_names = DeviceDisplayNames{store, owner};
    // ... and one index of this user's published keys. The first row for a device wins, as `find_if` did.
    auto keys_by_device = std::map<std::string_view, database::PersistentDeviceKey const*>{};
    database::for_each_user_device_key(store, user_id, [&](database::PersistentDeviceKey const& key) {
        keys_by_device.emplace(std::string_view{key.device_id}, &key);
        return true;
    });
    // The devices themselves, in table order (the order the per-device loop announced them in).
    database::for_each_user_device(store, user_id, [&](database::PersistentDevice const& device) {
        if (only_device.has_value() && device.device_id != *only_device)
        {
            return true;
        }
        auto const found = keys_by_device.find(std::string_view{device.device_id});
        auto const* const key = found == keys_by_device.end() ? nullptr : found->second;
        auto content = device_list_update_content(store, user_id, device.device_id, stream_id, display_names, key);
        if (content.has_value())
        {
            batch.entries.push_back({device.device_id, std::move(*content), key != nullptr});
        }
        return true;
    });
    return batch;
}

auto build_device_deleted_update_content(std::string_view user_id, std::string_view device_id, std::int64_t stream_id,
                                         std::span<std::int64_t const> prev_ids) -> std::optional<std::string>
{
    // Spec (SS API, m.device_list_update): `deleted` is "True if the server is announcing that this
    // device has been deleted"; `keys` and `device_display_name` are optional and say nothing about
    // a device that no longer exists, so neither is sent.
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("deleted", canonicaljson::Value{true}));
    content.push_back(canonicaljson::make_member("device_id", canonicaljson::Value{std::string{device_id}}));
    auto previous = canonicaljson::Array{};
    for (auto const prev_id : prev_ids)
    {
        previous.push_back(canonicaljson::Value{prev_id});
    }
    content.push_back(canonicaljson::make_member("prev_id", canonicaljson::Value{std::move(previous)}));
    content.push_back(canonicaljson::make_member("stream_id", canonicaljson::Value{stream_id}));
    content.push_back(canonicaljson::make_member("user_id", canonicaljson::Value{std::string{user_id}}));
    auto serialized = serialize(std::move(content));
    if (serialized.empty())
    {
        return std::nullopt;
    }
    return serialized;
}

auto build_one_time_keys_claim_response(database::PersistentStore& store, std::string_view request_body,
                                        std::string_view local_server_name) -> std::string
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

    if (key_request_entry_count(*requested) > max_key_request_entries)
    {
        log_diagnostic("otk_claim.rejected", {
                                                 {"reason", "request names too many entries", false}
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
        // A key is claimed from this server's own users only; another server's user costs no lookup.
        if (!user_is_on_server(user_member.key, local_server_name))
        {
            continue;
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
    auto const owner = std::array<std::string_view, 1U>{user_id};
    auto const display_names = DeviceDisplayNames{store, owner};
    database::for_each_user_device_key(store, user_id, [&](database::PersistentDeviceKey const& device_key) {
        auto keys = published_device_keys(store, device_key, std::nullopt, display_names);
        if (!keys.has_value())
        {
            return true;
        }
        auto device = canonicaljson::Object{};
        device.push_back(canonicaljson::make_member("device_id", canonicaljson::Value{device_key.device_id}));
        device.push_back(canonicaljson::make_member("keys", canonicaljson::Value{std::move(*keys)}));
        devices.push_back(canonicaljson::Value{std::move(device)});
        return true;
    });
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

auto accept_remote_user_devices_response(std::string_view origin, std::string_view user_id,
                                         std::string_view response_body) -> std::optional<RemoteDeviceList>
{
    auto const response = parsed_value(response_body);
    auto const* root = response.has_value() ? std::get_if<canonicaljson::Object>(&response->storage()) : nullptr;
    if (root == nullptr)
    {
        log_refused_user_devices(origin, user_id, "response is not a JSON object");
        return std::nullopt;
    }
    auto const stream_id = integer_value(member_value(*root, "stream_id"));
    auto const* devices = member_value(*root, "devices");
    auto const* device_list = devices == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&devices->storage());
    if (!string_member_equals(*root, "user_id", user_id) || !stream_id.has_value() || device_list == nullptr)
    {
        log_refused_user_devices(origin, user_id, "user_id, stream_id or devices missing or wrong");
        return std::nullopt;
    }
    auto list = RemoteDeviceList{};
    list.stream_id = *stream_id;
    for (auto const& entry : *device_list)
    {
        auto const* device = std::get_if<canonicaljson::Object>(&entry.storage());
        auto const* device_id = device == nullptr ? nullptr : string_value(member_value(*device, "device_id"));
        if (!cached_device_id_is_usable(device_id) || list.devices.contains(*device_id))
        {
            log_refused_user_devices(origin, user_id, "a device entry has no usable or a repeated device_id");
            return std::nullopt;
        }
        auto cached = RemoteCachedDevice{};
        if (auto const* keys_value = member_value(*device, "keys"); keys_value != nullptr)
        {
            auto const* keys = as_object(keys_value);
            auto kept = keys == nullptr ? std::nullopt : cacheable_device_keys(*keys, user_id, *device_id);
            if (!kept.has_value())
            {
                log_refused_user_devices(origin, user_id, "a device's keys are not filed under it");
                return std::nullopt;
            }
            cached.keys_json = std::move(*kept);
            cached.display_name = unsigned_display_name(*keys);
        }
        if (auto const* name_value = member_value(*device, "device_display_name"); name_value != nullptr)
        {
            auto const* name = string_value(name_value);
            if (name == nullptr)
            {
                log_refused_user_devices(origin, user_id, "a device_display_name is not a string");
                return std::nullopt;
            }
            cached.display_name = *name;
        }
        list.devices.emplace(*device_id, std::move(cached));
    }
    auto refused = false;
    list.master_key_json = cacheable_cross_signing_key(*root, "master_key", user_id, "master", refused);
    list.self_signing_key_json =
        cacheable_cross_signing_key(*root, "self_signing_key", user_id, "self_signing", refused);
    if (refused)
    {
        log_refused_user_devices(origin, user_id, "a cross-signing key is not the user's key for its usage");
        return std::nullopt;
    }
    return list;
}

auto parse_remote_device_list_update(canonicaljson::Object const& content) -> std::optional<RemoteDeviceListUpdate>
{
    auto const* user_id = string_value(member_value(content, "user_id"));
    auto const* device_id = string_value(member_value(content, "device_id"));
    auto const stream_id = integer_value(member_value(content, "stream_id"));
    if (user_id == nullptr || !cached_device_id_is_usable(device_id) || !stream_id.has_value())
    {
        return std::nullopt;
    }
    auto update = RemoteDeviceListUpdate{};
    update.user_id = *user_id;
    update.device_id = *device_id;
    update.stream_id = *stream_id;
    if (auto const* prev = member_value(content, "prev_id"); prev != nullptr)
    {
        auto const* prev_ids = std::get_if<canonicaljson::Array>(&prev->storage());
        if (prev_ids == nullptr)
        {
            return std::nullopt;
        }
        for (auto const& entry : *prev_ids)
        {
            auto const* number = std::get_if<std::int64_t>(&entry.storage());
            if (number == nullptr)
            {
                return std::nullopt;
            }
            update.prev_ids.push_back(*number);
        }
    }
    if (auto const* deleted = member_value(content, "deleted"); deleted != nullptr)
    {
        auto const* flag = std::get_if<bool>(&deleted->storage());
        if (flag == nullptr)
        {
            return std::nullopt;
        }
        update.deleted = *flag;
    }
    if (auto const* keys_value = member_value(content, "keys"); keys_value != nullptr)
    {
        auto const* keys = as_object(keys_value);
        auto kept = keys == nullptr ? std::nullopt : cacheable_device_keys(*keys, *user_id, *device_id);
        if (!kept.has_value())
        {
            return std::nullopt;
        }
        update.device.keys_json = std::move(*kept);
        update.device.display_name = unsigned_display_name(*keys);
    }
    if (auto const* name_value = member_value(content, "device_display_name"); name_value != nullptr)
    {
        auto const* name = string_value(name_value);
        if (name == nullptr)
        {
            return std::nullopt;
        }
        update.device.display_name = *name;
    }
    return update;
}

auto remote_key_query_keys_from_cache(std::string_view user_id, RemoteDeviceList const& list) -> RemoteKeyQueryKeys
{
    auto keys = RemoteKeyQueryKeys{};
    auto devices = canonicaljson::Object{};
    for (auto const& [device_id, device] : list.devices)
    {
        auto device_keys = device.keys_json.empty() ? std::nullopt : parsed_object_json(device.keys_json);
        if (!device_keys.has_value())
        {
            continue;
        }
        if (device.display_name.has_value())
        {
            auto unsigned_data = canonicaljson::Object{};
            unsigned_data.push_back(
                canonicaljson::make_member("device_display_name", canonicaljson::Value{*device.display_name}));
            device_keys->push_back(
                canonicaljson::make_member("unsigned", canonicaljson::Value{std::move(unsigned_data)}));
        }
        devices.push_back(canonicaljson::make_member(device_id, canonicaljson::Value{std::move(*device_keys)}));
    }
    keys.device_keys.push_back(
        canonicaljson::make_member(std::string{user_id}, canonicaljson::Value{std::move(devices)}));
    auto const add_cross_signing = [user_id](std::optional<std::string> const& json, canonicaljson::Object& into) {
        auto key = json.has_value() ? parsed_object_json(*json) : std::nullopt;
        if (key.has_value())
        {
            into.push_back(canonicaljson::make_member(std::string{user_id}, canonicaljson::Value{std::move(*key)}));
        }
    };
    add_cross_signing(list.master_key_json, keys.master_keys);
    add_cross_signing(list.self_signing_key_json, keys.self_signing_keys);
    return keys;
}

} // namespace merovingian::federation
