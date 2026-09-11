// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

// Builds the canonical-JSON response body for an inbound federation
// `POST /_matrix/federation/v1/user/keys/query`. `request_body` is the
// `{"device_keys": {"@user": ["device", ...]}}` request; an empty device list
// selects every published device for that user. The response carries
// `device_keys`, `master_keys`, and `self_signing_keys`, each with the key
// owner's own uploaded signatures merged in (key_signatures.hpp). Returns an
// empty string when the request body is not canonical-parseable.
[[nodiscard]] auto build_device_keys_query_response(database::PersistentStore const& store,
                                                    std::string_view request_body) -> std::string;

// The keys a remote server returned from
// `POST /_matrix/federation/v1/user/keys/query`, reduced to what it may
// speak for. Each member is keyed by user ID, as in the response.
struct RemoteKeyQueryKeys final
{
    canonicaljson::Object device_keys{};
    canonicaljson::Object master_keys{};
    canonicaljson::Object self_signing_keys{};
};

// Accepts `origin`'s `/user/keys/query` response to a query for
// `requested_users` (all of which are on `origin`). Keeps only entries for
// requested users, and only keys that describe the user they are filed
// under: a device whose `user_id` and `device_id` match its position, a
// master or self-signing key whose `user_id` matches, whose `usage` names its
// role, and which holds exactly one public key. Anything else is dropped and
// logged — a remote server has no authority over users it was not asked
// about, and a client would otherwise take an injected master key as that
// user's identity. `user_signing_keys` is never accepted over federation.
// std::nullopt when the body is not a JSON object.
[[nodiscard]] auto accept_remote_key_query_response(std::string_view origin, std::string_view response_body,
                                                    std::vector<std::string> const& requested_users)
    -> std::optional<RemoteKeyQueryKeys>;

// Builds the content of an `m.signing_key_update` EDU announcing `user_id`'s
// current master and self-signing keys, with the owner's own signatures. The
// user-signing key is private and never included. std::nullopt when the user
// has neither key.
[[nodiscard]] auto build_signing_key_update_content(database::PersistentStore const& store, std::string_view user_id)
    -> std::optional<std::string>;

// Builds the content of an `m.device_list_update` EDU for one of `user_id`'s
// devices. `keys` carries the device keys as published over federation —
// with the owner's cross-signing signatures — and is omitted when the device
// has published none. std::nullopt only if serialisation fails.
[[nodiscard]] auto build_device_list_update_content(database::PersistentStore const& store, std::string_view user_id,
                                                    std::string_view device_id, std::int64_t stream_id)
    -> std::optional<std::string>;

// Builds the response body for `POST /_matrix/federation/v1/user/keys/claim`
// and consumes the claimed one-time keys from the store. `request_body` is the
// `{"one_time_keys": {"@user": {"device": "algorithm"}}}` request. Returns an
// empty string when the request body is not canonical-parseable.
[[nodiscard]] auto build_one_time_keys_claim_response(database::PersistentStore& store, std::string_view request_body)
    -> std::string;

// Builds the response body for `GET /_matrix/federation/v1/user/devices/{userId}`.
// Device keys and cross-signing keys carry the owner's own uploaded
// signatures, as in build_device_keys_query_response. Returns an empty string
// when the user has no published device keys (the HTTP handler maps this to
// 404 M_NOT_FOUND per Matrix SS API v1.19).
[[nodiscard]] auto build_user_devices_response(database::PersistentStore const& store, std::string_view user_id)
    -> std::string;

} // namespace merovingian::federation
