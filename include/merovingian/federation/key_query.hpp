// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"

#include <string>
#include <string_view>

namespace merovingian::federation
{

// Builds the canonical-JSON response body for an inbound federation
// `POST /_matrix/federation/v1/user/keys/query`. `request_body` is the
// `{"device_keys": {"@user": ["device", ...]}}` request; an empty device list
// selects every published device for that user. The response carries
// `device_keys`, `master_keys`, and `self_signing_keys`. Returns an empty
// string when the request body is not canonical-parseable.
[[nodiscard]] auto build_device_keys_query_response(database::PersistentStore const& store,
                                                    std::string_view request_body) -> std::string;

// Builds the response body for `POST /_matrix/federation/v1/user/keys/claim`
// and consumes the claimed one-time keys from the store. `request_body` is the
// `{"one_time_keys": {"@user": {"device": "algorithm"}}}` request. Returns an
// empty string when the request body is not canonical-parseable.
[[nodiscard]] auto build_one_time_keys_claim_response(database::PersistentStore& store, std::string_view request_body)
    -> std::string;

// Builds the response body for `GET /_matrix/federation/v1/user/devices/{userId}`.
// Returns an empty string when the user has no published device keys (the HTTP
// handler maps this to 404 M_NOT_FOUND per Matrix SS API v1.18).
[[nodiscard]] auto build_user_devices_response(database::PersistentStore const& store, std::string_view user_id)
    -> std::string;

} // namespace merovingian::federation
