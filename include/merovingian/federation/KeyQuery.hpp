// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/DeviceListUpdateBatch.hpp"
#include "merovingian/federation/RemoteDeviceList.hpp"
#include "merovingian/federation/RemoteDeviceListUpdate.hpp"
#include "merovingian/federation/RemoteKeyClaimKeys.hpp"
#include "merovingian/federation/RemoteKeyQueryKeys.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::federation
{

// Builds the canonical-JSON response body for an inbound federation
// `POST /_matrix/federation/v1/user/keys/query`. `request_body` is the
// `{"device_keys": {"@user": ["device", ...]}}` request; an empty device list
// selects every published device for that user. The response carries
// `device_keys`, `master_keys`, and `self_signing_keys`, each with the key
// owner's own uploaded signatures merged in (KeySignatures.hpp). Returns an
// empty string when the request body is not canonical-parseable.
//
// The request is refused whole (an empty string) when it names more than `max_key_request_entries` users and
// devices, and users of other servers are skipped before any table is read: a server answers for its own users
// (`local_server_name`) only, and an entry costs a lookup, not a scan (ADR-0604).
[[nodiscard]] auto build_device_keys_query_response(database::PersistentStore const& store,
                                                    std::string_view request_body, std::string_view local_server_name)
    -> std::string;

// The most entries one `/user/keys/query` or `/user/keys/claim` request may name, counting each user and each
// device or algorithm entry under it. A federated server batches by room, so a real request names the users it
// shares rooms with, a few thousand at most; the 1 MiB body limit already stops a request near 25000 entries
// (ADR-0604). A request over it is answered 413 `M_TOO_LARGE`.
inline constexpr auto max_key_request_entries = std::size_t{25000U};

// True when the body's `section` object (`device_keys` for a query, `one_time_keys` for a claim) names more than
// `max_key_request_entries` entries. False for a body that does not parse: the builders refuse that as malformed.
[[nodiscard]] auto key_request_exceeds_entry_cap(std::string_view request_body, std::string_view section) -> bool;

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

// Accepts `origin`'s `/user/keys/claim` response to a claim for `requested` (user ID -> the device IDs
// asked for; every user is on `origin`). Keeps only users that were requested, only devices that were
// requested of them, and only a device whose value is a non-empty object of key ID -> string or object
// (the spec's `string|KeyObject`). A user named twice keeps its first entry. A remote server has no
// authority over users it was not asked about, and a duplicate user would make the client response
// unserialisable. Anything dropped is logged. std::nullopt when the body is not a JSON object with a
// `one_time_keys` object (the caller records that as a failure of `origin`).
[[nodiscard]] auto accept_remote_key_claim_response(
    std::string_view origin, std::string_view response_body,
    std::vector<std::pair<std::string, std::vector<std::string>>> const& requested)
    -> std::optional<RemoteKeyClaimKeys>;

// Builds the content of an `m.signing_key_update` EDU announcing `user_id`'s
// current master and self-signing keys, with the owner's own signatures. The
// user-signing key is private and never included. std::nullopt when the user
// has neither key.
[[nodiscard]] auto build_signing_key_update_content(database::PersistentStore const& store, std::string_view user_id)
    -> std::optional<std::string>;

// Builds the content of an `m.device_list_update` EDU for one of `user_id`'s
// devices. `keys` carries the device keys as published over federation —
// with the owner's cross-signing signatures — and is omitted when the device
// has published none. `device_display_name` is the device's current name and
// is omitted when it has none. std::nullopt only if serialisation fails.
[[nodiscard]] auto build_device_list_update_content(database::PersistentStore const& store, std::string_view user_id,
                                                    std::string_view device_id, std::int64_t stream_id)
    -> std::optional<std::string>;

// Builds the `m.device_list_update` contents for all of `user_id`'s devices (or only `only_device`) with ONE
// display-name lookup and ONE index of the user's published device keys, so the cost is a fixed number of passes over
// `store.devices` and `store.device_keys` however many devices the user holds (F-05, ADR-0582). Each entry is
// byte-for-byte what `build_device_list_update_content` returns for the same device and stream_id. A device whose
// content cannot be serialised is left out.
[[nodiscard]] auto build_device_list_update_batch(database::PersistentStore const& store, std::string_view user_id,
                                                  std::optional<std::string_view> only_device, std::int64_t stream_id)
    -> DeviceListUpdateBatch;

// Builds the content of an `m.device_list_update` EDU announcing that one of
// `user_id`'s devices has been deleted: `deleted: true`, the device ID, the
// stream_id and the `prev_id` list, and no `keys` or `device_display_name`
// (the device no longer exists). std::nullopt only if serialisation fails.
[[nodiscard]] auto build_device_deleted_update_content(std::string_view user_id, std::string_view device_id,
                                                       std::int64_t stream_id, std::span<std::int64_t const> prev_ids)
    -> std::optional<std::string>;

// Builds the response body for `POST /_matrix/federation/v1/user/keys/claim`
// and consumes the claimed one-time keys from the store. `request_body` is the
// `{"one_time_keys": {"@user": {"device": "algorithm"}}}` request. Returns an
// empty string when the request body is not canonical-parseable.
//
// Refused whole (an empty string) over `max_key_request_entries`; a user of another server is skipped before any
// table is read (ADR-0604).
[[nodiscard]] auto build_one_time_keys_claim_response(database::PersistentStore& store, std::string_view request_body,
                                                      std::string_view local_server_name) -> std::string;

// Builds the response body for `GET /_matrix/federation/v1/user/devices/{userId}`.
// Device keys and cross-signing keys carry the owner's own uploaded
// signatures, as in build_device_keys_query_response. Returns an empty string
// when the user has no published device keys (the HTTP handler maps this to
// 404 M_NOT_FOUND per Matrix SS API v1.19).
[[nodiscard]] auto build_user_devices_response(database::PersistentStore const& store, std::string_view user_id)
    -> std::string;

// Accepts `origin`'s answer to `GET /_matrix/federation/v1/user/devices/{userId}` for `user_id` (a user of `origin`)
// as the remote device-list cache's snapshot of that user (ADR-0560). Refused whole (std::nullopt, logged) unless it is
// an object naming `user_id`, with an integer `stream_id`, a `devices` array whose every entry has a distinct
// non-empty `device_id` of at most 255 bytes and `keys` (when present) filed under that user and device, and
// `master_key` / `self_signing_key` (when present) valid for the user and their usage. A cache must not hold half a
// list: one bad entry means the list is not cached and the user is asked for with `/user/keys/query` instead.
// The display name is the entry's `device_display_name`, else the keys' `unsigned.device_display_name`.
[[nodiscard]] auto accept_remote_user_devices_response(std::string_view origin, std::string_view user_id,
                                                       std::string_view response_body)
    -> std::optional<RemoteDeviceList>;

// Reads the content of an `m.device_list_update` EDU (ADR-0561). std::nullopt unless `user_id` and `device_id` are
// strings (the device ID non-empty, at most 255 bytes), `stream_id` is an integer, `prev_id` (when present) an array
// of integers, `deleted` (when present) a boolean, `device_display_name` (when present) a string and `keys` (when
// present) an object filed under that user and device. The caller binds `user_id` to the sending origin.
[[nodiscard]] auto parse_remote_device_list_update(canonicaljson::Object const& content)
    -> std::optional<RemoteDeviceListUpdate>;

// The keys of a cached list as a `/user/keys/query` answer for `user_id` would carry them: `device_keys` holds every
// device with keys, each with `unsigned.device_display_name` when it has a name, and `master_keys` /
// `self_signing_keys` the user's cross-signing keys. Ready for the same merge as an answer from the user's server.
[[nodiscard]] auto remote_key_query_keys_from_cache(std::string_view user_id, RemoteDeviceList const& list)
    -> RemoteKeyQueryKeys;

} // namespace merovingian::federation
