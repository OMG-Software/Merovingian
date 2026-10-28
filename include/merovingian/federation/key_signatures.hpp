// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::federation
{

// Serving published E2EE keys with the signatures uploaded through
// `POST /_matrix/client/v3/keys/signatures/upload` merged in.
//
// Matrix v1.19 returns each key "along with the signatures uploaded via
// /keys/signatures/upload that the requesting user is allowed to see". A
// stored upload is visible to a viewer when it was uploaded by the key's
// owner (self-signatures are public — they are what lets anyone check a
// device against its owner's self-signing key), or when the viewer uploaded
// it themselves (a user-signing-key signature over someone else's master
// key is private to the user who verified them). A `viewer_user_id` of
// std::nullopt is a remote server over federation, which has no user and so
// sees owner signatures only. From each upload, only the uploader's own
// signer entry is merged: nobody can publish a signature under another
// user's name. See ADR-0060.

// The key ID a cross-signing key is addressed by in
// `/keys/signatures/upload`: its unpadded base64 public key, which is the
// `keys` property name with the `<algorithm>:` prefix removed. std::nullopt
// unless `keys` holds exactly one property of that form.
[[nodiscard]] auto cross_signing_key_id(canonicaljson::Object const& key_object) -> std::optional<std::string>;

// Merges into `key_object`'s `signatures` every stored signature on
// (`target_user_id`, `target_key_id`) that `viewer_user_id` may see. Device
// keys are addressed by device ID, cross-signing keys by cross_signing_key_id().
auto merge_visible_key_signatures(canonicaljson::Object& key_object, database::PersistentStore const& store,
                                  std::string_view target_user_id, std::string_view target_key_id,
                                  std::optional<std::string_view> viewer_user_id) -> void;

// The display names of the devices of a set of users, read from `store.devices` in one pass. A key query
// names its users up front; building this once for them keeps the lookup for every published key off the
// device table, which holds every device on the server and is scanned under the runtime lock (work there is
// bounded by the request). Holds views into `store`, so it is valid only while `store.devices` is unchanged:
// build it inside the request and drop it with the response.
class DeviceDisplayNames final
{
public:
    DeviceDisplayNames(database::PersistentStore const& store, std::span<std::string_view const> users);

    // The device's display name, empty when it has none. std::nullopt when the lookup holds no row for the
    // device: it does not exist, or its user was not among those the lookup was built for.
    [[nodiscard]] auto find(std::string_view user_id, std::string_view device_id) const
        -> std::optional<std::string_view>;

private:
    std::map<std::pair<std::string_view, std::string_view>, std::string_view> names_{};
};

// `device_key` as published to `viewer_user_id`: the stored DeviceKeys object
// with the visible signatures merged and `unsigned.device_display_name` set to
// the device's display name as it is now (absent when it has none), since the
// stored object holds the name at upload time. `names` must cover the device's
// user; a device it holds no row for keeps whatever name was stored. std::nullopt
// when the stored JSON is not an object.
[[nodiscard]] auto published_device_keys(database::PersistentStore const& store,
                                         database::PersistentDeviceKey const& device_key,
                                         std::optional<std::string_view> viewer_user_id,
                                         DeviceDisplayNames const& names) -> std::optional<canonicaljson::Object>;

// As above for one key on its own: builds the lookup for the key's user, so it walks the device table once
// per call. Use the overload taking `names` wherever several keys are published.
[[nodiscard]] auto published_device_keys(database::PersistentStore const& store,
                                         database::PersistentDeviceKey const& device_key,
                                         std::optional<std::string_view> viewer_user_id)
    -> std::optional<canonicaljson::Object>;

// `user_id`'s stored cross-signing key of `key_type` ("master", "self_signing"
// or "user_signing") as published to `viewer_user_id`, with the visible
// signatures merged. std::nullopt when the user has no such key.
[[nodiscard]] auto published_cross_signing_key(database::PersistentStore const& store, std::string_view user_id,
                                               std::string_view key_type,
                                               std::optional<std::string_view> viewer_user_id)
    -> std::optional<canonicaljson::Object>;

} // namespace merovingian::federation
