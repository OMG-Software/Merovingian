// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <optional>
#include <string>
#include <string_view>

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

// `device_key` as published to `viewer_user_id`: the stored DeviceKeys object
// with the visible signatures merged. std::nullopt when the stored JSON is not
// an object.
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
