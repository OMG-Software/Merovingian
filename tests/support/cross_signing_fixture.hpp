// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// A master, self-signing and user-signing key set with real Ed25519 keys and real signatures, for tests
// that upload through POST /keys/device_signing/upload. The endpoint verifies the self-signing and
// user-signing keys' signatures by the master key (Client-Server API, CrossSigningKey), so a fixture with
// invented key text and signature text cannot be uploaded.

#include "CrossSigningKeyPair.hpp"
#include "CrossSigningSet.hpp"
#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/signable.hpp"
#include "merovingian/core/SecretBuffer.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/events/event_signer.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>
#include <utility>

namespace merovingian::tests
{

[[nodiscard]] inline auto generate_cross_signing_key_pair_once() -> CrossSigningKeyPair
{
    auto generated = crypto::generate_ed25519_keypair();
    REQUIRE(generated.has_value());
    auto pair = CrossSigningKeyPair{};
    pair.public_key = events::matrix_base64_from_bytes(
        std::string_view{reinterpret_cast<char const*>(generated->public_key.data()), generated->public_key.size()});
    pair.secret_key = std::move(generated->secret_key);
    return pair;
}

// With `alphanumeric_public_key`, keys are drawn until the unpadded base64 holds no '+' or '/', for a test that
// also uses a key as a device ID (a device ID is limited to alphanumeric characters).
[[nodiscard]] inline auto generate_cross_signing_key_pair(bool alphanumeric_public_key = false) -> CrossSigningKeyPair
{
    for (;;)
    {
        auto pair = generate_cross_signing_key_pair_once();
        if (!alphanumeric_public_key || pair.public_key.find_first_of("+/") == std::string::npos)
        {
            return pair;
        }
    }
}

// `{"keys":{"ed25519:<public>":"<public>"},"usage":["<usage>"],"user_id":"<user>"}`, unsigned.
[[nodiscard]] inline auto unsigned_cross_signing_key_json(std::string const& user_id, std::string const& usage,
                                                          std::string const& public_key) -> std::string
{
    return R"({"keys":{"ed25519:)" + public_key + R"(":")" + public_key + R"("},"usage":[")" + usage +
           R"("],"user_id":")" + user_id + R"("})";
}

// `key_json` with `signatures.<signing_user>.ed25519:<signer public>` added: the signer's signature over the
// key's canonical JSON without `signatures` and `unsigned`. Signatures already on the key are kept.
[[nodiscard]] inline auto sign_cross_signing_key_json(std::string const& key_json, std::string const& signing_user,
                                                      CrossSigningKeyPair const& signer) -> std::string
{
    auto parsed = canonicaljson::parse_lossless(key_json);
    REQUIRE(parsed.error == canonicaljson::ParseError::none);
    auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    REQUIRE(object != nullptr);
    auto const signable = canonicaljson::make_signable_object_view(parsed.value);
    REQUIRE(signable.error == canonicaljson::CanonicalJsonError::none);
    auto const signature = crypto::ed25519_sign_detached(signer.secret_key.bytes(), signable.output);
    REQUIRE(signature.has_value());
    auto inner = canonicaljson::Object{};
    inner.push_back(canonicaljson::make_member(
        "ed25519:" + signer.public_key, canonicaljson::Value{events::matrix_base64_from_bytes(signature->bytes)}));
    auto signatures = canonicaljson::Object{};
    signatures.push_back(canonicaljson::make_member(signing_user, canonicaljson::Value{std::move(inner)}));
    auto signed_object = canonicaljson::Object{};
    for (auto const& member : *object)
    {
        if (member.value != nullptr)
        {
            signed_object.push_back(canonicaljson::make_member(member.key, *member.value));
        }
    }
    signed_object.push_back(canonicaljson::make_member("signatures", canonicaljson::Value{std::move(signatures)}));
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(signed_object)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

// The body of POST /keys/device_signing/upload: `members` (see CrossSigningSet) with password UIA.
[[nodiscard]] inline auto cross_signing_upload_body(std::string const& members,
                                                    std::string const& password = "CorrectHorse7!") -> std::string
{
    return "{" + members + R"(,"auth":{"type":"m.login.password","password":")" + password + R"("}})";
}

[[nodiscard]] inline auto make_cross_signing_set(std::string const& user_id, bool alphanumeric_public_keys = false)
    -> CrossSigningSet
{
    auto set = CrossSigningSet{};
    set.user_id = user_id;
    set.master = generate_cross_signing_key_pair(alphanumeric_public_keys);
    set.self_signing = generate_cross_signing_key_pair(alphanumeric_public_keys);
    set.user_signing = generate_cross_signing_key_pair(alphanumeric_public_keys);
    set.master_json = unsigned_cross_signing_key_json(user_id, "master", set.master.public_key);
    set.self_signing_json = sign_cross_signing_key_json(
        unsigned_cross_signing_key_json(user_id, "self_signing", set.self_signing.public_key), user_id, set.master);
    set.user_signing_json = sign_cross_signing_key_json(
        unsigned_cross_signing_key_json(user_id, "user_signing", set.user_signing.public_key), user_id, set.master);
    return set;
}

// A complete upload body for a user with freshly generated keys, when the test needs none of the keys again.
[[nodiscard]] inline auto fresh_cross_signing_upload_body(std::string const& user_id, bool master_key,
                                                          bool self_signing_key, bool user_signing_key) -> std::string
{
    return cross_signing_upload_body(
        make_cross_signing_set(user_id).selected_members(master_key, self_signing_key, user_signing_key));
}

} // namespace merovingian::tests
