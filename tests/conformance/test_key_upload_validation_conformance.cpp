// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Cross-signing key uploads are judged before anything is stored and stored in one transaction, and
// a key backup batch upload stores all of its sessions or answers an error.
//
// Spec: Matrix Client-Server API v1.19
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3keysdevice_signingupload
//      ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3room_keyskeys

#include "../support/CrossSigningKeyPair.hpp"
#include "../support/CrossSigningFixture.hpp"
#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto upload_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

struct Reply final
{
    std::uint16_t status{0U};
    std::string body{};
};

[[nodiscard]] auto call(ClientServerRuntime& rt, std::string method, std::string target, std::string const& token,
                        std::string body = {}) -> Reply
{
    auto const result = merovingian::homeserver::handle_client_server_request(
        rt, {std::move(method), std::move(target), token, std::move(body)}, /*can_wait=*/false);
    return {static_cast<std::uint16_t>(result.response.status), result.response.body};
}

[[nodiscard]] auto register_and_login(ClientServerRuntime& rt, std::string const& localpart) -> std::string
{
    REQUIRE(
        call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json(localpart, "CorrectHorse7!")).status ==
        200U);
    auto const login =
        call(rt, "POST", "/_matrix/client/v3/login", {},
             std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} + localpart +
                 R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + localpart + R"(_DEV"})");
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

constexpr auto auth_member = R"("auth":{"type":"m.login.password","password":"CorrectHorse7!"})";

[[nodiscard]] auto upload_keys(ClientServerRuntime& rt, std::string const& token, std::string const& members) -> Reply
{
    return call(rt, "POST", "/_matrix/client/v3/keys/device_signing/upload", token,
                "{" + members + "," + auth_member + "}");
}

[[nodiscard]] auto held_cross_signing_keys(ClientServerRuntime const& rt) -> std::size_t
{
    return rt.homeserver.database.persistent_store.cross_signing_keys.size();
}

void create_backup(ClientServerRuntime& rt, std::string const& token)
{
    REQUIRE(
        call(
            rt, "POST", "/_matrix/client/v3/room_keys/version", token,
            R"({"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abc","signatures":{}}})")
            .status == 200U);
}

constexpr auto batch_path = "/_matrix/client/v3/room_keys/keys?version=1";

[[nodiscard]] auto session(std::string const& ciphertext) -> std::string
{
    return R"({"first_message_index":0,"forwarded_count":0,"is_verified":false,"session_data":{"ciphertext":")" +
           ciphertext + R"(","ephemeral":"e","mac":"m"}})";
}

} // namespace

// Spec: POST /keys/device_signing/upload, CrossSigningKey: `keys`, `usage` and `user_id` are required;
// "The object must have exactly one property, whose name is in the form
// `<algorithm>:<unpadded_base64_public_key>`". Responses: 400 `M_MISSING_PARAM` "No master signing key is
// available"; 403 "the request is not authorised for any other reason".
SCENARIO("a cross-signing upload is judged before anything is stored",
         "[conformance][client-server][cross-signing][upload-validation]")
{
    GIVEN("a user who has uploaded a master, self-signing and user-signing key")
    {
        auto started = merovingian::homeserver::start_client_server(upload_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const set = make_cross_signing_set("@alice:example.org");
        auto const first = upload_keys(rt, token, set.members());
        INFO(first.body);
        REQUIRE(first.status == 200U);
        REQUIRE(held_cross_signing_keys(rt) == 3U);
        // The master key is the one every other key is signed by, so checking it survives shows a refused upload
        // stored nothing: a replaced master key would show here even if the key count stayed at three.
        auto const holds_original_master = [&rt, &set] {
            auto const& keys = rt.homeserver.database.persistent_store.cross_signing_keys;
            return std::ranges::any_of(keys, [&set](merovingian::database::PersistentCrossSigningKey const& key) {
                return key.key_type == "master" && key.json.find(set.master.public_key) != std::string::npos;
            });
        };

        // Ownership: the spec makes a key for any other user "not authorised", which is a 403 rather than a 400.
        WHEN("a key names another user")
        {
            auto const other = generate_cross_signing_key_pair();
            auto const reply =
                upload_keys(rt, token,
                            R"("master_key":)" +
                                unsigned_cross_signing_key_json("@mallory:example.org", "master", other.public_key));

            THEN("it is refused with 403 and the held keys are unchanged")
            {
                CHECK(reply.status == 403U);
                CHECK(held_cross_signing_keys(rt) == 3U);
                CHECK(holds_original_master());
            }
        }

        // The key is signed and owned correctly, so only its declared usage is wrong. That must still be refused.
        WHEN("a self-signing key is uploaded with the usage of a master key")
        {
            auto const other = generate_cross_signing_key_pair();
            auto const reply =
                upload_keys(rt, token,
                            R"("self_signing_key":)" +
                                sign_cross_signing_key_json(
                                    unsigned_cross_signing_key_json("@alice:example.org", "master", other.public_key),
                                    "@alice:example.org", set.master));

            THEN("it is refused with 400 and nothing is stored")
            {
                CHECK(reply.status == 400U);
                CHECK(held_cross_signing_keys(rt) == 3U);
            }
        }

        // Both shapes break the "exactly one property" rule, and each is sent as its own request.
        WHEN("a key's keys object is empty or holds two properties")
        {
            auto const empty =
                upload_keys(rt, token, R"("master_key":{"user_id":"@alice:example.org","usage":["master"],"keys":{}})");
            auto const two = upload_keys(
                rt, token,
                R"("master_key":{"user_id":"@alice:example.org","usage":["master"],"keys":{"ed25519:A":"A","ed25519:B":"B"}})");

            THEN("both are refused with 400 and the held master key is unchanged")
            {
                CHECK(empty.status == 400U);
                CHECK(two.status == 400U);
                CHECK(held_cross_signing_keys(rt) == 3U);
                CHECK(holds_original_master());
            }
        }

        WHEN("a key has no user_id or no usage")
        {
            auto const other = generate_cross_signing_key_pair();
            auto const no_user = upload_keys(rt, token,
                                             R"("master_key":{"usage":["master"],"keys":{"ed25519:)" +
                                                 other.public_key + R"(":")" + other.public_key + R"("}})");
            auto const no_usage = upload_keys(rt, token,
                                              R"("master_key":{"user_id":"@alice:example.org","keys":{"ed25519:)" +
                                                  other.public_key + R"(":")" + other.public_key + R"("}})");

            THEN("both are refused with 400")
            {
                CHECK(no_user.status == 400U);
                CHECK(no_usage.status == 400U);
                CHECK(held_cross_signing_keys(rt) == 3U);
                CHECK(holds_original_master());
            }
        }

        // The master key is valid on its own. Its survival unchanged shows the keys are judged as a set before any
        // is written.
        WHEN("a valid master key is uploaded beside a user-signing key for another user")
        {
            auto const new_master = generate_cross_signing_key_pair();
            auto const other = generate_cross_signing_key_pair();
            auto const reply = upload_keys(
                rt, token,
                R"("master_key":)" +
                    unsigned_cross_signing_key_json("@alice:example.org", "master", new_master.public_key) +
                    R"(,"user_signing_key":)" +
                    sign_cross_signing_key_json(
                        unsigned_cross_signing_key_json("@mallory:example.org", "user_signing", other.public_key),
                        "@alice:example.org", new_master));

            THEN("the upload is refused as a whole and the master key is not replaced")
            {
                CHECK(reply.status == 403U);
                CHECK(held_cross_signing_keys(rt) == 3U);
                CHECK(holds_original_master());
            }
        }

        // A write failure after validation passed: the three keys are written together, so none may be left
        // replaced.
        WHEN("the store fails while the keys are written")
        {
            rt.homeserver.database.persistent_store.force_failure_statement_names.emplace("upsert_cross_signing_key");
            auto const replacement = make_cross_signing_set("@alice:example.org");
            auto const reply = upload_keys(rt, token, replacement.members());

            THEN("the request fails and the previous set of keys is intact")
            {
                CHECK(reply.status == 500U);
                CHECK(held_cross_signing_keys(rt) == 3U);
                CHECK(holds_original_master());
            }
        }
    }

    // Separate user, so no master key is held to fall back on.
    GIVEN("a user with no master key")
    {
        auto started = merovingian::homeserver::start_client_server(upload_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "bob");
        auto const set = make_cross_signing_set("@bob:example.org");

        WHEN("only a self-signing key is uploaded")
        {
            auto const reply = upload_keys(rt, token, R"("self_signing_key":)" + set.self_signing_json);

            THEN("it is refused with 400 M_MISSING_PARAM and nothing is stored")
            {
                CHECK(reply.status == 400U);
                CHECK(reply.body.find("M_MISSING_PARAM") != std::string::npos);
                CHECK(held_cross_signing_keys(rt) == 0U);
            }
        }
    }
}

// Spec: POST /keys/device_signing/upload: `self_signing_key` and `user_signing_key` "Must be signed by the
// accompanying master signing key, or by the user's most recently uploaded master signing key if no master
// signing key is included in the request." CrossSigningKey `keys`: "exactly one property, whose name is in
// the form <algorithm>:<unpadded_base64_public_key>, and whose value is the unpadded base64 public key."
// `signatures`: "Other keys must be signed by the user's master signing key." Responses: 400
// `M_INVALID_SIGNATURE` "the self-signing or user-signing key had an incorrect signature". The signature is
// over the key's Signing JSON (appendices): canonical JSON without `signatures` and `unsigned`.
SCENARIO("a cross-signing upload's signatures are verified before anything is stored",
         "[conformance][client-server][cross-signing][upload-validation][signatures]")
{
    GIVEN("a user who has uploaded a full cross-signing set")
    {
        auto started = merovingian::homeserver::start_client_server(upload_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        auto const user = std::string{"@alice:example.org"};
        auto const set = make_cross_signing_set(user);
        REQUIRE(upload_keys(rt, token, set.members()).status == 200U);
        auto const& store = rt.homeserver.database.persistent_store;
        auto const stored_json = [&store](std::string const& type) {
            for (auto const& key : store.cross_signing_keys)
            {
                if (key.key_type == type)
                {
                    return key.json;
                }
            }
            return std::string{};
        };
        // A snapshot taken before each request. "Nothing is stored" is then checked as equality with the snapshot,
        // including the device-list changes a stored upload would record.
        auto const before_master = stored_json("master");
        auto const before_self = stored_json("self_signing");
        auto const before_changes = store.device_list_changes.size();
        auto const nothing_changed = [&] {
            return stored_json("master") == before_master && stored_json("self_signing") == before_self &&
                   store.cross_signing_keys.size() == 3U && store.device_list_changes.size() == before_changes;
        };
        // Builds a self-signing key for the key under test, signed by the given key as the given user, so each
        // scenario varies only the signer or the user the signature is filed under.
        auto const fresh_self_key = [&user](CrossSigningKeyPair const& signer, std::string const& signing_user,
                                            CrossSigningKeyPair const& key) {
            return sign_cross_signing_key_json(unsigned_cross_signing_key_json(user, "self_signing", key.public_key),
                                               signing_user, signer);
        };
        auto const key = generate_cross_signing_key_pair();

        // No master key in the request, so the signature is checked against the held master key.
        WHEN("a new self-signing key signed by the stored master key is uploaded with no master key")
        {
            auto const reply = upload_keys(rt, token, R"("self_signing_key":)" + fresh_self_key(set.master, user, key));

            THEN("it is accepted and replaces the held one")
            {
                INFO(reply.body);
                CHECK(reply.status == 200U);
                CHECK(stored_json("self_signing").find(key.public_key) != std::string::npos);
                CHECK(store.cross_signing_keys.size() == 3U);
            }
        }

        WHEN("a new master key is uploaded with a self-signing key signed by it")
        {
            auto const new_master = generate_cross_signing_key_pair();
            auto const reply = upload_keys(rt, token,
                                           R"("master_key":)" +
                                               unsigned_cross_signing_key_json(user, "master", new_master.public_key) +
                                               R"(,"self_signing_key":)" + fresh_self_key(new_master, user, key));

            THEN("it is accepted")
            {
                INFO(reply.body);
                CHECK(reply.status == 200U);
                CHECK(stored_json("master").find(new_master.public_key) != std::string::npos);
                CHECK(stored_json("self_signing").find(key.public_key) != std::string::npos);
            }
        }

        // The rotation is set up first with a master key alone, which needs no signature. The old key must no
        // longer verify.
        WHEN("the master key has been replaced and a self-signing key signed by the old master key is uploaded")
        {
            auto const new_master = generate_cross_signing_key_pair();
            REQUIRE(
                upload_keys(rt, token,
                            R"("master_key":)" + unsigned_cross_signing_key_json(user, "master", new_master.public_key))
                    .status == 200U);
            auto const master_after_rotation = stored_json("master");
            auto const reply = upload_keys(rt, token, R"("self_signing_key":)" + fresh_self_key(set.master, user, key));

            THEN("it is refused with 400 M_INVALID_SIGNATURE: only the most recently uploaded master key counts")
            {
                CHECK(reply.status == 400U);
                CHECK(reply.body.find("M_INVALID_SIGNATURE") != std::string::npos);
                CHECK(stored_json("master") == master_after_rotation);
                CHECK(stored_json("self_signing").find(key.public_key) == std::string::npos);
            }
        }

        WHEN("a self-signing key carries no signature")
        {
            auto const reply = upload_keys(rt, token,
                                           R"("self_signing_key":)" +
                                               unsigned_cross_signing_key_json(user, "self_signing", key.public_key));

            THEN("it is refused with 400 M_INVALID_SIGNATURE and nothing is stored")
            {
                CHECK(reply.status == 400U);
                CHECK(reply.body.find("M_INVALID_SIGNATURE") != std::string::npos);
                CHECK(nothing_changed());
            }
        }

        // Both requests carry a signature from a key the user never uploaded as master.
        WHEN("a self-signing key is signed by a key that is not the master key")
        {
            auto const stranger = generate_cross_signing_key_pair();
            // The signature names the master key's ID but was made by another key.
            auto forged = fresh_self_key(stranger, user, key);
            auto const stranger_id = "ed25519:" + stranger.public_key;
            forged.replace(forged.find(stranger_id), stranger_id.size(), "ed25519:" + set.master.public_key);
            auto const by_stranger = upload_keys(rt, token, R"("self_signing_key":)" + forged);
            // And one signed under the stranger's own ID, which is not the master key's.
            auto const under_other_id =
                upload_keys(rt, token, R"("self_signing_key":)" + fresh_self_key(stranger, user, key));

            THEN("both are refused with 400 M_INVALID_SIGNATURE and nothing is stored")
            {
                CHECK(by_stranger.status == 400U);
                CHECK(by_stranger.body.find("M_INVALID_SIGNATURE") != std::string::npos);
                CHECK(under_other_id.status == 400U);
                CHECK(under_other_id.body.find("M_INVALID_SIGNATURE") != std::string::npos);
                CHECK(nothing_changed());
            }
        }

        // The signature covers the key as signed, so any later change to its content must break verification.
        WHEN("a signed self-signing key is changed after it was signed")
        {
            auto tampered = fresh_self_key(set.master, user, key);
            auto const usage = std::string{R"("usage":["self_signing"])"};
            REQUIRE(tampered.find(usage) != std::string::npos);
            tampered.replace(tampered.find(usage), usage.size(), R"("usage":["self_signing","extra"])");
            auto const reply = upload_keys(rt, token, R"("self_signing_key":)" + tampered);

            THEN("it is refused with 400 M_INVALID_SIGNATURE and nothing is stored")
            {
                CHECK(reply.status == 400U);
                CHECK(reply.body.find("M_INVALID_SIGNATURE") != std::string::npos);
                CHECK(nothing_changed());
            }
        }

        // The signature itself was made by the master key. Only the user it is filed under differs.
        WHEN("the master key's signature is filed under another user's name")
        {
            auto const reply = upload_keys(
                rt, token, R"("self_signing_key":)" + fresh_self_key(set.master, "@mallory:example.org", key));

            THEN("it is refused with 400 M_INVALID_SIGNATURE and nothing is stored")
            {
                CHECK(reply.status == 400U);
                CHECK(reply.body.find("M_INVALID_SIGNATURE") != std::string::npos);
                CHECK(nothing_changed());
            }
        }

        WHEN("a key's value differs from the public key in its name")
        {
            auto const other = generate_cross_signing_key_pair();
            auto const reply =
                upload_keys(rt, token,
                            R"("master_key":{"user_id":"@alice:example.org","usage":["master"],"keys":{"ed25519:)" +
                                key.public_key + R"(":")" + other.public_key + R"("}})");

            THEN("it is refused with 400 M_BAD_JSON and nothing is stored")
            {
                CHECK(reply.status == 400U);
                CHECK(reply.body.find("M_BAD_JSON") != std::string::npos);
                CHECK(nothing_changed());
            }
        }

        // Ed25519 public keys are 32 bytes, so a shorter key or a different algorithm name cannot be a cross-
        // signing key.
        WHEN("a key is not 32 bytes long or names an algorithm other than ed25519")
        {
            auto const short_key = std::string{"AAAAAAAAAAAAAAAAAAAAAA"}; // 16 bytes, unpadded
            auto const too_short =
                upload_keys(rt, token,
                            R"("master_key":{"user_id":"@alice:example.org","usage":["master"],"keys":{"ed25519:)" +
                                short_key + R"(":")" + short_key + R"("}})");
            auto const other_algorithm =
                upload_keys(rt, token,
                            R"("master_key":{"user_id":"@alice:example.org","usage":["master"],"keys":{"curve25519:)" +
                                key.public_key + R"(":")" + key.public_key + R"("}})");

            THEN("both are refused with 400 M_BAD_JSON and nothing is stored")
            {
                CHECK(too_short.status == 400U);
                CHECK(too_short.body.find("M_BAD_JSON") != std::string::npos);
                CHECK(other_algorithm.status == 400U);
                CHECK(other_algorithm.body.find("M_BAD_JSON") != std::string::npos);
                CHECK(nothing_changed());
            }
        }

        WHEN("a good master key is uploaded beside a self-signing key with a bad signature")
        {
            auto const new_master = generate_cross_signing_key_pair();
            auto const stranger = generate_cross_signing_key_pair();
            auto const reply = upload_keys(rt, token,
                                           R"("master_key":)" +
                                               unsigned_cross_signing_key_json(user, "master", new_master.public_key) +
                                               R"(,"self_signing_key":)" + fresh_self_key(stranger, user, key));

            THEN("neither is stored and no device-list change or signing-key update is recorded")
            {
                CHECK(reply.status == 400U);
                CHECK(reply.body.find("M_INVALID_SIGNATURE") != std::string::npos);
                CHECK(nothing_changed());
            }
        }

        // Signing JSON leaves out `unsigned`, so adding it after signing must not invalidate the signature.
        WHEN("a signed self-signing key carries an unsigned member")
        {
            auto with_unsigned = fresh_self_key(set.master, user, key);
            REQUIRE(with_unsigned.back() == '}');
            with_unsigned.pop_back();
            with_unsigned += R"(,"unsigned":{"note":"not signed"}})";
            auto const reply = upload_keys(rt, token, R"("self_signing_key":)" + with_unsigned);

            THEN("the verdict is the same as without it: accepted")
            {
                INFO(reply.body);
                CHECK(reply.status == 200U);
                CHECK(stored_json("self_signing").find(key.public_key) != std::string::npos);
            }
        }
    }
}

// Spec: PUT /room_keys/keys uploads `rooms`, a map of room ID to {sessions: map of session ID to
// KeyBackupData}. A 200 answers with `count` and `etag` of the backup after the upload.
SCENARIO("a key backup batch upload stores every session or answers an error",
         "[conformance][client-server][key-backup][batch-upload]")
{
    GIVEN("a user with a key backup")
    {
        auto started = merovingian::homeserver::start_client_server(upload_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        create_backup(rt, token);
        auto const sessions_held = [&rt] {
            return rt.homeserver.database.persistent_store.key_backup_sessions.size();
        };

        WHEN("a batch of two sessions in two rooms is uploaded")
        {
            auto const reply = call(rt, "PUT", batch_path, token,
                                    R"({"rooms":{"!a:example.org":{"sessions":{"s1":)" + session("one") +
                                        R"(}},"!b:example.org":{"sessions":{"s2":)" + session("two") + R"(}}}})");

            THEN("both are stored and the answer counts them")
            {
                REQUIRE(reply.status == 200U);
                CHECK(sessions_held() == 2U);
                auto const body = parse_object(reply.body);
                auto const* count = int_member(body, "count");
                REQUIRE(count != nullptr);
                CHECK(*count == 2);
                CHECK(string_member(body, "etag") != nullptr);
            }
        }

        WHEN("the body has no rooms")
        {
            auto const reply = call(rt, "PUT", batch_path, token, "{}");

            THEN("it is refused with 400")
            {
                CHECK(reply.status == 400U);
                CHECK(sessions_held() == 0U);
            }
        }

        WHEN("a room is null, a room has no sessions or a session is null")
        {
            auto const null_room = call(rt, "PUT", batch_path, token, R"({"rooms":{"!a:example.org":null}})");
            auto const no_sessions = call(rt, "PUT", batch_path, token, R"({"rooms":{"!a:example.org":{}}})");
            auto const null_session =
                call(rt, "PUT", batch_path, token, R"({"rooms":{"!a:example.org":{"sessions":{"s1":null}}}})");

            THEN("each is refused with 400 and nothing is stored")
            {
                CHECK(null_room.status == 400U);
                CHECK(no_sessions.status == 400U);
                CHECK(null_session.status == 400U);
                CHECK(sessions_held() == 0U);
            }
        }

        WHEN("one session of an otherwise valid batch is malformed")
        {
            auto const reply =
                call(rt, "PUT", batch_path, token,
                     R"({"rooms":{"!a:example.org":{"sessions":{"good":)" + session("one") + R"(,"bad":"text"}}}})");

            THEN("the whole batch is refused and the good session is not stored")
            {
                CHECK(reply.status == 400U);
                CHECK(sessions_held() == 0U);
            }
        }

        WHEN("the store fails while the batch is written")
        {
            rt.homeserver.database.persistent_store.force_failure_statement_names.emplace("upsert_key_backup_session");
            auto const reply = call(rt, "PUT", batch_path, token,
                                    R"({"rooms":{"!a:example.org":{"sessions":{"s1":)" + session("one") + R"(,"s2":)" +
                                        session("two") + R"(}}}})");

            THEN("the client is told, with no etag, and none of the sessions is stored")
            {
                CHECK(reply.status == 500U);
                CHECK(reply.body.find("etag") == std::string::npos);
                CHECK(sessions_held() == 0U);
            }
        }
    }
}
