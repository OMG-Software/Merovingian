// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |  MATRIX END-TO-END ENCRYPTION OTK SIGNATURE VALIDATION (REGRESSION)     |
// |                                                                         |
// |  Spec: https://spec.matrix.org/v1.18/client-server-api/                 |
// |        #post_matrixclientv3keysupload                                   |
// |                                                                         |
// |  Every REQUIRE in this file encodes a Matrix v1.18 MUST for /keys/upload |
// |  signature validation. A failure here means the server accepted (and    |
// |  therefore returned via /keys/claim) a one-time key whose signature     |
// |  cannot be verified against the device's own published identity,        |
// |  causing matrix-rust-sdk to report `NoSignatureFound` and refuse to    |
// |  establish an Olm session. That was the live bug on pong.ping.me.uk     |
// |  where Element's james could not decrypt Cinny's jc2 messages.          |
// |                                                                         |
// |  If a test fails:                                                       |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass. |
// +-------------------------------------------------------------------------+

#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

namespace
{

// registration_enabled_config mirrors the helper in test_client_server.cpp so
// the test files are independent.
[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

[[nodiscard]] auto login_token(std::string const& body) -> std::string
{
    auto const key = std::string{"\"access_token\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

// Convenience: build the login body for a freshly registered user.
[[nodiscard]] auto login_body(std::string_view user_id, std::string_view password,
                              std::string_view device_id) -> std::string
{
    auto out = std::string{};
    out.append(R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":")");
    out.append(user_id);
    out.append(R"("},"password":")");
    out.append(password);
    out.append(R"(","device_id":")");
    out.append(device_id);
    out.append(R"("})");
    return out;
}

[[nodiscard]] auto register_body(std::string_view localpart, std::string_view password) -> std::string
{
    // Mirrors merovingian::tests::registration_json so the test files are
    // independent, but embedded locally to avoid having to update the shared
    // helper for this regression suite.
    return std::string{R"({"username":")"} + std::string{localpart} + R"(","password":")" +
           std::string{password} +
           R"(","auth":{"type":"m.login.registration_token","token":"test-registration-token"}})";
}

} // namespace

// --- Bug reproducer: OTK signed by wrong key MUST be rejected ----------------
//
// Spec: Matrix Client-Server API v1.18
// URL:  https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3keysupload
//
// A one-time key is a SignedKey: the `signatures` map must contain a signature
// from the device's own ed25519 identity key. If the server stores a key whose
// signature is from a different ed25519 key, the peer that claims the OTK via
// /keys/claim will fail to verify the signature and cannot establish an Olm
// session, and the room key the sender tries to share with the peer is
// silently dropped. That was the live bug on pong.ping.me.uk: matrix-rust-sdk
// reported `signing_key=ed25519:bsfTcD...` vs OTK signed by
// `ed25519:5c935785...` for the stale "MEROVINGIAN" device row.
SCENARIO("E2EE /keys/upload rejects one-time keys signed by a different ed25519 key",
         "[homeserver][client-server][e2ee][otk-signature][regression]")
{
    GIVEN("a logged-in inviter whose device_keys identity key is ed25519:INVITER_DEV")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/register", {},
                              register_body("inviter", "CorrectHorse7!")})
                    .response.status == 200U);

        auto const inviter_login = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/login", {},
                      login_body("@inviter:example.org", "CorrectHorse7!", "INVITER_DEV")});
        REQUIRE(inviter_login.response.status == 200U);
        auto const inviter_token = login_token(inviter_login.response.body);

        // Pin the device's identity by uploading its device_keys first.
        auto const device_keys_upload = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/keys/upload", inviter_token,
             R"({"device_keys":{"user_id":"@inviter:example.org","device_id":"INVITER_DEV","algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"keys":{"curve25519:INVITER_DEV":"AAAA_CURVE","ed25519:INVITER_DEV":"BBBB_ED"}}})"});
        REQUIRE(device_keys_upload.response.status == 200U);

        WHEN("the inviter uploads a one_time_key signed by a different ed25519 key")
        {
            auto const otk_upload = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/keys/upload", inviter_token,
                 R"({"one_time_keys":{"signed_curve25519:AAAA":{"key":"OTK_KEY_1","signatures":{"@inviter:example.org":{"ed25519:IMPOSTER_KEY":"OTK_SIG_1"}}}}})"});

            THEN("the upload is rejected with 400 M_INVALID_SIGNATURE and the OTK is not stored")
            {
                // Spec MUST: OTK is unverifiable for the peer → server must
                // reject, not store. Storing unverifiable OTKs is what
                // produced the MEROVINGIAN row on pong.ping.me.uk.
                REQUIRE(otk_upload.response.status == 400U);
                REQUIRE(otk_upload.response.body.find("M_INVALID_SIGNATURE") != std::string::npos);

                auto const& store = runtime.homeserver.database.persistent_store;
                auto const stored = std::ranges::find_if(
                    store.one_time_keys,
                    [](merovingian::database::PersistentOneTimeKey const& k) {
                        return k.device_id == "INVITER_DEV";
                    });
                REQUIRE(stored == store.one_time_keys.end());
            }
        }
    }
}

// --- Regression guard: OTK signed by own key MUST still be accepted ----------
//
// Spec: Matrix Client-Server API v1.18
// URL:  https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3keysupload
//
// The OTK signature validator must not regress the happy path: a one-time
// key signed by the device's own ed25519 identity key MUST be accepted.
SCENARIO("E2EE /keys/upload accepts one-time keys signed by the device's own ed25519 key",
         "[homeserver][client-server][e2ee][otk-signature][regression]")
{
    GIVEN("a logged-in inviter whose device_keys identity key is ed25519:INVITER_DEV")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/register", {},
                              register_body("inviter", "CorrectHorse7!")})
                    .response.status == 200U);

        auto const inviter_login = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/login", {},
                      login_body("@inviter:example.org", "CorrectHorse7!", "INVITER_DEV")});
        REQUIRE(inviter_login.response.status == 200U);
        auto const inviter_token = login_token(inviter_login.response.body);

        auto const device_keys_upload = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/keys/upload", inviter_token,
             R"({"device_keys":{"user_id":"@inviter:example.org","device_id":"INVITER_DEV","algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"keys":{"curve25519:INVITER_DEV":"AAAA_CURVE","ed25519:INVITER_DEV":"BBBB_ED"}}})"});
        REQUIRE(device_keys_upload.response.status == 200U);

        WHEN("the inviter uploads a one_time_key signed by ed25519:INVITER_DEV")
        {
            auto const otk_upload = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/keys/upload", inviter_token,
                 R"({"one_time_keys":{"signed_curve25519:AAAA":{"key":"OTK_KEY_1","signatures":{"@inviter:example.org":{"ed25519:INVITER_DEV":"OTK_SIG_1"}}}}})"});

            THEN("the upload succeeds and the OTK is stored")
            {
                // Regression guard: the signature validator must accept
                // OTKs signed by the device's own identity key.
                REQUIRE(otk_upload.response.status == 200U);

                auto const& store = runtime.homeserver.database.persistent_store;
                auto const stored = std::ranges::find_if(
                    store.one_time_keys,
                    [](merovingian::database::PersistentOneTimeKey const& k) {
                        return k.device_id == "INVITER_DEV";
                    });
                REQUIRE(stored != store.one_time_keys.end());
            }
        }
    }
}

// --- Fallback key parity -----------------------------------------------------
//
// Spec: Matrix Client-Server API v1.18
// URL:  https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3keysupload
//
// Fallback keys (signed_curve25519 with `fallback: true`) follow the same
// rules as one-time keys: they MUST be SignedKey objects whose signature is
// made by the device's own ed25519 identity key. The server MUST apply the
// same signature check to fallback keys.
SCENARIO("E2EE /keys/upload rejects fallback keys signed by a different ed25519 key",
         "[homeserver][client-server][e2ee][fallback-key-signature][regression]")
{
    GIVEN("a logged-in inviter whose device_keys identity key is ed25519:INVITER_DEV")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/register", {},
                              register_body("inviter", "CorrectHorse7!")})
                    .response.status == 200U);

        auto const inviter_login = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/login", {},
                      login_body("@inviter:example.org", "CorrectHorse7!", "INVITER_DEV")});
        REQUIRE(inviter_login.response.status == 200U);
        auto const inviter_token = login_token(inviter_login.response.body);

        auto const device_keys_upload = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/keys/upload", inviter_token,
             R"({"device_keys":{"user_id":"@inviter:example.org","device_id":"INVITER_DEV","algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"keys":{"curve25519:INVITER_DEV":"AAAA_CURVE","ed25519:INVITER_DEV":"BBBB_ED"}}})"});
        REQUIRE(device_keys_upload.response.status == 200U);

        WHEN("the inviter uploads a fallback key signed by a different ed25519 key")
        {
            auto const fallback_upload = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/keys/upload", inviter_token,
                 R"({"fallback_keys":{"signed_curve25519:BBBB":{"key":"FB_KEY_1","fallback":true,"signatures":{"@inviter:example.org":{"ed25519:IMPOSTER_KEY":"FB_SIG_1"}}}}})"});

            THEN("the upload is rejected with 400 M_INVALID_SIGNATURE and the fallback is not stored")
            {
                // Spec MUST: the same signature check applies to fallback
                // keys. Storing an unverifiable fallback key is just as
                // harmful as storing an unverifiable one-time key.
                REQUIRE(fallback_upload.response.status == 400U);
                REQUIRE(fallback_upload.response.body.find("M_INVALID_SIGNATURE") != std::string::npos);

                auto const& store = runtime.homeserver.database.persistent_store;
                auto const stored = std::ranges::find_if(
                    store.fallback_keys,
                    [](merovingian::database::PersistentFallbackKey const& k) {
                        return k.device_id == "INVITER_DEV";
                    });
                REQUIRE(stored == store.fallback_keys.end());
            }
        }
    }
}

// --- No prior device_keys MUST NOT block first /keys/upload with OTK ---------
//
// Spec: Matrix Client-Server API v1.18
// URL:  https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3keysupload
//
// A device MAY upload OTKs as part of its first /keys/upload before uploading
// any device_keys. When no device_keys exist for the (user, device), the
// server has no reference signing key to verify the OTK against, and the
// only sane behaviour is to accept the OTK (the device's first call must
// succeed). This scenario is the regression guard for the no-device-yet
// first-boot path so the validator does not over-reject.
SCENARIO("E2EE /keys/upload accepts a first-time OTK upload before device_keys is known",
         "[homeserver][client-server][e2ee][otk-signature][regression]")
{
    GIVEN("a logged-in inviter that has never uploaded device_keys")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/register", {},
                              register_body("inviter", "CorrectHorse7!")})
                    .response.status == 200U);

        auto const inviter_login = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/login", {},
                      login_body("@inviter:example.org", "CorrectHorse7!", "INVITER_DEV")});
        REQUIRE(inviter_login.response.status == 200U);
        auto const inviter_token = login_token(inviter_login.response.body);

        WHEN("the inviter uploads a one_time_key with no device_keys in the body or store")
        {
            auto const otk_upload = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/keys/upload", inviter_token,
                 R"({"one_time_keys":{"signed_curve25519:AAAA":{"key":"OTK_KEY_1","signatures":{"@inviter:example.org":{"ed25519:INVITER_DEV":"OTK_SIG_1"}}}}})"});

            THEN("the upload succeeds because there is no device identity to verify against")
            {
                // The validator must be lenient on a device's first upload:
                // there is no device_keys row to compare against, so the
                // OTK is accepted and stored as before.
                REQUIRE(otk_upload.response.status == 200U);

                auto const& store = runtime.homeserver.database.persistent_store;
                auto const stored = std::ranges::find_if(
                    store.one_time_keys,
                    [](merovingian::database::PersistentOneTimeKey const& k) {
                        return k.device_id == "INVITER_DEV";
                    });
                REQUIRE(stored != store.one_time_keys.end());
            }
        }
    }
}
