// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |  MATRIX END-TO-END ENCRYPTION OTK SIGNATURE VALIDATION (REGRESSION)     |
// |                                                                         |
// |  Spec: ../../docs/matrix-v1.18-spec/client-server-api.md                 |
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

#include "../federation_signing_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <iostream>
#include <string>

#include <sodium.h>

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
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
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

// Builds the JSON for a SignedKey (OTK or fallback key) that carries a real
// Ed25519 signature from the device's own signing key. The payload is the
// canonical JSON of the key object WITHOUT the signatures field; the
// signature is computed with crypto_sign_detached and base64-encoded using
// the same unpadded variant that the server expects.
//
// key_object_prefix: optional JSON fields to include before "key" (e.g. "\"fallback\":true,")
[[nodiscard]] auto make_valid_signed_otk(std::string_view user_id, std::string_view device_id,
                                         std::string_view key_value, std::string_view key_object_prefix,
                                         std::string const& secret_key_bytes) -> std::string
{
    // Payload: canonical JSON of the key object minus the signatures field.
    // Keys must be sorted (canonical JSON); include any prefix fields first.
    auto payload = std::string{};
    if (key_object_prefix.empty())
    {
        payload = std::string{R"({"key":")"} + std::string{key_value} + R"("})";
    }
    else
    {
        payload = "{" + std::string{key_object_prefix} + R"("key":")" + std::string{key_value} + "\"}";
    }

    auto signature = std::array<unsigned char, crypto_sign_BYTES>{};
    crypto_sign_detached(signature.data(), nullptr,
                         reinterpret_cast<unsigned char const*>(payload.data()), payload.size(),
                         reinterpret_cast<unsigned char const*>(secret_key_bytes.data()));

    auto const sig_b64 = merovingian::events::matrix_base64_from_bytes(
        {reinterpret_cast<char const*>(signature.data()), crypto_sign_BYTES});

    // Build the full signed key JSON (with signatures field appended).
    auto result = std::string{};
    if (key_object_prefix.empty())
    {
        result = std::string{R"({"key":")"} + std::string{key_value} +
                 R"(","signatures":{")" + std::string{user_id} +
                 R"(":{"ed25519:)" + std::string{device_id} + R"(":")" + sig_b64 + R"("}}})" ;
    }
    else
    {
        result = "{" + std::string{key_object_prefix} + R"("key":")" + std::string{key_value} +
                 R"(","signatures":{")" + std::string{user_id} +
                 R"(":{"ed25519:)" + std::string{device_id} + R"(":")" + sig_b64 + R"("}}})" ;
    }
    return result;
}

} // namespace

// --- Bug reproducer: OTK signed by wrong key MUST be rejected ----------------
//
// Spec: Matrix Client-Server API v1.18
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3keysupload
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
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3keysupload
//
// The OTK signature validator must not regress the happy path: a one-time
// key signed by the device's own ed25519 identity key MUST be accepted.
// This test uses a real Ed25519 keypair so that cryptographic verification
// (not just key-ID presence) is exercised on the happy path.
SCENARIO("E2EE /keys/upload accepts one-time keys signed by the device's own ed25519 key",
         "[homeserver][client-server][e2ee][otk-signature][regression]")
{
    GIVEN("a logged-in inviter whose device_keys identity key is a real Ed25519 key")
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

        // Derive a real deterministic Ed25519 keypair from a seed.
        auto const keypair     = merovingian::federation::test::keypair_from_seed("inviter-dev-seed");
        auto const pubkey_b64  = merovingian::events::matrix_base64_from_bytes(keypair.public_key);

        auto const device_keys_upload = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/keys/upload", inviter_token,
             std::string{R"({"device_keys":{"user_id":"@inviter:example.org","device_id":"INVITER_DEV","algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"keys":{"curve25519:INVITER_DEV":"AAAA_CURVE","ed25519:INVITER_DEV":")"} +
             pubkey_b64 + R"("}}})"});
        REQUIRE(device_keys_upload.response.status == 200U);

        WHEN("the inviter uploads a one_time_key with a valid Ed25519 signature")
        {
            auto const otk_json = make_valid_signed_otk("@inviter:example.org", "INVITER_DEV",
                                                        "OTK_KEY_1", {}, keypair.secret_key);
            auto const otk_upload = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/keys/upload", inviter_token,
                 R"({"one_time_keys":{"signed_curve25519:AAAA":)" + otk_json + R"(}})"});

            THEN("the upload succeeds and the OTK is stored")
            {
                // Regression guard: the signature validator must accept
                // OTKs carrying a cryptographically valid signature from
                // the device's own identity key.
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

// --- Finding 4: garbage signature bytes under correct key ID MUST be rejected -
//
// Spec: Matrix Client-Server API v1.18
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3keysupload
//
// The server MUST perform real Ed25519 signature verification, not just check
// that the correct key ID is present. An OTK with a syntactically valid
// signatures map entry (correct user_id AND correct key ID) but with garbage
// signature bytes MUST be rejected. A peer that receives such a key via
// /keys/claim will fail to verify the signature and cannot establish an Olm
// session.
SCENARIO("E2EE /keys/upload rejects one-time keys with garbage signature bytes under the correct key ID",
         "[homeserver][client-server][e2ee][otk-signature][regression]")
{
    GIVEN("a logged-in device whose published ed25519 identity key is a real Ed25519 public key")
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

        auto const keypair    = merovingian::federation::test::keypair_from_seed("inviter-dev-seed");
        auto const pubkey_b64 = merovingian::events::matrix_base64_from_bytes(keypair.public_key);

        auto const device_keys_upload = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/keys/upload", inviter_token,
             std::string{R"({"device_keys":{"user_id":"@inviter:example.org","device_id":"INVITER_DEV","algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"keys":{"curve25519:INVITER_DEV":"AAAA_CURVE","ed25519:INVITER_DEV":")"} +
             pubkey_b64 + R"("}}})"});
        REQUIRE(device_keys_upload.response.status == 200U);

        WHEN("an OTK is uploaded with garbage signature bytes under the correct key ID")
        {
            // The signatures map uses the correct user_id AND the correct
            // key ID (ed25519:INVITER_DEV) — only the signature bytes are garbage.
            // A shallow check (key-ID presence only) would accept this; real
            // Ed25519 verification must reject it.
            auto const otk_upload = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/keys/upload", inviter_token,
                 R"({"one_time_keys":{"signed_curve25519:AAAA":{"key":"OTK_KEY_1","signatures":{"@inviter:example.org":{"ed25519:INVITER_DEV":"GARBAGE_BYTES_NOT_A_VALID_SIGNATURE"}}}}})"});

            THEN("the upload is rejected with 400 M_INVALID_SIGNATURE")
            {
                // Spec MUST: real cryptographic verification is required.
                // Presence of the correct key ID is insufficient.
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

// --- Fallback key parity -----------------------------------------------------
//
// Spec: Matrix Client-Server API v1.18
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3keysupload
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
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3keysupload
//
// Bug 11 fix: signed_curve25519 OTKs must be verifiable against the device's
// own ed25519 identity key. When no device_keys have been uploaded, the server
// has no reference key and MUST reject the upload (M_INVALID_SIGNATURE).
// Plain curve25519 (unsigned) OTKs do not require a signature and are accepted.
SCENARIO("E2EE /keys/upload rejects signed_curve25519 OTKs when no device identity is known",
         "[homeserver][client-server][e2ee][otk-signature][regression]")
{
    GIVEN("a logged-in inviter that has never uploaded device_keys")
    {
        std::cerr << "[netbsd-diag] otk-no-identity: start_client_server\n" << std::flush;
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        std::cerr << "[netbsd-diag] otk-no-identity: runtime started\n" << std::flush;
        auto& runtime = started.runtime;

        std::cerr << "[netbsd-diag] otk-no-identity: register\n" << std::flush;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/register", {},
                              register_body("inviter", "CorrectHorse7!")})
                    .response.status == 200U);
        std::cerr << "[netbsd-diag] otk-no-identity: registered\n" << std::flush;

        std::cerr << "[netbsd-diag] otk-no-identity: login\n" << std::flush;
        auto const inviter_login = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/login", {},
                      login_body("@inviter:example.org", "CorrectHorse7!", "INVITER_DEV")});
        REQUIRE(inviter_login.response.status == 200U);
        std::cerr << "[netbsd-diag] otk-no-identity: logged in\n" << std::flush;
        auto const inviter_token = login_token(inviter_login.response.body);

        WHEN("the inviter uploads a signed_curve25519 one_time_key with no device_keys in the body or store")
        {
            std::cerr << "[netbsd-diag] otk-no-identity: upload\n" << std::flush;
            auto const otk_upload = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/keys/upload", inviter_token,
                 R"({"one_time_keys":{"signed_curve25519:AAAA":{"key":"OTK_KEY_1","signatures":{"@inviter:example.org":{"ed25519:INVITER_DEV":"OTK_SIG_1"}}}}})"});
            std::cerr << "[netbsd-diag] otk-no-identity: upload returned status=" << otk_upload.response.status
                      << "\n"
                      << std::flush;

            THEN("the upload is rejected because the signature cannot be verified without a device identity")
            {
                // Spec MUST: signed_curve25519 keys must be signed by the device's
                // own ed25519 key. No device identity → no reference key → reject.
                REQUIRE(otk_upload.response.status == 400U);

                // Rejected keys must not be persisted.
                auto const& store = runtime.homeserver.database.persistent_store;
                auto const stored = std::ranges::find_if(
                    store.one_time_keys,
                    [](merovingian::database::PersistentOneTimeKey const& k) {
                        return k.device_id == "INVITER_DEV";
                    });
                REQUIRE(stored == store.one_time_keys.end());
            }
            std::cerr << "[netbsd-diag] otk-no-identity: scenario end\n" << std::flush;
        }
    }
}
