// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX FEDERATION SPACE / MEDIA CONFORMANCE TESTS             |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.19                                     |
// |  URL:  ../../docs/matrix-v1.19-spec/server-server-api.md                |
// |                                                                         |
// |  These scenarios cover the remaining non-transaction federation         |
// |  endpoints that did not previously have dedicated conformance tests:      |
// |    - GET /_matrix/federation/v1/hierarchy/{roomId}                        |
// |    - GET /_matrix/federation/v1/media/download/{mediaId}                  |
// +-------------------------------------------------------------------------+

#include "federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/homeserver/media_service.hpp"
#include "merovingian/media/repository.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace
{

[[nodiscard]] auto runtime_config() -> merovingian::federation::RuntimeFederationConfig
{
    auto config = merovingian::federation::RuntimeFederationConfig{};
    config.enabled = true;
    config.default_policy = "allow";
    config.require_valid_tls = true;
    config.verify_json_signatures = true;
    config.max_transaction_bytes = 65536U;
    config.remote_timeout_seconds = 30U;
    config.server_name = "local.example.org";
    return config;
}

[[nodiscard]] auto remote_for(std::string const& origin, std::string const& key_id, std::string const& key_seed)
    -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = origin;
    remote.signing_key = {origin, key_id, 2000U, merovingian::federation::test::keypair_from_seed(key_seed).public_key};
    remote.discovery.server_name = origin;
    remote.discovery.well_known_host = origin;
    remote.discovery.resolved_host = origin;
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    return remote;
}

[[nodiscard]] auto signed_get_request(std::string const& origin, std::string const& key_id, std::string const& key_seed,
                                      std::string const& target) -> merovingian::federation::SignedFederationRequest
{
    auto const kp = merovingian::federation::test::keypair_from_seed(key_seed);
    auto request = merovingian::federation::SignedFederationRequest{};
    request.method = "GET";
    request.target = target;
    request.origin = origin;
    request.destination = "local.example.org";
    request.key_id = key_id;
    request.now_ts = 1000U;
    request.canonical_json_verified = true;
    request.body = "";
    request.signature = merovingian::federation::make_federation_signature(
        origin, request.destination, request.method, target, request.body,
        std::span<std::uint8_t const>{reinterpret_cast<std::uint8_t const*>(kp.secret_key.data()),
                                      kp.secret_key.size()});
    return request;
}

auto const origin = std::string{"remote.example.org"};
auto const key_id = std::string{"ed25519:auto"};
auto const key_seed = std::string{"space-media-conformance-seed"};

} // namespace

// --- space hierarchy ---------------------------------------------------------
// Spec: Matrix Server-Server API v1.19
// Endpoint: GET /_matrix/federation/v1/hierarchy/{roomId}
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1hierarchyroomid
//
// The resident server MUST return 200 with the space hierarchy for a known room.
// An unknown room MUST return 404 M_NOT_FOUND. A missing provider MUST return 501.
// An invalid suggested_only query parameter MUST return 400 M_INVALID_PARAM.
SCENARIO("GET /hierarchy/{roomId} returns the space hierarchy when provider is wired",
         "[federation][conformance][space_hierarchy]")
{
    GIVEN("a runtime with space_hierarchy_provider installed")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        runtime.space_hierarchy_provider = [](std::string_view queried_room_id, bool /*suggested_only*/,
                                              std::string_view /*origin*/) -> std::string {
            if (queried_room_id == "!conformance:local.example.org")
            {
                return std::string{"{\"rooms\":[],\"children\":[]}"};
            }
            return {};
        };

        WHEN("a signed GET /hierarchy/{roomId} is dispatched for a known room")
        {
            auto const target = std::string{"/_matrix/federation/v1/hierarchy/!conformance:local.example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 200 with parseable JSON")
            {
                // Spec MUST: 200 for a known room.
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
            }
        }

        WHEN("a signed GET /hierarchy/{roomId} is dispatched for an unknown room")
        {
            auto const target = std::string{"/_matrix/federation/v1/hierarchy/!unknown:local.example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 when the room is not known to this server.
                REQUIRE(response.status == 404U);
                REQUIRE(response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }

        WHEN("a signed GET /hierarchy/{roomId} supplies an invalid suggested_only value")
        {
            auto const target =
                std::string{"/_matrix/federation/v1/hierarchy/!conformance:local.example.org?suggested_only=yes"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 400 M_INVALID_PARAM")
            {
                // Spec: suggested_only must be "true" or "false".
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_INVALID_PARAM") != std::string::npos);
            }
        }
    }

    GIVEN("a runtime with no space_hierarchy_provider installed")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        WHEN("a signed GET /hierarchy/{roomId} is dispatched")
        {
            auto const target = std::string{"/_matrix/federation/v1/hierarchy/!conformance:local.example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 501 Not Implemented")
            {
                // Architectural invariant: no provider installed -> 501.
                REQUIRE(response.status == 501U);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint: GET /_matrix/federation/v1/hierarchy/{roomId}
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1hierarchyroomid
//
// The response holds "all the space-room's children the requesting server could feasibly
// peek/join", and `children` excludes "Rooms which the requesting server cannot peek/join". What
// the requesting server may join differs per server, so the provider is told the X-Matrix
// authenticated origin, never a value taken from the request.
SCENARIO("GET /hierarchy/{roomId} judges the room for the authenticated requesting server",
         "[federation][conformance][space_hierarchy]")
{
    GIVEN("a provider that records the origin it is asked about")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));
        auto seen_origin = std::string{};
        runtime.space_hierarchy_provider = [&seen_origin](std::string_view, bool, std::string_view asking) {
            seen_origin = std::string{asking};
            return std::string{"{\"room\":{},\"children\":[],\"inaccessible_children\":[]}"};
        };

        WHEN("a signed request that also carries a forged origin in its query string is dispatched")
        {
            auto const target = std::string{
                "/_matrix/federation/v1/hierarchy/!conformance:local.example.org?origin=forged.example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the provider is asked about the signing server")
            {
                // Spec: the response is for "the requesting server", identified by request authentication.
                REQUIRE(response.status == 200U);
                REQUIRE(seen_origin == origin);
            }
        }
    }
}

// --- media download ----------------------------------------------------------
// Spec: Matrix Server-Server API v1.19
// Endpoint: GET /_matrix/federation/v1/media/download/{mediaId}
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1mediadownloadmediaid
//
// The resident server MUST return 200 with a multipart/mixed response when the
// media is available. Missing media MUST return 404 M_NOT_FOUND. Quarantined
// media MUST return 451 M_NOT_FOUND. A missing provider MUST return 501.
SCENARIO("GET /media/download/{mediaId} serves local media as multipart/mixed",
         "[federation][conformance][media_download]")
{
    GIVEN("a runtime with media_download_provider installed")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        auto captured_media_id = std::make_shared<std::string>();
        runtime.media_download_provider =
            [captured_media_id](std::string_view queried_media_id) -> merovingian::media::LocalMediaDownloadResult {
            *captured_media_id = std::string{queried_media_id};
            if (queried_media_id == "abc123" || queried_media_id == "abc:123")
            {
                return {true, 200U, "image/png", "PNGDATA", {}};
            }
            if (queried_media_id == "named")
            {
                return {true, 200U, "image/png", "PNGDATA", {}, "photo.png"};
            }
            if (queried_media_id == "named-unicode")
            {
                return {true, 200U, "image/png", "PNGDATA", {}, "\xF0\x9F\x90\x94"};
            }
            if (queried_media_id == "missing")
            {
                return {false, 404U, {}, {}, "media not found"};
            }
            if (queried_media_id == "quarantined")
            {
                return {false, 451U, {}, {}, "media quarantined"};
            }
            return {false, 500U, {}, {}, "unknown media"};
        };

        WHEN("a signed GET /media/download/{mediaId} requests an available file")
        {
            auto const target = std::string{"/_matrix/federation/v1/media/download/abc123"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 200 multipart/mixed with the media bytes in the second part")
            {
                // Spec MUST: 200 for available media.
                REQUIRE(response.status == 200U);
                // Spec MUST: outer Content-Type is multipart/mixed with a boundary.
                REQUIRE(response.content_type.find("multipart/mixed; boundary=") != std::string::npos);

                auto const parsed =
                    merovingian::homeserver::parse_federation_media_multipart(response.content_type, response.body);
                REQUIRE(parsed.ok);
                REQUIRE_FALSE(parsed.is_redirect);
                REQUIRE(parsed.bytes == "PNGDATA");
            }
        }

        WHEN("a signed GET /media/download/{mediaId} requests a file that was uploaded with a filename")
        {
            auto const named = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, "/_matrix/federation/v1/media/download/named"));
            auto const unicode = merovingian::federation::handle_inbound_federation_request(
                runtime,
                signed_get_request(origin, key_id, key_seed, "/_matrix/federation/v1/media/download/named-unicode"));
            auto const unnamed = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, "/_matrix/federation/v1/media/download/abc123"));

            THEN("the media part's Content-Disposition carries the filename, encoded per RFC 6266")
            {
                // Spec (Client-Server API, GET /_matrix/client/v1/media/download): "If the upload was made with a
                // filename, this header MUST contain the same filename"; the federation endpoint's media part
                // carries "Content-Disposition headers as appropriate" so the requesting server can serve it.
                REQUIRE(named.status == 200U);
                REQUIRE(named.body.find("Content-Disposition: inline; filename=\"photo.png\"\r\n") !=
                        std::string::npos);
                REQUIRE(unicode.status == 200U);
                REQUIRE(unicode.body.find("Content-Disposition: inline; filename*=utf-8''%F0%9F%90%94\r\n") !=
                        std::string::npos);
                auto const parsed_unicode =
                    merovingian::homeserver::parse_federation_media_multipart(unicode.content_type, unicode.body);
                REQUIRE(parsed_unicode.ok);
                REQUIRE(parsed_unicode.filename == "\xF0\x9F\x90\x94");
            }

            THEN("a file uploaded without a filename carries none")
            {
                // Spec: "Otherwise, filename is excluded from the header."
                REQUIRE(unnamed.status == 200U);
                REQUIRE(unnamed.body.find("filename") == std::string::npos);
            }
        }

        WHEN("a signed GET /media/download/{mediaId} requests a missing file")
        {
            auto const target = std::string{"/_matrix/federation/v1/media/download/missing"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 when the media is not known to this server.
                REQUIRE(response.status == 404U);
                REQUIRE(response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }

        WHEN("a signed GET /media/download/{mediaId} requests a quarantined file")
        {
            auto const target = std::string{"/_matrix/federation/v1/media/download/quarantined"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 451 M_NOT_FOUND")
            {
                // Spec: quarantined media returns 451 (unavailable for legal reasons).
                REQUIRE(response.status == 451U);
                REQUIRE(response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }

        WHEN("a signed GET /media/download/{mediaId} carries a percent-encoded media id")
        {
            auto const target = std::string{"/_matrix/federation/v1/media/download/abc%3A123"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the provider receives the decoded media id")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*captured_media_id == "abc:123");
            }
        }
    }

    GIVEN("a runtime with no media_download_provider installed")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, key_seed));

        WHEN("a signed GET /media/download/{mediaId} is dispatched")
        {
            auto const target = std::string{"/_matrix/federation/v1/media/download/abc123"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, key_seed, target));

            THEN("the response is 501 Not Implemented")
            {
                // Architectural invariant: no provider installed -> 501.
                REQUIRE(response.status == 501U);
            }
        }
    }
}
