// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/config.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>

TEST_CASE("Config provides secure server and listener defaults", "[config]")
{
    // Given
    auto const config = merovingian::config::Config{};

    // When
    auto const& server = config.server();
    auto const& listeners = config.listeners();
    auto const& database = config.database();

    // Then
    REQUIRE(server.server_name == "example.org");
    REQUIRE(server.public_baseurl == "https://matrix.example.org");
    REQUIRE(server.trusted_proxies.empty());

    REQUIRE(listeners.client.bind == "127.0.0.1:8008");
    REQUIRE_FALSE(listeners.client.tls);
    REQUIRE(listeners.federation.bind == "127.0.0.1:8448");
    REQUIRE_FALSE(listeners.federation.tls);

    REQUIRE(database.uri_file == "/etc/merovingian/db-uri");
    REQUIRE(database.pool_size == 16U);
}

TEST_CASE("Config disables open registration by default", "[config][security]")
{
    // Given
    auto const config = merovingian::config::Config{};

    // When
    auto const& registration = config.security().registration;

    // Then
    REQUIRE_FALSE(registration.enabled);
    REQUIRE(registration.require_token);
}

TEST_CASE("Config defaults private rooms and direct messages to encrypted", "[config][security]")
{
    // Given
    auto const config = merovingian::config::Config{};

    // When
    auto const& encryption = config.security().encryption;

    // Then
    REQUIRE(encryption.default_for_new_rooms);
    REQUIRE(encryption.require_for_direct_messages);
    REQUIRE(encryption.require_for_private_rooms);
    REQUIRE(encryption.allow_unencrypted_public_rooms);
    REQUIRE(encryption.block_unencrypted_federated_private_rooms);
}

TEST_CASE("Config blocks private federation and loopback targets by default", "[config][security]")
{
    // Given
    auto const config = merovingian::config::Config{};

    // When
    auto const& federation = config.security().federation;

    // Then
    REQUIRE(federation.enabled);
    REQUIRE(federation.default_policy == "allow");
    REQUIRE(federation.require_valid_tls);
    REQUIRE(federation.verify_json_signatures);
    REQUIRE(federation.deny_ip_ranges.size() == 6U);
    REQUIRE(federation.deny_ip_ranges[0] == "127.0.0.0/8");
    REQUIRE(federation.deny_ip_ranges[5] == "fc00::/7");
}

TEST_CASE("Config enables media and logging protections by default", "[config][security]")
{
    // Given
    auto const config = merovingian::config::Config{};

    // When
    auto const& media = config.security().media;
    auto const& logging = config.security().logging;

    // Then
    REQUIRE(media.max_upload_size == "50MiB");
    REQUIRE(media.quarantine_unknown_mime);
    REQUIRE(media.enable_av_scanner);
    REQUIRE(media.block_private_ip_fetches);
    REQUIRE(media.decode_in_sandbox);

    REQUIRE(logging.redact_tokens);
    REQUIRE(logging.redact_event_content);
    REQUIRE(logging.structured);
}
