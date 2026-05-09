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

TEST_CASE("Default media upload limit parses to bytes", "[config][validation]")
{
    // Given
    auto const default_limit = std::string{"50MiB"};

    // When
    auto const parsed = merovingian::config::parse_size_limit(default_limit);

    // Then
    REQUIRE(parsed.valid);
    REQUIRE(parsed.bytes == 52428800U);
}

TEST_CASE("Media upload size parser rejects invalid or unbounded-looking values", "[config][validation]")
{
    // Given
    auto const empty = std::string{};
    auto const zero = std::string{"0MiB"};
    auto const unsupported_suffix = std::string{"50MB"};
    auto const negative = std::string{"-1MiB"};
    auto const malformed = std::string{"50 MiB"};

    // When / Then
    REQUIRE_FALSE(merovingian::config::parse_size_limit(empty).valid);
    REQUIRE_FALSE(merovingian::config::parse_size_limit(zero).valid);
    REQUIRE_FALSE(merovingian::config::parse_size_limit(unsupported_suffix).valid);
    REQUIRE_FALSE(merovingian::config::parse_size_limit(negative).valid);
    REQUIRE_FALSE(merovingian::config::parse_size_limit(malformed).valid);
}

TEST_CASE("Config validation helpers accept secure address-shaped defaults", "[config][validation]")
{
    // Given
    auto const public_baseurl = std::string{"https://matrix.example.org"};
    auto const listener_bind = std::string{"127.0.0.1:8008"};

    // When / Then
    REQUIRE(merovingian::config::is_valid_public_baseurl(public_baseurl));
    REQUIRE(merovingian::config::is_valid_listener_bind(listener_bind));
    REQUIRE(merovingian::config::is_valid_federation_policy("allow"));
    REQUIRE(merovingian::config::is_valid_federation_policy("deny"));
}

TEST_CASE("Config validation helpers reject unsafe address-shaped values", "[config][validation]")
{
    // Given
    auto const insecure_public_baseurl = std::string{"http://matrix.example.org"};
    auto const empty_host_bind = std::string{":8008"};
    auto const missing_port_bind = std::string{"127.0.0.1"};
    auto const out_of_range_port_bind = std::string{"127.0.0.1:70000"};

    // When / Then
    REQUIRE_FALSE(merovingian::config::is_valid_public_baseurl(insecure_public_baseurl));
    REQUIRE_FALSE(merovingian::config::is_valid_listener_bind(empty_host_bind));
    REQUIRE_FALSE(merovingian::config::is_valid_listener_bind(missing_port_bind));
    REQUIRE_FALSE(merovingian::config::is_valid_listener_bind(out_of_range_port_bind));
    REQUIRE_FALSE(merovingian::config::is_valid_federation_policy("permissive"));
}

TEST_CASE("Config validation accepts cleartext listeners only on loopback", "[config][validation]")
{
    // Given
    auto const loopback_listener = merovingian::config::ListenerConfig{"127.0.0.1:8008", false};
    auto const tls_public_listener = merovingian::config::ListenerConfig{"0.0.0.0:8448", true};

    // When / Then
    REQUIRE(merovingian::config::is_safe_cleartext_listener(loopback_listener));
    REQUIRE(merovingian::config::is_safe_cleartext_listener(tls_public_listener));
}

TEST_CASE("Config validation rejects cleartext listeners on public interfaces", "[config][validation]")
{
    // Given
    auto const public_cleartext_listener = merovingian::config::ListenerConfig{"0.0.0.0:8008", false};

    // When / Then
    REQUIRE_FALSE(merovingian::config::is_safe_cleartext_listener(public_cleartext_listener));
}

TEST_CASE("Default config validates without findings", "[config][validation]")
{
    // Given
    auto const config = merovingian::config::Config{};

    // When
    auto const findings = merovingian::config::validate(config);

    // Then
    REQUIRE(findings.empty());
    REQUIRE(merovingian::config::is_valid(config));
}

TEST_CASE("Config validation rejects missing critical fields", "[config][validation]")
{
    // Given
    auto server = merovingian::config::ServerConfig{};
    auto listeners = merovingian::config::ListenersConfig{};
    auto database = merovingian::config::DatabaseConfig{};
    auto security = merovingian::config::SecurityConfig{};
    server.server_name.clear();
    listeners.client.bind.clear();
    database.pool_size = 0U;

    // When
    auto const config = merovingian::config::Config{server, listeners, database, security};
    auto const findings = merovingian::config::validate(config);

    // Then
    REQUIRE_FALSE(findings.empty());
    REQUIRE_FALSE(merovingian::config::is_valid(config));
}

TEST_CASE("Config validation rejects unsafe registration policy", "[config][validation][security]")
{
    // Given
    auto security = merovingian::config::SecurityConfig{};
    security.registration.enabled = true;
    security.registration.require_token = false;

    // When
    auto const config = merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
    auto const findings = merovingian::config::validate(config);

    // Then
    REQUIRE_FALSE(findings.empty());
    REQUIRE_FALSE(merovingian::config::is_valid(config));
}

TEST_CASE("Config validation rejects invalid media upload size", "[config][validation][security]")
{
    // Given
    auto security = merovingian::config::SecurityConfig{};
    security.media.max_upload_size = "unbounded";

    // When
    auto const config = merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
    auto const findings = merovingian::config::validate(config);

    // Then
    REQUIRE_FALSE(findings.empty());
    REQUIRE_FALSE(merovingian::config::is_valid(config));
}

TEST_CASE("Config validation rejects unsafe public URL, listener bind, and federation policy", "[config][validation][security]")
{
    // Given
    auto server = merovingian::config::ServerConfig{};
    auto listeners = merovingian::config::ListenersConfig{};
    auto database = merovingian::config::DatabaseConfig{};
    auto security = merovingian::config::SecurityConfig{};
    server.public_baseurl = "http://matrix.example.org";
    listeners.federation.bind = "127.0.0.1:not-a-port";
    security.federation.default_policy = "permissive";

    // When
    auto const config = merovingian::config::Config{server, listeners, database, security};
    auto const findings = merovingian::config::validate(config);

    // Then
    REQUIRE(findings.size() == 3U);
    REQUIRE_FALSE(merovingian::config::is_valid(config));
}

TEST_CASE("Config validation rejects public cleartext listeners", "[config][validation][security]")
{
    // Given
    auto server = merovingian::config::ServerConfig{};
    auto listeners = merovingian::config::ListenersConfig{};
    auto database = merovingian::config::DatabaseConfig{};
    auto security = merovingian::config::SecurityConfig{};
    listeners.client.bind = "0.0.0.0:8008";
    listeners.client.tls = false;

    // When
    auto const config = merovingian::config::Config{server, listeners, database, security};
    auto const findings = merovingian::config::validate(config);

    // Then
    REQUIRE(findings.size() == 1U);
    REQUIRE_FALSE(merovingian::config::is_valid(config));
}

TEST_CASE("Config validation rejects weakened Matrix security defaults", "[config][validation][security]")
{
    // Given
    auto security = merovingian::config::SecurityConfig{};
    security.encryption.default_for_new_rooms = false;
    security.encryption.require_for_direct_messages = false;
    security.federation.require_valid_tls = false;
    security.federation.verify_json_signatures = false;
    security.federation.deny_ip_ranges.clear();
    security.media.block_private_ip_fetches = false;
    security.media.decode_in_sandbox = false;
    security.logging.redact_tokens = false;
    security.logging.redact_event_content = false;

    // When
    auto const config = merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
    auto const findings = merovingian::config::validate(config);

    // Then
    REQUIRE(findings.size() == 9U);
    REQUIRE_FALSE(merovingian::config::is_valid(config));
}
