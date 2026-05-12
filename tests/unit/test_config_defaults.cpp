// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstdint>
#include <string>

#include <catch2/catch_test_macros.hpp>
#include <merovingian/config/config.hpp>

SCENARIO("Config provides secure server and listener defaults", "[config]")
{
    GIVEN("a default config")
    {
        auto const config = merovingian::config::Config{};

        WHEN("server, listener, and database defaults are inspected")
        {
            auto const& server = config.server();
            auto const& listeners = config.listeners();
            auto const& database = config.database();

            THEN("secure defaults are present")
            {
                REQUIRE(server.server_name == "example.org");
                REQUIRE(server.public_baseurl == "https://matrix.example.org");
                REQUIRE(server.trusted_proxies.empty());
                REQUIRE(listeners.client.bind == "127.0.0.1:8008");
                REQUIRE_FALSE(listeners.client.tls);
                REQUIRE(listeners.client.tls_certificate_file.empty());
                REQUIRE(listeners.client.tls_private_key_file.empty());
                REQUIRE(listeners.federation.bind == "127.0.0.1:8448");
                REQUIRE_FALSE(listeners.federation.tls);
                REQUIRE(listeners.federation.tls_certificate_file.empty());
                REQUIRE(listeners.federation.tls_private_key_file.empty());
                REQUIRE(database.uri_file == "/etc/merovingian/db-uri");
                REQUIRE(database.pool_size == 16U);
            }
        }
    }
}

SCENARIO("Config validation rejects TLS listeners without configured certificate files", "[config][validation][tls]")
{
    GIVEN("a listener with TLS enabled and no certificate or private key path")
    {
        auto listeners = merovingian::config::ListenersConfig{};
        listeners.client.tls = true;

        WHEN("the config is constructed and validated")
        {
            auto const config = merovingian::config::Config{
                merovingian::config::ServerConfig{},
                listeners,
                merovingian::config::DatabaseConfig{},
                merovingian::config::SecurityConfig{},
            };
            auto const findings = merovingian::config::validate(config);
            auto const valid = merovingian::config::is_valid(config);

            THEN("both missing key material paths are reported")
            {
                REQUIRE(findings.size() == 2U);
                REQUIRE(findings[0].field == "listeners.client.tls_certificate_file");
                REQUIRE(findings[1].field == "listeners.client.tls_private_key_file");
                REQUIRE_FALSE(valid);
            }
        }
    }
}

SCENARIO("Config disables open registration by default", "[config][security]")
{
    GIVEN("a default config")
    {
        auto const config = merovingian::config::Config{};

        WHEN("registration defaults are inspected")
        {
            auto const& registration = config.security().registration;

            THEN("registration requires a token and is disabled")
            {
                REQUIRE_FALSE(registration.enabled);
                REQUIRE(registration.require_token);
            }
        }
    }
}

SCENARIO("Config defaults private rooms and direct messages to encrypted", "[config][security]")
{
    GIVEN("a default config")
    {
        auto const config = merovingian::config::Config{};

        WHEN("encryption defaults are inspected")
        {
            auto const& encryption = config.security().encryption;

            THEN("private and direct contexts require encryption")
            {
                REQUIRE(encryption.default_for_new_rooms);
                REQUIRE(encryption.require_for_direct_messages);
                REQUIRE(encryption.require_for_private_rooms);
                REQUIRE(encryption.allow_unencrypted_public_rooms);
                REQUIRE(encryption.block_unencrypted_federated_private_rooms);
            }
        }
    }
}

SCENARIO("Config blocks private federation and loopback targets by default", "[config][security]")
{
    GIVEN("a default config")
    {
        auto const config = merovingian::config::Config{};

        WHEN("federation defaults are inspected")
        {
            auto const& federation = config.security().federation;

            THEN("secure federation defaults are present")
            {
                REQUIRE(federation.enabled);
                REQUIRE(federation.default_policy == "allow");
                REQUIRE(federation.require_valid_tls);
                REQUIRE(federation.verify_json_signatures);
                REQUIRE(federation.deny_ip_ranges.size() == 6U);
                REQUIRE(federation.deny_ip_ranges[0] == "127.0.0.0/8");
                REQUIRE(federation.deny_ip_ranges[5] == "fc00::/7");
                REQUIRE(federation.max_transaction_size == "10MiB");
                REQUIRE(federation.remote_timeout == "30s");
            }
        }
    }
}

SCENARIO("Config enables media and logging protections by default", "[config][security]")
{
    GIVEN("a default config")
    {
        auto const config = merovingian::config::Config{};

        WHEN("media and logging defaults are inspected")
        {
            auto const& media = config.security().media;
            auto const& logging = config.security().logging;

            THEN("protective defaults are enabled")
            {
                REQUIRE(media.max_upload_size == "50MiB");
                REQUIRE(media.quarantine_unknown_mime);
                REQUIRE(media.enable_av_scanner);
                REQUIRE(media.block_private_ip_fetches);
                REQUIRE(media.decode_in_sandbox);
                REQUIRE(logging.redact_tokens);
                REQUIRE(logging.redact_event_content);
                REQUIRE(logging.structured);
            }
        }
    }
}

SCENARIO("Default media upload limit parses to bytes", "[config][validation]")
{
    GIVEN("the default media upload limit")
    {
        auto const default_limit = std::string{"50MiB"};

        WHEN("the size limit is parsed")
        {
            auto const parsed = merovingian::config::parse_size_limit(default_limit);

            THEN("the byte count is bounded")
            {
                REQUIRE(parsed.valid);
                REQUIRE(parsed.bytes == 52428800U);
            }
        }
    }
}

SCENARIO("Default federation transaction limit and timeout parse", "[config][validation]")
{
    GIVEN("default federation transaction and timeout values")
    {
        auto const transaction_limit = std::string{"10MiB"};
        auto const remote_timeout = std::string{"30s"};

        WHEN("the values are parsed")
        {
            auto const parsed_limit = merovingian::config::parse_size_limit(transaction_limit);
            auto const parsed_timeout = merovingian::config::parse_duration_seconds(remote_timeout);

            THEN("they parse to bounded values")
            {
                REQUIRE(parsed_limit.valid);
                REQUIRE(parsed_limit.bytes == 10485760U);
                REQUIRE(parsed_timeout.valid);
                REQUIRE(parsed_timeout.seconds == 30U);
            }
        }
    }
}

SCENARIO("Media upload size parser rejects invalid or unbounded-looking values", "[config][validation]")
{
    GIVEN("invalid size limit strings")
    {
        auto const empty = std::string{};
        auto const zero = std::string{"0MiB"};
        auto const unsupported_suffix = std::string{"50MB"};
        auto const negative = std::string{"-1MiB"};
        auto const malformed = std::string{"50 MiB"};

        WHEN("the size limits are parsed")
        {
            auto const empty_result = merovingian::config::parse_size_limit(empty);
            auto const zero_result = merovingian::config::parse_size_limit(zero);
            auto const unsupported_suffix_result = merovingian::config::parse_size_limit(unsupported_suffix);
            auto const negative_result = merovingian::config::parse_size_limit(negative);
            auto const malformed_result = merovingian::config::parse_size_limit(malformed);

            THEN("all invalid values are rejected")
            {
                REQUIRE_FALSE(empty_result.valid);
                REQUIRE_FALSE(zero_result.valid);
                REQUIRE_FALSE(unsupported_suffix_result.valid);
                REQUIRE_FALSE(negative_result.valid);
                REQUIRE_FALSE(malformed_result.valid);
            }
        }
    }
}

SCENARIO("Duration parser accepts bounded seconds and minutes", "[config][validation]")
{
    GIVEN("bounded duration strings")
    {
        auto const seconds = std::string{"30s"};
        auto const minutes = std::string{"1m"};

        WHEN("the durations are parsed")
        {
            auto const parsed_seconds = merovingian::config::parse_duration_seconds(seconds);
            auto const parsed_minutes = merovingian::config::parse_duration_seconds(minutes);

            THEN("the durations are accepted")
            {
                REQUIRE(parsed_seconds.valid);
                REQUIRE(parsed_minutes.seconds == 60U);
            }
        }
    }
}

SCENARIO("Duration parser rejects invalid or unbounded-looking values", "[config][validation]")
{
    GIVEN("invalid duration strings")
    {
        auto const empty = std::string{};
        auto const zero = std::string{"0s"};
        auto const missing_suffix = std::string{"30"};
        auto const unsupported_suffix = std::string{"30ms"};
        auto const unbounded = std::string{"forever"};

        WHEN("the durations are parsed")
        {
            auto const empty_result = merovingian::config::parse_duration_seconds(empty);
            auto const zero_result = merovingian::config::parse_duration_seconds(zero);
            auto const missing_suffix_result = merovingian::config::parse_duration_seconds(missing_suffix);
            auto const unsupported_suffix_result = merovingian::config::parse_duration_seconds(unsupported_suffix);
            auto const unbounded_result = merovingian::config::parse_duration_seconds(unbounded);

            THEN("all invalid durations are rejected")
            {
                REQUIRE_FALSE(empty_result.valid);
                REQUIRE_FALSE(zero_result.valid);
                REQUIRE_FALSE(missing_suffix_result.valid);
                REQUIRE_FALSE(unsupported_suffix_result.valid);
                REQUIRE_FALSE(unbounded_result.valid);
            }
        }
    }
}

SCENARIO("Config validation helpers accept secure address-shaped defaults", "[config][validation]")
{
    GIVEN("secure address-shaped values")
    {
        auto const public_baseurl = std::string{"https://matrix.example.org"};
        auto const listener_bind = std::string{"127.0.0.1:8008"};

        WHEN("the values are validated")
        {
            auto const public_baseurl_valid = merovingian::config::is_valid_public_baseurl(public_baseurl);
            auto const listener_bind_valid = merovingian::config::is_valid_listener_bind(listener_bind);
            auto const allow_policy_valid = merovingian::config::is_valid_federation_policy("allow");
            auto const deny_policy_valid = merovingian::config::is_valid_federation_policy("deny");

            THEN("the secure values are accepted")
            {
                REQUIRE(public_baseurl_valid);
                REQUIRE(listener_bind_valid);
                REQUIRE(allow_policy_valid);
                REQUIRE(deny_policy_valid);
            }
        }
    }
}

SCENARIO("Config validation helpers reject unsafe address-shaped values", "[config][validation]")
{
    GIVEN("unsafe address-shaped values")
    {
        auto const insecure_public_baseurl = std::string{"http://matrix.example.org"};
        auto const empty_host_bind = std::string{":8008"};
        auto const missing_port_bind = std::string{"127.0.0.1"};
        auto const out_of_range_port_bind = std::string{"127.0.0.1:70000"};

        WHEN("the values are validated")
        {
            auto const insecure_public_baseurl_valid =
                merovingian::config::is_valid_public_baseurl(insecure_public_baseurl);
            auto const empty_host_bind_valid = merovingian::config::is_valid_listener_bind(empty_host_bind);
            auto const missing_port_bind_valid = merovingian::config::is_valid_listener_bind(missing_port_bind);
            auto const out_of_range_port_bind_valid =
                merovingian::config::is_valid_listener_bind(out_of_range_port_bind);
            auto const permissive_policy_valid = merovingian::config::is_valid_federation_policy("permissive");

            THEN("the unsafe values are rejected")
            {
                REQUIRE_FALSE(insecure_public_baseurl_valid);
                REQUIRE_FALSE(empty_host_bind_valid);
                REQUIRE_FALSE(missing_port_bind_valid);
                REQUIRE_FALSE(out_of_range_port_bind_valid);
                REQUIRE_FALSE(permissive_policy_valid);
            }
        }
    }
}

SCENARIO("Config validation accepts cleartext listeners only on loopback", "[config][validation]")
{
    GIVEN("loopback cleartext and public TLS listeners")
    {
        auto const loopback_listener = merovingian::config::ListenerConfig{"127.0.0.1:8008", false};
        auto const tls_public_listener = merovingian::config::ListenerConfig{"0.0.0.0:8448", true};

        WHEN("cleartext listener safety is evaluated")
        {
            auto const loopback_listener_safe = merovingian::config::is_safe_cleartext_listener(loopback_listener);
            auto const tls_public_listener_safe = merovingian::config::is_safe_cleartext_listener(tls_public_listener);

            THEN("the listener configurations are accepted")
            {
                REQUIRE(loopback_listener_safe);
                REQUIRE(tls_public_listener_safe);
            }
        }
    }
}

SCENARIO("Config validation rejects cleartext listeners on public interfaces", "[config][validation]")
{
    GIVEN("a public cleartext listener")
    {
        auto const public_cleartext_listener = merovingian::config::ListenerConfig{"0.0.0.0:8008", false};

        WHEN("cleartext listener safety is evaluated")
        {
            auto const listener_safe = merovingian::config::is_safe_cleartext_listener(public_cleartext_listener);

            THEN("the listener is rejected")
            {
                REQUIRE_FALSE(listener_safe);
            }
        }
    }
}

SCENARIO("Default config validates without findings", "[config][validation]")
{
    GIVEN("a default config")
    {
        auto const config = merovingian::config::Config{};

        WHEN("the config is validated")
        {
            auto const findings = merovingian::config::validate(config);
            auto const valid = merovingian::config::is_valid(config);

            THEN("no findings are reported")
            {
                REQUIRE(findings.empty());
                REQUIRE(valid);
            }
        }
    }
}

SCENARIO("Config validation rejects missing critical fields", "[config][validation]")
{
    GIVEN("config sections with missing critical fields")
    {
        auto server = merovingian::config::ServerConfig{};
        auto listeners = merovingian::config::ListenersConfig{};
        auto database = merovingian::config::DatabaseConfig{};
        auto security = merovingian::config::SecurityConfig{};
        server.server_name.clear();
        listeners.client.bind.clear();
        database.pool_size = 0U;

        WHEN("the config is constructed and validated")
        {
            auto const config = merovingian::config::Config{server, listeners, database, security};
            auto const findings = merovingian::config::validate(config);
            auto const valid = merovingian::config::is_valid(config);

            THEN("validation fails")
            {
                REQUIRE_FALSE(findings.empty());
                REQUIRE_FALSE(valid);
            }
        }
    }
}

SCENARIO("Config validation rejects unsafe registration policy", "[config][validation][security]")
{
    GIVEN("registration enabled without requiring a token")
    {
        auto security = merovingian::config::SecurityConfig{};
        security.registration.enabled = true;
        security.registration.require_token = false;

        WHEN("the config is constructed and validated")
        {
            auto const config = merovingian::config::Config{
                merovingian::config::ServerConfig{},
                merovingian::config::ListenersConfig{},
                merovingian::config::DatabaseConfig{},
                security,
            };
            auto const findings = merovingian::config::validate(config);
            auto const valid = merovingian::config::is_valid(config);

            THEN("validation fails")
            {
                REQUIRE_FALSE(findings.empty());
                REQUIRE_FALSE(valid);
            }
        }
    }
}

SCENARIO("Config validation rejects invalid media upload size", "[config][validation][security]")
{
    GIVEN("security config with an invalid media upload size")
    {
        auto security = merovingian::config::SecurityConfig{};
        security.media.max_upload_size = "unbounded";

        WHEN("the config is constructed and validated")
        {
            auto const config = merovingian::config::Config{
                merovingian::config::ServerConfig{},
                merovingian::config::ListenersConfig{},
                merovingian::config::DatabaseConfig{},
                security,
            };
            auto const findings = merovingian::config::validate(config);
            auto const valid = merovingian::config::is_valid(config);

            THEN("validation fails")
            {
                REQUIRE_FALSE(findings.empty());
                REQUIRE_FALSE(valid);
            }
        }
    }
}

SCENARIO("Config validation rejects invalid federation transaction limits", "[config][validation][security]")
{
    GIVEN("security config with invalid federation limits")
    {
        auto security = merovingian::config::SecurityConfig{};
        security.federation.max_transaction_size = "unbounded";
        security.federation.remote_timeout = "forever";

        WHEN("the config is constructed and validated")
        {
            auto const config = merovingian::config::Config{
                merovingian::config::ServerConfig{},
                merovingian::config::ListenersConfig{},
                merovingian::config::DatabaseConfig{},
                security,
            };
            auto const findings = merovingian::config::validate(config);
            auto const valid = merovingian::config::is_valid(config);

            THEN("validation fails")
            {
                REQUIRE_FALSE(findings.empty());
                REQUIRE_FALSE(valid);
            }
        }
    }
}

SCENARIO("Config validation rejects unsafe public URL, listener bind, and federation policy",
         "[config][validation][security]")
{
    GIVEN("config sections with unsafe public URL, listener bind, and federation policy")
    {
        auto server = merovingian::config::ServerConfig{};
        auto listeners = merovingian::config::ListenersConfig{};
        auto database = merovingian::config::DatabaseConfig{};
        auto security = merovingian::config::SecurityConfig{};
        server.public_baseurl = "http://matrix.example.org";
        listeners.federation.bind = "127.0.0.1:not-a-port";
        security.federation.default_policy = "permissive";

        WHEN("the config is constructed and validated")
        {
            auto const config = merovingian::config::Config{server, listeners, database, security};
            auto const findings = merovingian::config::validate(config);
            auto const valid = merovingian::config::is_valid(config);

            THEN("all unsafe values are reported")
            {
                REQUIRE(findings.size() == 3U);
                REQUIRE_FALSE(valid);
            }
        }
    }
}

SCENARIO("Config validation rejects public cleartext listeners", "[config][validation][security]")
{
    GIVEN("config sections with a public cleartext listener")
    {
        auto server = merovingian::config::ServerConfig{};
        auto listeners = merovingian::config::ListenersConfig{};
        auto database = merovingian::config::DatabaseConfig{};
        auto security = merovingian::config::SecurityConfig{};
        listeners.client.bind = "0.0.0.0:8008";
        listeners.client.tls = false;

        WHEN("the config is constructed and validated")
        {
            auto const config = merovingian::config::Config{server, listeners, database, security};
            auto const findings = merovingian::config::validate(config);
            auto const valid = merovingian::config::is_valid(config);

            THEN("the public cleartext listener is rejected")
            {
                REQUIRE(findings.size() == 1U);
                REQUIRE_FALSE(valid);
            }
        }
    }
}

SCENARIO("Config validation rejects weakened Matrix security defaults", "[config][validation][security]")
{
    GIVEN("security config with weakened Matrix defaults")
    {
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

        WHEN("the config is constructed and validated")
        {
            auto const config = merovingian::config::Config{
                merovingian::config::ServerConfig{},
                merovingian::config::ListenersConfig{},
                merovingian::config::DatabaseConfig{},
                security,
            };
            auto const findings = merovingian::config::validate(config);
            auto const valid = merovingian::config::is_valid(config);

            THEN("all weakened defaults are reported")
            {
                REQUIRE(findings.size() == 9U);
                REQUIRE_FALSE(valid);
            }
        }
    }
}
