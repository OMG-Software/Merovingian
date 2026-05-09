// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/config_parser.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("Key-value config parser preserves secure defaults for empty input", "[config][parser]")
{
    // Given
    auto const input = std::string{};

    // When
    auto const result = merovingian::config::parse_key_value_config(input);

    // Then
    REQUIRE(result.findings.empty());
    REQUIRE(result.config.server().server_name == "example.org");
    REQUIRE(result.config.security().encryption.default_for_new_rooms);
}

TEST_CASE("Key-value config parser applies known scalar values", "[config][parser]")
{
    // Given
    auto const input = std::string{
        "server.name=matrix.example.org\n"
        "server.public_baseurl=https://matrix.example.org\n"
        "listeners.client.bind=127.0.0.1:9008\n"
        "database.pool_size=32\n"
        "security.federation.default_policy=deny\n"
        "security.federation.max_transaction_size=8MiB\n"
        "security.federation.remote_timeout=45s\n"
        "security.media.max_upload_size=25MiB\n"
    };

    // When
    auto const result = merovingian::config::parse_key_value_config(input);

    // Then
    REQUIRE(result.findings.empty());
    REQUIRE(result.config.server().server_name == "matrix.example.org");
    REQUIRE(result.config.listeners().client.bind == "127.0.0.1:9008");
    REQUIRE(result.config.database().pool_size == 32U);
    REQUIRE(result.config.security().federation.default_policy == "deny");
    REQUIRE(result.config.security().federation.max_transaction_size == "8MiB");
    REQUIRE(result.config.security().federation.remote_timeout == "45s");
    REQUIRE(result.config.security().media.max_upload_size == "25MiB");
}

TEST_CASE("Key-value config parser applies booleans and lists", "[config][parser]")
{
    // Given
    auto const input = std::string{
        "server.trusted_proxies=127.0.0.1, 10.0.0.1\n"
        "listeners.client.tls=true\n"
        "security.media.enable_av_scanner=false\n"
        "security.federation.deny_ip_ranges=127.0.0.0/8, ::1/128\n"
    };

    // When
    auto const result = merovingian::config::parse_key_value_config(input);

    // Then
    REQUIRE(result.findings.empty());
    REQUIRE(result.config.server().trusted_proxies.size() == 2U);
    REQUIRE(result.config.listeners().client.tls);
    REQUIRE_FALSE(result.config.security().media.enable_av_scanner);
    REQUIRE(result.config.security().federation.deny_ip_ranges.size() == 2U);
}

TEST_CASE("Key-value config parser ignores comments and blank lines", "[config][parser]")
{
    // Given
    auto const input = std::string{
        "# comment\n"
        "\n"
        " server.name = matrix.example.org \n"
    };

    // When
    auto const result = merovingian::config::parse_key_value_config(input);

    // Then
    REQUIRE(result.findings.empty());
    REQUIRE(result.config.server().server_name == "matrix.example.org");
}

TEST_CASE("Key-value config parser rejects unknown keys and malformed lines", "[config][parser]")
{
    // Given
    auto const input = std::string{
        "unknown.key=value\n"
        "not a key value line\n"
    };

    // When
    auto const result = merovingian::config::parse_key_value_config(input);

    // Then
    REQUIRE(result.findings.size() == 2U);
}

TEST_CASE("Key-value config parser rejects duplicate keys", "[config][parser]")
{
    // Given
    auto const input = std::string{
        "server.name=one.example.org\n"
        "server.name=two.example.org\n"
    };

    // When
    auto const result = merovingian::config::parse_key_value_config(input);

    // Then
    REQUIRE(result.findings.size() == 1U);
    REQUIRE(result.config.server().server_name == "one.example.org");
}

TEST_CASE("Key-value config parser rejects oversized input", "[config][parser]")
{
    // Given
    auto input = std::string(merovingian::config::max_config_bytes + 1U, '#');

    // When
    auto const result = merovingian::config::parse_key_value_config(input);

    // Then
    REQUIRE(result.findings.size() == 1U);
}

TEST_CASE("Key-value config parser rejects oversized lines", "[config][parser]")
{
    // Given
    auto const input = std::string{"server.name="} + std::string(merovingian::config::max_config_line_bytes, 'a');

    // When
    auto const result = merovingian::config::parse_key_value_config(input);

    // Then
    REQUIRE_FALSE(result.findings.empty());
}

TEST_CASE("Key-value config parser rejects invalid typed values", "[config][parser]")
{
    // Given
    auto const input = std::string{
        "listeners.client.tls=yes\n"
        "database.pool_size=-1\n"
    };

    // When
    auto const result = merovingian::config::parse_key_value_config(input);

    // Then
    REQUIRE(result.findings.size() == 2U);
}

TEST_CASE("Key-value config parser validates parsed insecure settings", "[config][parser]")
{
    // Given
    auto const input = std::string{
        "server.public_baseurl=http://matrix.example.org\n"
        "listeners.client.bind=0.0.0.0:8008\n"
        "security.registration.enabled=true\n"
        "security.registration.require_token=false\n"
        "security.federation.max_transaction_size=unbounded\n"
        "security.federation.remote_timeout=forever\n"
    };

    // When
    auto const result = merovingian::config::parse_key_value_config(input);

    // Then
    REQUIRE_FALSE(result.findings.empty());
    REQUIRE_FALSE(merovingian::config::is_valid(result.config));
}
