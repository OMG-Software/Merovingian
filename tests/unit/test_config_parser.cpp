// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/config_parser.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Key-value config parser preserves secure defaults for empty input", "[config][parser]")
{
    GIVEN("empty config input")
    {
        auto const input = std::string{};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("secure defaults are preserved")
            {
                REQUIRE(result.findings.empty());
                REQUIRE(result.config.server().server_name == "example.org");
                REQUIRE(result.config.security().encryption.default_for_new_rooms);
            }
        }
    }
}

SCENARIO("Key-value config parser applies known scalar values", "[config][parser]")
{
    GIVEN("config input with known scalar values")
    {
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

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the scalar values are applied")
            {
                REQUIRE(result.findings.empty());
                REQUIRE(result.config.server().server_name == "matrix.example.org");
                REQUIRE(result.config.listeners().client.bind == "127.0.0.1:9008");
                REQUIRE(result.config.database().pool_size == 32U);
                REQUIRE(result.config.security().federation.default_policy == "deny");
                REQUIRE(result.config.security().federation.max_transaction_size == "8MiB");
                REQUIRE(result.config.security().federation.remote_timeout == "45s");
                REQUIRE(result.config.security().media.max_upload_size == "25MiB");
            }
        }
    }
}

SCENARIO("Key-value config parser applies booleans and lists", "[config][parser]")
{
    GIVEN("config input with booleans and lists")
    {
        auto const input = std::string{
            "server.trusted_proxies=127.0.0.1, 10.0.0.1\n"
            "listeners.client.tls=true\n"
            "security.media.enable_av_scanner=false\n"
            "security.federation.deny_ip_ranges=127.0.0.0/8, ::1/128\n"
        };

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the typed values are applied")
            {
                REQUIRE(result.findings.empty());
                REQUIRE(result.config.server().trusted_proxies.size() == 2U);
                REQUIRE(result.config.listeners().client.tls);
                REQUIRE_FALSE(result.config.security().media.enable_av_scanner);
                REQUIRE(result.config.security().federation.deny_ip_ranges.size() == 2U);
            }
        }
    }
}

SCENARIO("Key-value config parser ignores comments and blank lines", "[config][parser]")
{
    GIVEN("config input with comments and blank lines")
    {
        auto const input = std::string{
            "# comment\n"
            "\n"
            " server.name = matrix.example.org \n"
        };

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("comments and blanks are ignored")
            {
                REQUIRE(result.findings.empty());
                REQUIRE(result.config.server().server_name == "matrix.example.org");
            }
        }
    }
}

SCENARIO("Key-value config parser rejects unknown keys and malformed lines", "[config][parser]")
{
    GIVEN("config input with unknown and malformed lines")
    {
        auto const input = std::string{
            "unknown.key=value\n"
            "not a key value line\n"
        };

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("both issues are reported")
            {
                REQUIRE(result.findings.size() == 2U);
            }
        }
    }
}

SCENARIO("Key-value config parser rejects duplicate keys", "[config][parser]")
{
    GIVEN("config input with duplicate keys")
    {
        auto const input = std::string{
            "server.name=one.example.org\n"
            "server.name=two.example.org\n"
        };

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the duplicate is reported and the first value is retained")
            {
                REQUIRE(result.findings.size() == 1U);
                REQUIRE(result.config.server().server_name == "one.example.org");
            }
        }
    }
}

SCENARIO("Key-value config parser rejects oversized input", "[config][parser]")
{
    GIVEN("config input larger than the configured maximum")
    {
        auto input = std::string(merovingian::config::max_config_bytes + 1U, '#');

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the oversized input is rejected")
            {
                REQUIRE(result.findings.size() == 1U);
            }
        }
    }
}

SCENARIO("Key-value config parser rejects oversized lines", "[config][parser]")
{
    GIVEN("config input with an oversized line")
    {
        auto const input = std::string{"server.name="} + std::string(merovingian::config::max_config_line_bytes, 'a');

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the oversized line is rejected")
            {
                REQUIRE_FALSE(result.findings.empty());
            }
        }
    }
}

SCENARIO("Key-value config parser rejects invalid typed values", "[config][parser]")
{
    GIVEN("config input with invalid typed values")
    {
        auto const input = std::string{
            "listeners.client.tls=yes\n"
            "database.pool_size=-1\n"
        };

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("each invalid value is reported")
            {
                REQUIRE(result.findings.size() == 2U);
            }
        }
    }
}

SCENARIO("Key-value config parser validates parsed insecure settings", "[config][parser]")
{
    GIVEN("config input with insecure settings")
    {
        auto const input = std::string{
            "server.public_baseurl=http://matrix.example.org\n"
            "listeners.client.bind=0.0.0.0:8008\n"
            "security.registration.enabled=true\n"
            "security.registration.require_token=false\n"
            "security.federation.max_transaction_size=unbounded\n"
            "security.federation.remote_timeout=forever\n"
        };

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("validation findings are reported")
            {
                REQUIRE_FALSE(result.findings.empty());
                REQUIRE_FALSE(merovingian::config::is_valid(result.config));
            }
        }
    }
}
