// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config_parser.hpp"

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
        auto const input = std::string{"server.name=matrix.example.org\n"
                                       "server.public_baseurl=https://matrix.example.org\n"
                                       "listeners.client.bind=127.0.0.1:9008\n"
                                       "database.pool_size=32\n"
                                       "security.federation.default_policy=deny\n"
                                       "security.federation.allowed_servers=matrix.org\n"
                                       "security.federation.max_transaction_size=8MiB\n"
                                       "security.federation.remote_timeout=45s\n"
                                       "security.registration.token_file=/etc/merovingian/registration-token\n"
                                       "security.secrets.master_key_file=/etc/merovingian/master.key\n"
                                       "security.media.max_upload_size=25MiB\n"};

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
                REQUIRE(result.config.security().federation.allowed_servers.size() == 1U);
                REQUIRE(result.config.security().federation.allowed_servers.front() == "matrix.org");
                REQUIRE(result.config.security().federation.max_transaction_size == "8MiB");
                REQUIRE(result.config.security().federation.remote_timeout == "45s");
                REQUIRE(result.config.security().registration.token_file == "/etc/merovingian/registration-token");
                REQUIRE(result.config.security().secrets.master_key_file == "/etc/merovingian/master.key");
                REQUIRE(result.config.security().media.max_upload_size == "25MiB");
            }
        }
    }
}

SCENARIO("Key-value config parser applies booleans and lists", "[config][parser]")
{
    GIVEN("config input with booleans and lists")
    {
        auto const input = std::string{"server.trusted_proxies=127.0.0.1, 10.0.0.1\n"
                                       "listeners.client.tls=true\n"
                                       "listeners.client.tls_certificate_file=/etc/merovingian/client.crt\n"
                                       "listeners.client.tls_private_key_file=/etc/merovingian/client.key\n"
                                       "security.media.enable_av_scanner=false\n"
                                       "security.media.remote_fetch_enabled=true\n"
                                       "security.trust_safety.enabled=true\n"
                                       "security.trust_safety.policy_server_url=https://policy.example.org/check\n"
                                       "security.trust_safety.policy_server_timeout=7s\n"
                                       "security.trust_safety.policy_server_allow_without_result=true\n"
                                       "security.federation.allowed_servers=matrix.org, example.net\n"
                                       "security.federation.denied_servers=bad.example, abuse.example\n"
                                       "security.federation.deny_ip_ranges=127.0.0.0/8, ::1/128\n"};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the typed values are applied")
            {
                REQUIRE(result.findings.empty());
                REQUIRE(result.config.server().trusted_proxies.size() == 2U);
                REQUIRE(result.config.listeners().client.tls);
                REQUIRE(result.config.listeners().client.tls_certificate_file == "/etc/merovingian/client.crt");
                REQUIRE(result.config.listeners().client.tls_private_key_file == "/etc/merovingian/client.key");
                REQUIRE_FALSE(result.config.security().media.enable_av_scanner);
                REQUIRE(result.config.security().media.remote_fetch_enabled);
                REQUIRE(result.config.security().trust_safety.enabled);
                REQUIRE(result.config.security().trust_safety.policy_server_url == "https://policy.example.org/check");
                REQUIRE(result.config.security().trust_safety.policy_server_timeout == "7s");
                REQUIRE(result.config.security().trust_safety.policy_server_allow_without_result);
                REQUIRE(result.config.security().federation.allowed_servers.size() == 2U);
                REQUIRE(result.config.security().federation.denied_servers.size() == 2U);
                REQUIRE(result.config.security().federation.deny_ip_ranges.size() == 2U);
            }
        }
    }
}

SCENARIO("Key-value config parser applies TLS certificate paths", "[config][parser][tls]")
{
    GIVEN("config input with client and federation TLS certificate paths")
    {
        auto const input = std::string{"listeners.client.tls=true\n"
                                       "listeners.client.tls_certificate_file=/etc/merovingian/client.pem\n"
                                       "listeners.client.tls_private_key_file=/etc/merovingian/client.key\n"
                                       "listeners.federation.tls=true\n"
                                       "listeners.federation.tls_certificate_file=/etc/merovingian/federation.pem\n"
                                       "listeners.federation.tls_private_key_file=/etc/merovingian/federation.key\n"};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the listener TLS file paths are preserved")
            {
                REQUIRE(result.findings.empty());
                REQUIRE(result.config.listeners().client.tls);
                REQUIRE(result.config.listeners().client.tls_certificate_file == "/etc/merovingian/client.pem");
                REQUIRE(result.config.listeners().client.tls_private_key_file == "/etc/merovingian/client.key");
                REQUIRE(result.config.listeners().federation.tls);
                REQUIRE(result.config.listeners().federation.tls_certificate_file == "/etc/merovingian/federation.pem");
                REQUIRE(result.config.listeners().federation.tls_private_key_file == "/etc/merovingian/federation.key");
            }
        }
    }
}

SCENARIO("Key-value config parser rejects TLS listeners without certificate paths", "[config][parser][tls]")
{
    GIVEN("config input enabling TLS without key material paths")
    {
        auto const input = std::string{"listeners.client.tls=true\n"};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the missing TLS files are reported")
            {
                REQUIRE(result.findings.size() == 2U);
                REQUIRE(result.findings[0].field == "listeners.client.tls_certificate_file");
                REQUIRE(result.findings[1].field == "listeners.client.tls_private_key_file");
            }
        }
    }
}

SCENARIO("Key-value config parser rejects deny-by-default federation without allowed servers", "[config][parser]")
{
    GIVEN("config input with deny-by-default federation and no allowed servers")
    {
        auto const input = std::string{"security.federation.default_policy=deny\n"};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the missing allowed server list is reported")
            {
                REQUIRE_FALSE(result.findings.empty());
                REQUIRE(result.findings.front().field == "security.federation.allowed_servers");
            }
        }
    }
}

SCENARIO("Key-value config parser rejects invalid federation server list entries", "[config][parser]")
{
    GIVEN("config input with malformed allowed and denied server entries")
    {
        auto const allowed_input = std::string{"security.federation.allowed_servers=bad server\n"};
        auto const denied_input = std::string{"security.federation.denied_servers=bad/server\n"};

        WHEN("the configs are parsed")
        {
            auto const allowed_result = merovingian::config::parse_key_value_config(allowed_input);
            auto const denied_result = merovingian::config::parse_key_value_config(denied_input);

            THEN("the malformed server names are reported")
            {
                REQUIRE_FALSE(allowed_result.findings.empty());
                REQUIRE(allowed_result.findings.front().field == "security.federation.allowed_servers");
                REQUIRE_FALSE(denied_result.findings.empty());
                REQUIRE(denied_result.findings.front().field == "security.federation.denied_servers");
            }
        }
    }
}

SCENARIO("Key-value config parser ignores comments and blank lines", "[config][parser]")
{
    GIVEN("config input with comments and blank lines")
    {
        auto const input = std::string{"# comment\n"
                                       "\n"
                                       " server.name = matrix.example.org \n"};

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
        auto const input = std::string{"unknown.key=value\n"
                                       "not a key value line\n"};

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
        auto const input = std::string{"server.name=one.example.org\n"
                                       "server.name=two.example.org\n"};

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
        auto const input = std::string{"listeners.client.tls=yes\n"
                                       "database.pool_size=-1\n"};

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
        auto const input = std::string{"server.public_baseurl=http://matrix.example.org\n"
                                       "listeners.client.bind=0.0.0.0:8008\n"
                                       "security.registration.enabled=true\n"
                                       "security.registration.require_token=false\n"
                                       "security.federation.max_transaction_size=unbounded\n"
                                       "security.federation.remote_timeout=forever\n"};

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

SCENARIO("Key-value config parser applies CORS policy keys", "[config][parser][cors]")
{
    GIVEN("a config with the CORS keys set to non-default values")
    {
        auto const input =
            std::string{"server.name=example.org\n"
                        "server.public_baseurl=https://matrix.example.org\n"
                        "server.cors.allowed_origins=https://app.example.com, https://other.example.com\n"
                        "server.cors.allow_methods=GET, POST, PUT, DELETE, OPTIONS\n"
                        "server.cors.allow_headers=authorization, content-type\n"
                        "server.cors.allow_credentials=false\n"
                        "server.cors.max_age=3600\n"};
        WHEN("the config is parsed and validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);
            REQUIRE(result.findings.empty());

            THEN("the CORS policy is round-tripped into the config struct")
            {
                REQUIRE(result.config.server().cors.allowed_origins.size() == 2U);
                REQUIRE(result.config.server().cors.allowed_origins.front() == "https://app.example.com");
                REQUIRE(result.config.server().cors.allow_methods == "GET, POST, PUT, DELETE, OPTIONS");
                REQUIRE(result.config.server().cors.allow_headers == "authorization, content-type");
                REQUIRE(result.config.server().cors.allow_credentials == false);
                REQUIRE(result.config.server().cors.max_age == 3600U);
            }
        }
    }
}

SCENARIO("Key-value config parser rejects wildcard origin with credentials enabled", "[config][parser][cors]")
{
    GIVEN("a config combining wildcard '*' with allow_credentials=true")
    {
        auto const input = std::string{"server.name=example.org\n"
                                       "server.public_baseurl=https://matrix.example.org\n"
                                       "server.cors.allowed_origins=*\n"
                                       "server.cors.allow_credentials=true\n"};
        WHEN("the config is validated")
        {
            auto const result = merovingian::config::parse_key_value_config(input);
            auto const findings = merovingian::config::validate(result.config);

            THEN("a finding names the offending field")
            {
                auto found = false;
                for (auto const& f : findings)
                {
                    if (f.field == "server.cors.allowed_origins")
                    {
                        found = true;
                        break;
                    }
                }
                REQUIRE(found);
            }
        }
    }
}
