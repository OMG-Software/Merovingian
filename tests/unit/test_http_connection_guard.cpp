// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/TlsMockServer.hpp"
#include "merovingian/homeserver/Tls.hpp"
#include "merovingian/http/SlowlorisPolicy.hpp"
#include "merovingian/http/ConnectionGuard.hpp"

#include <catch2/catch_test_macros.hpp>
#include <openssl/ssl.h>

#include <string>

SCENARIO("HTTP slowloris policy validates conservative bounds", "[http][slowloris]")
{
    GIVEN("the default slowloris policy")
    {
        auto const policy = merovingian::http::SlowlorisPolicy{};

        WHEN("the policy is validated")
        {
            auto const valid = merovingian::http::slowloris_policy_is_valid(policy);

            THEN("the conservative bounds are accepted")
            {
                REQUIRE(valid);
                REQUIRE(policy.min_bytes_per_second == 64U);
                REQUIRE(policy.grace_seconds == 5U);
                REQUIRE(policy.header_deadline_seconds == 30U);
            }
        }
    }
}

SCENARIO("HTTP slowloris guard allows grace period and rejects slow progress", "[http][slowloris]")
{
    GIVEN("the default slowloris policy")
    {
        auto const policy = merovingian::http::SlowlorisPolicy{};

        WHEN("request progress samples are evaluated")
        {
            auto const grace_period_too_slow = merovingian::http::request_progress_is_too_slow({0U, 5U}, policy);
            auto const under_rate_too_slow = merovingian::http::request_progress_is_too_slow({63U, 6U}, policy);
            auto const at_rate_too_slow = merovingian::http::request_progress_is_too_slow({64U, 6U}, policy);
            auto const deadline_exceeded_too_slow =
                merovingian::http::request_progress_is_too_slow({4096U, 31U}, policy);

            THEN("only slow or deadline-exceeded progress is rejected")
            {
                REQUIRE_FALSE(grace_period_too_slow);
                REQUIRE(under_rate_too_slow);
                REQUIRE_FALSE(at_rate_too_slow);
                REQUIRE(deadline_exceeded_too_slow);
            }
        }
    }
}

SCENARIO("HTTP slowloris policy summary is stable", "[http][slowloris]")
{
    GIVEN("the default slowloris policy")
    {
        auto const policy = merovingian::http::SlowlorisPolicy{};

        WHEN("the policy summary is generated")
        {
            auto const summary = merovingian::http::slowloris_policy_summary(policy);

            THEN("the expected fields are present")
            {
                REQUIRE(summary.find("min_bytes_per_second=64") != std::string::npos);
                REQUIRE(summary.find("grace_seconds=5") != std::string::npos);
                REQUIRE(summary.find("header_deadline_seconds=30") != std::string::npos);
            }
        }
    }
}

SCENARIO("TLS server context excludes non-forward-secret cipher suites", "[http][tls][security]")
{
    // Security audit 2026-09 L-04: HIGH:!aNULL:!MD5:!RC4:!3DES still permitted
    // plain-RSA key exchange (no forward secrecy) and CBC/HMAC suites. This
    // only governs SSL_CTX_set_cipher_list, which configures TLS 1.2-and-below
    // suites; TLS 1.3 ciphersuites are selected separately (OpenSSL's
    // compiled-in defaults, never touched by Tls.cpp) and must stay available.
    GIVEN("a TLS server context built with the hardened cipher list")
    {
        auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto result = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                       certificate.private_key_file);
        REQUIRE(result.ok());

        WHEN("the effective enabled cipher suites are inspected")
        {
            auto* const ciphers = SSL_CTX_get_ciphers(&result.context->native_handle());
            REQUIRE(ciphers != nullptr);
            REQUIRE(sk_SSL_CIPHER_num(ciphers) > 0);

            auto saw_tls13_suite = false;
            auto saw_rsa_key_exchange = false;
            for (auto i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i)
            {
                auto const* cipher = sk_SSL_CIPHER_value(ciphers, i);
                if (SSL_CIPHER_get_kx_nid(cipher) == NID_kx_rsa)
                {
                    saw_rsa_key_exchange = true;
                }
                if (std::string{SSL_CIPHER_get_name(cipher)}.starts_with("TLS_"))
                {
                    saw_tls13_suite = true;
                }
            }

            THEN("no enabled suite uses plain RSA key exchange, and a TLS 1.3 ciphersuite is still present")
            {
                REQUIRE_FALSE(saw_rsa_key_exchange);
                REQUIRE(saw_tls13_suite);
            }
        }
    }
}
