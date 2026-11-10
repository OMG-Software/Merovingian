// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// Registration token file loading (load_hashed_registration_token), which needs
// no runtime: a rotated token file invalidates the cached hash, and an insecure
// file is refused even after a hash was cached. The auth_service functions that
// run over a started runtime are tested in
// tests/integration/test_homeserver_auth_service_flow.cpp (ADR-0593).

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/auth/AccountState.hpp"
#include "merovingian/auth/password.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/RegistrationSecurityConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalUser.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/auth_service.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

// --- bootstrap_admin_user --------------------------------------------------------

#if defined(__linux__)
#endif

// --- load_hashed_registration_token: rotation invalidates the cache -----------

// M-01 (security audit 2026-09). The Argon2id hash of the registration token
// file is cached because hashing it on every registration would be a
// self-inflicted DoS. It was cached by path alone and never revalidated, so an
// operator who rotated the token on disk kept serving the old one until the
// next restart — a revoked credential that stays live is the failure mode
// credential rotation exists to prevent.
SCENARIO("load_hashed_registration_token reloads a rotated token file", "[homeserver][auth][registration][token]")
{
    GIVEN("a registration token file on disk")
    {
        REQUIRE(sodium_init() >= 0);
        auto const path = std::filesystem::path{merovingian::tests::temporary_directory() /
                                                ("merovingian-rotate-" + std::to_string(::getpid()) + ".txt")};
        {
            auto output = std::ofstream{path};
            output << "first-token-value\n";
        }
        std::filesystem::permissions(path, std::filesystem::perms::owner_read);
        auto registration = merovingian::config::RegistrationSecurityConfig{};
        registration.token_file = path.string();

        auto const first = merovingian::homeserver::load_hashed_registration_token(registration);
        REQUIRE(first.has_value());
        REQUIRE(merovingian::auth::registration_token_matches(*first, "first-token-value"));

        WHEN("the file is read again without changing")
        {
            auto const again = merovingian::homeserver::load_hashed_registration_token(registration);

            THEN("the same hash is served from cache")
            {
                REQUIRE(again.has_value());
                REQUIRE(*again == *first);
            }
        }

        WHEN("the operator rotates the token on disk")
        {
            // A same-second rewrite is the hard case: an mtime-seconds-only
            // check would miss it. The identity therefore includes size and
            // sub-second mtime as well.
            std::filesystem::permissions(path,
                                         std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
            {
                auto output = std::ofstream{path, std::ios::trunc};
                output << "second-token-value-which-is-longer\n";
            }
            std::filesystem::permissions(path, std::filesystem::perms::owner_read);
            auto const rotated = merovingian::homeserver::load_hashed_registration_token(registration);

            THEN("the new token is accepted and the old one is not")
            {
                REQUIRE(rotated.has_value());
                REQUIRE(merovingian::auth::registration_token_matches(*rotated, "second-token-value-which-is-longer"));
                REQUIRE_FALSE(merovingian::auth::registration_token_matches(*rotated, "first-token-value"));
            }
        }

        std::error_code ec{};
        std::ignore = std::filesystem::remove(path, ec);
    }
}

// --- load_hashed_registration_token ------------------------------------------------

SCENARIO("Registration token loading rejects insecure files even after caching",
         "[homeserver][auth][iso7-registration]")
{
    GIVEN("a securely provisioned registration token file")
    {
        REQUIRE(sodium_init() >= 0);
        auto const path = merovingian::tests::registration_token_file();
        std::filesystem::permissions(path, std::filesystem::perms::owner_read);
        auto registration = merovingian::config::RegistrationSecurityConfig{};
        registration.token_file = path;
        REQUIRE(merovingian::homeserver::load_hashed_registration_token(registration).has_value());
        WHEN("its permissions become group-readable")
        {
            std::filesystem::permissions(path, std::filesystem::perms::owner_read | std::filesystem::perms::group_read);
            auto const accepted = merovingian::homeserver::load_hashed_registration_token(registration).has_value();
            std::filesystem::remove(path);
            THEN("a cached hash cannot authorize use of the insecure file")
            {
                REQUIRE_FALSE(accepted);
            }
        }
        WHEN("a fresh unsafe file has never been cached")
        {
            auto const unsafe = merovingian::tests::registration_token_file();
            std::filesystem::permissions(unsafe,
                                         std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
            registration.token_file = unsafe;
            auto const accepted = merovingian::homeserver::load_hashed_registration_token(registration).has_value();
            std::filesystem::remove(unsafe);
            std::filesystem::remove(path);
            THEN("the read boundary refuses it before hashing")
            {
                REQUIRE_FALSE(accepted);
            }
        }
    }
}

SCENARIO("load_hashed_registration_token loads and hashes a token file once",
         "[homeserver][auth][registration][security]")
{
    GIVEN("a registration token file")
    {
        REQUIRE(sodium_init() >= 0);
        auto token_file = merovingian::tests::registration_token_file();
        auto config = merovingian::config::RegistrationSecurityConfig{};
        config.enabled = true;
        config.require_token = true;
        config.token_file = token_file;

        WHEN("the token file is hashed")
        {
            auto const first = merovingian::homeserver::load_hashed_registration_token(config);

            THEN("a non-empty Argon2id hash is returned")
            {
                REQUIRE(first.has_value());
                REQUIRE(!first->empty());
            }
        }

        WHEN("the hash is used to verify the original token")
        {
            auto const hash = merovingian::homeserver::load_hashed_registration_token(config);

            THEN("the correct token validates and an incorrect token is rejected")
            {
                REQUIRE(hash.has_value());
                REQUIRE(merovingian::auth::registration_token_matches(
                    *hash, std::string{merovingian::tests::registration_token}));
                REQUIRE_FALSE(merovingian::auth::registration_token_matches(*hash, "not-the-token"));
            }
        }

        WHEN("the same token file is hashed twice")
        {
            auto const first = merovingian::homeserver::load_hashed_registration_token(config);
            auto const second = merovingian::homeserver::load_hashed_registration_token(config);

            THEN("the second call returns the cached hash without re-reading the file")
            {
                REQUIRE(first.has_value());
                REQUIRE(second.has_value());
                REQUIRE(*first == *second);
            }
        }
    }

    GIVEN("a missing token file")
    {
        auto config = merovingian::config::RegistrationSecurityConfig{};
        config.enabled = true;
        config.require_token = true;
        config.token_file = "/nonexistent/registration/token/file.txt";

        WHEN("load_hashed_registration_token is called")
        {
            auto const hash = merovingian::homeserver::load_hashed_registration_token(config);

            THEN("no hash is returned so registration is rejected")
            {
                REQUIRE_FALSE(hash.has_value());
            }
        }
    }
}
