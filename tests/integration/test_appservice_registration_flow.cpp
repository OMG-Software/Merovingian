// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |          APPLICATION SERVICE REGISTRATION — PARSING & NAMESPACES        |
// |                                                                         |
// |  Spec: Matrix Application Service API v1.19, "Registration"            |
// |  URL:  ../../docs/matrix-v1.19-spec/application-service-api.md          |
// |                                                                         |
// |  Pure, network-free coverage of registration-file parsing, namespace   |
// |  matching, exclusivity, and cross-registration uniqueness validation.  |
// +-------------------------------------------------------------------------+

#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "../support/TempDirectory.hpp"
#include "merovingian/appservice/AppserviceRegistration.hpp"
#include "merovingian/appservice/AppserviceRegistry.hpp"
#include "merovingian/appservice/EventInterestFacts.hpp"
#include "merovingian/appservice/LoadRegistrationsResult.hpp"
#include "merovingian/appservice/Namespace.hpp"
#include "merovingian/appservice/Registration.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalUser.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

using merovingian::appservice::any_exclusive_namespace_matches;
using merovingian::appservice::any_namespace_matches;
using merovingian::appservice::appservice_owns_user;
using merovingian::appservice::AppserviceRegistration;
using merovingian::appservice::AppserviceRegistry;
using merovingian::appservice::EventInterestFacts;
using merovingian::appservice::load_registration_file;
using merovingian::appservice::load_registrations;
using merovingian::appservice::Namespace;
using merovingian::appservice::namespace_matches;
using merovingian::appservice::parse_registration_json;
using merovingian::appservice::registration_interested_in_room_event;
using merovingian::appservice::sender_user_id;
using merovingian::appservice::validate_registrations;

namespace
{

[[nodiscard]] auto runtime_enabled_config(std::string server_name = "example.org") -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = std::move(server_name);
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        server,   merovingian::config::ListenersConfig{},        merovingian::tests::in_memory_database_config(),
        security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

// A scratch path no other run on this host shares, so concurrent runs never overwrite each other's file.
[[nodiscard]] auto unique_registration_path(std::string const& label) -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() / ("merovingian-" + label + "-" + std::to_string(now) + ".json");
}

// Removes a scratch file when the scope ends, including when a failed REQUIRE unwinds it.
class RemoveFileOnExit final
{
public:
    explicit RemoveFileOnExit(std::filesystem::path path)
        : path_{std::move(path)}
    {
    }

    RemoveFileOnExit(RemoveFileOnExit const&) = delete;
    auto operator=(RemoveFileOnExit const&) -> RemoveFileOnExit& = delete;
    RemoveFileOnExit(RemoveFileOnExit&&) = delete;
    auto operator=(RemoveFileOnExit&&) -> RemoveFileOnExit& = delete;

    ~RemoveFileOnExit() noexcept
    {
        auto error = std::error_code{};
        std::ignore = std::filesystem::remove(path_, error);
    }

private:
    std::filesystem::path path_;
};

} // namespace

// AUTH-3: the sender_localpart user must be created at runtime startup,
// before ordinary client registration can race for the same localpart.
SCENARIO("appservice sender_localpart users are created at runtime startup",
         "[appservice][registration][security][auth-3]")
{
    GIVEN("a registration file whose sender_localpart is outside its users namespace")
    {
        auto const path = unique_registration_path("auth3-sender");
        auto const remove_registration = RemoveFileOnExit{path};
        {
            auto out = std::ofstream{path, std::ios::binary};
            out << R"({
                "id": "auth3-bridge",
                "url": null,
                "as_token": "as-token-auth3",
                "hs_token": "hs-token-auth3",
                "sender_localpart": "_auth3_bot",
                "namespaces": {
                    "users": [{"exclusive": true, "regex": "@_auth3_.*"}],
                    "aliases": [],
                    "rooms": []
                },
                "protocols": []
            })";
        }

        auto config = runtime_enabled_config();
        config.appservice().registration_files = {path.string()};

        WHEN("the runtime starts")
        {
            auto started = merovingian::homeserver::start_runtime(config);
            REQUIRE(started.started);
            auto const& runtime = started.runtime;

            THEN("the sender_localpart user exists in the local user store")
            {
                auto const expected_sender = std::string{"@_auth3_bot:example.org"};
                auto const found = std::ranges::any_of(
                    runtime.database.users, [&expected_sender](merovingian::homeserver::LocalUser const& user) {
                        return user.user_id == expected_sender;
                    });
                REQUIRE(found);
            }
        }
    }
}
