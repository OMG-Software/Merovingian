// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// Registration files and a homeserver Config for tests that run appservices.
//
// Every appservice written here has the as_token "as-token-<id>", the hs_token
// "hs-token-<id>" and the sender_localpart "_<id>_bot", so a test can build the
// tokens it presents from the id alone. A fresh file is written per call, so
// parallel scenarios never share on-disk state.

#include "in_memory_database_config.hpp"
#include "master_key.hpp"
#include "merovingian/config/config.hpp"
#include "registration_token.hpp"
#include "temp_directory.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::tests
{

struct TestAppservice final
{
    std::string id{"bridge"};
    // The registration's `url`; nullopt writes `url: null` ("no traffic is required").
    std::optional<std::string> url{};
    // POSIX ERE patterns; an empty string leaves that namespace out.
    std::string users_regex{};
    std::string aliases_regex{};
    std::string rooms_regex{};
    std::vector<std::string> protocols{};
    bool receive_ephemeral{false};

    [[nodiscard]] auto as_token() const -> std::string
    {
        return "as-token-" + id;
    }

    [[nodiscard]] auto hs_token() const -> std::string
    {
        return "hs-token-" + id;
    }
};

[[nodiscard]] inline auto write_test_registration(TestAppservice const& appservice) -> std::filesystem::path
{
    static auto counter = std::atomic<std::uint64_t>{0U};
    auto const path =
        temporary_directory() / ("merovingian-as-" + appservice.id + "-" +
                                 std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "-" +
                                 std::to_string(counter.fetch_add(1U)) + ".json");
    auto const entries = [](std::string_view regex) {
        return regex.empty() ? std::string{"[]"}
                             : std::string{R"([{"exclusive": false, "regex": ")"} + std::string{regex} + R"("}])";
    };
    auto out = std::ofstream{path, std::ios::binary};
    out << R"({"id": ")" << appservice.id << R"(", "url": )";
    if (appservice.url.has_value())
    {
        out << '"' << *appservice.url << '"';
    }
    else
    {
        out << "null";
    }
    out << R"(, "as_token": ")" << appservice.as_token() << R"(", "hs_token": ")" << appservice.hs_token()
        << R"(", "sender_localpart": "_)" << appservice.id << R"(_bot", "namespaces": {"users": )"
        << entries(appservice.users_regex) << R"(, "aliases": )" << entries(appservice.aliases_regex)
        << R"(, "rooms": )" << entries(appservice.rooms_regex) << R"(}, "protocols": [)";
    for (auto index = std::size_t{0U}; index < appservice.protocols.size(); ++index)
    {
        out << (index == 0U ? "" : ", ") << '"' << appservice.protocols[index] << '"';
    }
    out << R"(], "receive_ephemeral": )" << (appservice.receive_ephemeral ? "true" : "false") << "}";
    return path;
}

// A Config with token registration enabled, an in-memory database and the given appservices
// registered. The caller may adjust it (for example `appservice().max_queued_events`) before
// starting the runtime.
[[nodiscard]] inline auto appservice_test_config(std::vector<TestAppservice> const& appservices)
    -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest.
    security.secrets.master_key_file = shared_master_key_file();
    enable_token_registration(security);
    auto config = merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
    for (auto const& appservice : appservices)
    {
        config.appservice().registration_files.push_back(write_test_registration(appservice).string());
    }
    return config;
}

} // namespace merovingian::tests
