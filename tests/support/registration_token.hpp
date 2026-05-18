// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>

namespace merovingian::tests
{

inline constexpr auto registration_token = std::string_view{"test-registration-token"};

inline auto registration_token_file() -> std::string
{
    auto const path = std::filesystem::temp_directory_path() / "merovingian-test-registration-token.txt";
    auto output = std::ofstream{path};
    output << registration_token << '\n';
    return path.string();
}

inline auto enable_token_registration(config::SecurityConfig& security) -> void
{
    security.registration.enabled = true;
    security.registration.require_token = true;
    security.registration.token_file = registration_token_file();
}

inline auto registration_json(std::string_view username, std::string_view password) -> std::string
{
    return std::string{R"({"username":")"} + std::string{username} + R"(","password":")" + std::string{password} +
           R"(","auth":{"type":"m.login.registration_token","token":"test-registration-token"}})";
}

inline auto registration_pipe(std::string_view localpart, std::string_view password) -> std::string
{
    return std::string{localpart} + "|" + std::string{password} + "|" + std::string{registration_token};
}

} // namespace merovingian::tests
