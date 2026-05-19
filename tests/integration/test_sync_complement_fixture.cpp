// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

[[nodiscard]] auto read_file(std::filesystem::path const& path) -> std::string
{
    auto stream = std::ifstream{path};
    REQUIRE(stream.good());
    auto buffer = std::stringstream{};
    buffer << stream.rdbuf();
    return buffer.str();
}

[[nodiscard]] auto object_member(merovingian::canonicaljson::Object const& object, std::string_view key)
    -> merovingian::canonicaljson::Value const*
{
    for (auto const& member : object)
    {
        if (member.key == key)
        {
            return member.value.get();
        }
    }
    return nullptr;
}

// Navigate a dotted JSON path against a parsed Value. Returns nullptr when
// any segment is missing. Only object navigation is supported; that is
// sufficient for the v1.18 sync shape predicate set we ship.
[[nodiscard]] auto navigate(merovingian::canonicaljson::Value const& value, std::string_view path)
    -> merovingian::canonicaljson::Value const*
{
    auto cursor = &value;
    auto remainder = path;
    while (!remainder.empty())
    {
        auto const dot = remainder.find('.');
        auto const segment = remainder.substr(0U, dot);
        auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&cursor->storage());
        if (obj == nullptr)
        {
            return nullptr;
        }
        cursor = object_member(*obj, segment);
        if (cursor == nullptr)
        {
            return nullptr;
        }
        if (dot == std::string_view::npos)
        {
            break;
        }
        remainder = remainder.substr(dot + 1U);
    }
    return cursor;
}

[[nodiscard]] auto value_as_string(merovingian::canonicaljson::Value const& value) -> std::optional<std::string>
{
    auto const* text = std::get_if<std::string>(&value.storage());
    return text == nullptr ? std::nullopt : std::optional<std::string>{*text};
}

[[nodiscard]] auto value_as_integer(merovingian::canonicaljson::Value const& value) -> std::optional<std::int64_t>
{
    auto const* number = std::get_if<std::int64_t>(&value.storage());
    return number == nullptr ? std::nullopt : std::optional<std::int64_t>{*number};
}

[[nodiscard]] auto serialize(merovingian::canonicaljson::Value const& value) -> std::string
{
    auto const out = merovingian::canonicaljson::serialize_canonical(value);
    REQUIRE(out.error == merovingian::canonicaljson::CanonicalJsonError::none);
    return out.output;
}

} // namespace

SCENARIO("Sync conformance fixture (Complement-style) drives /sync against the v1.18 contract",
         "[sync][complement][integration]")
{
    GIVEN("the bundled sync_v1_18 fixture")
    {
        auto const fixture_path = std::filesystem::path{"tests/fixtures/complement/sync_v1_18.json"};
        auto fixture_text = std::string{};
        if (std::filesystem::exists(fixture_path))
        {
            fixture_text = read_file(fixture_path);
        }
        else
        {
            // Build run from a build directory: walk up to find the source tree.
            auto candidate = std::filesystem::current_path();
            for (auto i = 0; i < 5 && !candidate.empty(); ++i)
            {
                auto const probe = candidate / "tests" / "fixtures" / "complement" / "sync_v1_18.json";
                if (std::filesystem::exists(probe))
                {
                    fixture_text = read_file(probe);
                    break;
                }
                candidate = candidate.parent_path();
            }
        }
        REQUIRE_FALSE(fixture_text.empty());
        auto parsed = merovingian::canonicaljson::parse_lossless(fixture_text);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
        REQUIRE(root != nullptr);
        auto const* steps_value = object_member(*root, "steps");
        REQUIRE(steps_value != nullptr);
        auto const* steps = std::get_if<merovingian::canonicaljson::Array>(&steps_value->storage());
        REQUIRE(steps != nullptr);

        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto bindings = std::unordered_map<std::string, std::string>{};

        WHEN("each fixture step runs against the runtime")
        {
            for (auto const& step_value : *steps)
            {
                auto const* step = std::get_if<merovingian::canonicaljson::Object>(&step_value.storage());
                REQUIRE(step != nullptr);
                auto const* method = object_member(*step, "method");
                auto const* path = object_member(*step, "path");
                REQUIRE(method != nullptr);
                REQUIRE(path != nullptr);
                auto request = merovingian::homeserver::LocalHttpRequest{};
                request.method = value_as_string(*method).value_or("");
                request.target = value_as_string(*path).value_or("");
                if (auto const* body = object_member(*step, "body"); body != nullptr)
                {
                    request.body = serialize(*body);
                }
                if (auto const* auth = object_member(*step, "auth_from"); auth != nullptr)
                {
                    auto const key = value_as_string(*auth).value_or("");
                    request.access_token = bindings[key];
                }
                auto const response = merovingian::homeserver::handle_client_server_request(rt, request);

                if (auto const* expect_status = object_member(*step, "expect_status"); expect_status != nullptr)
                {
                    auto const expected = value_as_integer(*expect_status).value_or(-1);
                    REQUIRE(response.status == static_cast<std::uint16_t>(expected));
                }

                if (response.status == 200U && !response.body.empty())
                {
                    auto parsed_body = merovingian::canonicaljson::parse_lossless(response.body);
                    if (parsed_body.error == merovingian::canonicaljson::ParseError::none)
                    {
                        if (auto const* keys = object_member(*step, "expect_keys_present"); keys != nullptr)
                        {
                            auto const* array = std::get_if<merovingian::canonicaljson::Array>(&keys->storage());
                            REQUIRE(array != nullptr);
                            for (auto const& entry : *array)
                            {
                                auto const dotted = value_as_string(entry).value_or("");
                                INFO("Missing required key path: " << dotted);
                                REQUIRE(navigate(parsed_body.value, dotted) != nullptr);
                            }
                        }
                        if (auto const* save = object_member(*step, "save_string"); save != nullptr)
                        {
                            auto const* save_obj = std::get_if<merovingian::canonicaljson::Object>(&save->storage());
                            REQUIRE(save_obj != nullptr);
                            for (auto const& mapping : *save_obj)
                            {
                                auto const target_key = mapping.key;
                                auto const source_path = value_as_string(*mapping.value).value_or("");
                                auto const* sourced = navigate(parsed_body.value, source_path);
                                REQUIRE(sourced != nullptr);
                                bindings[target_key] = value_as_string(*sourced).value_or("");
                            }
                        }
                    }
                }
            }

            THEN("every fixture step satisfied its predicates")
            {
                REQUIRE(bindings.count("alice_token") == 1U);
                REQUIRE_FALSE(bindings["alice_token"].empty());
            }
        }
    }
}
