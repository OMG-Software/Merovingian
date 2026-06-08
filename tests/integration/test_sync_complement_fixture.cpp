// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |       MATRIX /SYNC COMPLEMENT CONFORMANCE INTEGRATION TESTS             |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.18, Sec. 9.4 /sync                      |
// |  URL:  https://spec.matrix.org/v1.18/client-server-api/                |
// |        #get_matrixclientv3sync                                          |
// |                                                                         |
// |  Complement: https://github.com/matrix-org/complement                   |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST or SHOULD from the Matrix    |
// |  specification. If a test fails:                                         |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |      spec itself has changed and citing the updated section.             |
// |                                                                         |
// |  The spec section is cited above each SCENARIO. Cross-check it before   |
// |  concluding that a failing assertion is wrong.                           |
// |                                                                         |
// |  Sync response structure that every fixture step validates:             |
// |    next_batch                   - string token, MUST be present         |
// |    rooms.join                   - map of room_id -> joined room data     |
// |    rooms.join[id].timeline.events     - array of timeline events        |
// |    rooms.join[id].state.events        - array of state events           |
// |    rooms.join[id].timeline.limited    - bool, true if truncated         |
// |    rooms.join[id].timeline.prev_batch - backfill token (when limited)   |
// +-------------------------------------------------------------------------+

#include "../federation_signing_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <optional>
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
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
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

// Navigate a dotted JSON path against a parsed Value. Matrix response keys
// often contain literal dots (for example `m.change_password`), so each level
// first tries the remaining text as an exact key before splitting on dots.
[[nodiscard]] auto navigate(merovingian::canonicaljson::Value const& value, std::string_view path)
    -> merovingian::canonicaljson::Value const*
{
    auto cursor = &value;
    auto remainder = path;
    while (!remainder.empty())
    {
        auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&cursor->storage());
        if (obj == nullptr)
        {
            return nullptr;
        }
        if (auto const* exact = object_member(*obj, remainder); exact != nullptr)
        {
            return exact;
        }
        auto const dot = remainder.find('.');
        if (dot == std::string_view::npos)
        {
            return nullptr;
        }
        auto const segment = remainder.substr(0U, dot);
        cursor = object_member(*obj, segment);
        if (cursor == nullptr)
        {
            return nullptr;
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

auto replace_all(std::string& value, std::string_view needle, std::string_view replacement) -> void
{
    auto position = value.find(needle);
    while (position != std::string::npos)
    {
        value.replace(position, needle.size(), replacement);
        position = value.find(needle, position + replacement.size());
    }
}

[[nodiscard]] auto interpolate(std::string value, std::unordered_map<std::string, std::string> const& bindings)
    -> std::string
{
    for (auto const& [name, replacement] : bindings)
    {
        replace_all(value, "{{" + name + "}}", replacement);
    }
    return value;
}

[[nodiscard]] auto media_id_from_mxc(std::string_view content_uri) -> std::string
{
    auto constexpr prefix = std::string_view{"mxc://"};
    if (!content_uri.starts_with(prefix))
    {
        return {};
    }
    auto const without_scheme = content_uri.substr(prefix.size());
    auto const separator = without_scheme.find('/');
    if (separator == std::string_view::npos || separator + 1U >= without_scheme.size())
    {
        return {};
    }
    return std::string{without_scheme.substr(separator + 1U)};
}

[[nodiscard]] auto read_fixture(std::string_view filename) -> std::string
{
    auto const relative = std::filesystem::path{"tests/fixtures/complement"} / std::string{filename};
    if (std::filesystem::exists(relative))
    {
        return read_file(relative);
    }
    auto candidate = std::filesystem::current_path();
    for (auto i = 0; i < 5 && !candidate.empty(); ++i)
    {
        auto const probe = candidate / "tests" / "fixtures" / "complement" / std::string{filename};
        if (std::filesystem::exists(probe))
        {
            return read_file(probe);
        }
        candidate = candidate.parent_path();
    }
    return {};
}

auto run_complement_fixture(std::string_view filename, merovingian::homeserver::ClientServerRuntime& rt,
                            std::unordered_map<std::string, std::string>& bindings) -> void
{
    auto const fixture_text = read_fixture(filename);
    // Spec MUST: fixture file MUST exist and be non-empty; missing fixtures mean incomplete test coverage.
    // Do NOT remove/change - an empty fixture silently skips all spec assertions in the file.
    REQUIRE_FALSE(fixture_text.empty());
    auto parsed = merovingian::canonicaljson::parse_lossless(fixture_text);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
    REQUIRE(root != nullptr);
    auto const* steps_value = object_member(*root, "steps");
    REQUIRE(steps_value != nullptr);
    auto const* steps = std::get_if<merovingian::canonicaljson::Array>(&steps_value->storage());
    REQUIRE(steps != nullptr);

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
        request.target = interpolate(value_as_string(*path).value_or(""), bindings);
        if (auto const* body = object_member(*step, "body"); body != nullptr)
        {
            request.body = interpolate(serialize(*body), bindings);
        }
        if (auto const* raw_body = object_member(*step, "raw_body"); raw_body != nullptr)
        {
            request.body = interpolate(value_as_string(*raw_body).value_or(""), bindings);
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
            INFO("Fixture " << filename << " failed at " << request.method << ' ' << request.target << " body "
                            << response.response.body);
            // Spec MUST: each fixture step's HTTP status MUST match the Matrix spec contract for that endpoint.
            // Do NOT remove/change - weakening this hides non-conformant HTTP status codes.
            REQUIRE(response.response.status == static_cast<std::uint16_t>(expected));
        }

        auto parsed_body = merovingian::canonicaljson::parse_lossless(response.response.body);
        if (parsed_body.error == merovingian::canonicaljson::ParseError::none)
        {
            if (auto const* keys = object_member(*step, "expect_keys_present"); keys != nullptr)
            {
                auto const* array = std::get_if<merovingian::canonicaljson::Array>(&keys->storage());
                REQUIRE(array != nullptr);
                for (auto const& entry : *array)
                {
                    auto const dotted = value_as_string(entry).value_or("");
                    auto const* root_object =
                        std::get_if<merovingian::canonicaljson::Object>(&parsed_body.value.storage());
                    auto const has_dotted_root_key =
                        root_object != nullptr && object_member(*root_object, dotted) != nullptr;
                    INFO("Missing required key path: " << dotted);
                    // Spec MUST: all keys listed in expect_keys_present MUST appear in the response body.
                    // Do NOT remove/change - a missing key means the response violates the Matrix spec schema.
                    REQUIRE((navigate(parsed_body.value, dotted) != nullptr || has_dotted_root_key));
                }
            }
            if (auto const* keys = object_member(*step, "expect_keys_absent"); keys != nullptr)
            {
                auto const* array = std::get_if<merovingian::canonicaljson::Array>(&keys->storage());
                REQUIRE(array != nullptr);
                for (auto const& entry : *array)
                {
                    auto const dotted = value_as_string(entry).value_or("");
                    auto const* root_object =
                        std::get_if<merovingian::canonicaljson::Object>(&parsed_body.value.storage());
                    auto const has_dotted_root_key =
                        root_object != nullptr && object_member(*root_object, dotted) != nullptr;
                    INFO("Unexpected key path: " << dotted);
                    // Spec MUST: all keys listed in expect_keys_absent MUST NOT appear in the response body.
                    // Do NOT remove/change - an unexpected key leaks internal state or violates the spec schema.
                    REQUIRE((navigate(parsed_body.value, dotted) == nullptr && !has_dotted_root_key));
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
                    // Spec MUST: saved binding paths MUST resolve; a null here means a required field is absent.
                    // Do NOT remove/change - a null sourced value would silently propagate empty tokens into
                    // subsequent fixture steps, causing cascading failures with misleading error messages.
                    REQUIRE(sourced != nullptr);
                    bindings[target_key] = value_as_string(*sourced).value_or("");
                }
            }
            if (auto const* save = object_member(*step, "save_mxc_media_id"); save != nullptr)
            {
                auto const* save_obj = std::get_if<merovingian::canonicaljson::Object>(&save->storage());
                REQUIRE(save_obj != nullptr);
                for (auto const& mapping : *save_obj)
                {
                    auto const target_key = mapping.key;
                    auto const source_path = value_as_string(*mapping.value).value_or("");
                    auto const* sourced = navigate(parsed_body.value, source_path);
                    REQUIRE(sourced != nullptr);
                    auto const media_id = media_id_from_mxc(value_as_string(*sourced).value_or(""));
                    // Spec MUST: content_uri MUST follow the mxc:// scheme defined in the Matrix spec.
                    // Do NOT remove/change - an empty media_id means the server returned a malformed URI.
                    REQUIRE_FALSE(media_id.empty());
                    bindings[target_key] = media_id;
                }
            }
        }
    }
}

} // namespace

// --- Sync Complement fixture - v1.18 /sync contract --------------------------
// Spec: Matrix Client-Server API v1.18, Sec. 9.4 /sync
// URL:  https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3sync
// Complement: https://github.com/matrix-org/complement
//
// Drives the bundled sync_v1_18 Complement-style fixture against the runtime.
// Each step validates that the /sync response structure matches the Matrix spec
// exactly: next_batch presence, rooms.join structure, timeline.events array,
// state.events array, timeline.limited bool, and prev_batch token when limited.
SCENARIO("Sync conformance fixture (Complement-style) drives /sync against the v1.18 contract",
         "[sync][complement][integration]")
{
    GIVEN("the bundled sync_v1_18 fixture")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto bindings = std::unordered_map<std::string, std::string>{};

        WHEN("each fixture step runs against the runtime")
        {
            run_complement_fixture("sync_v1_18.json", rt, bindings);

            THEN("every fixture step satisfied its predicates")
            {
                // Spec MUST: alice_token MUST be saved by the fixture, proving auth and /sync succeeded end-to-end.
                // Do NOT remove/change - an absent or empty token means registration, login, or /sync is broken.
                REQUIRE(bindings.count("alice_token") == 1U);
                REQUIRE_FALSE(bindings["alice_token"].empty());
            }
        }
    }
}

// --- Client-server v1.18 conformance - full endpoint family coverage ----------
// Spec: Matrix Client-Server API v1.18, Sec. 9.4 /sync and related endpoint families
// URL:  https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3sync
// Complement: https://github.com/matrix-org/complement
//
// Drives the bundled client_server_v1_18 fixture which covers auth, devices,
// rooms, sync, media, reports, and E2EE key endpoints in a single fixture run.
// Validates that all required response bindings (auth tokens, room IDs, event
// IDs) are populated, proving end-to-end conformance across endpoint families.
SCENARIO("Client-server v1.18 conformance fixture covers beta endpoint families",
         "[client-server][complement][integration]")
{
    GIVEN("the bundled client_server_v1_18 fixture")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto bindings = std::unordered_map<std::string, std::string>{};

        WHEN("each endpoint family step runs against the runtime")
        {
            // Pre-compute real Ed25519 values for the keys/upload fixture step.
            // The fixture JSON uses {{placeholder}} tokens that are interpolated
            // by run_complement_fixture; the signatures must match the ed25519 key
            // we inject here so the server's real crypto_sign_verify_detached passes.
            auto const fix_kp =
                merovingian::federation::test::keypair_from_seed("fixture-device-seed");
            bindings["fixture_ed25519_key"] = merovingian::federation::test::pubkey_b64(fix_kp);
            bindings["fixture_otk_sig"] = merovingian::federation::test::sign_payload_b64(
                R"({"key":"one-time-key"})", fix_kp.secret_key);
            bindings["fixture_fallback_sig"] = merovingian::federation::test::sign_payload_b64(
                R"({"fallback":true,"key":"fallback-key"})", fix_kp.secret_key);

            run_complement_fixture("client_server_v1_18.json", rt, bindings);

            THEN("auth, devices, rooms, sync, media, reports, and E2EE keys have fixture coverage")
            {
                // Spec MUST: refreshed_token MUST be saved, proving token refresh works per Sec. 5.7.2.
                // Do NOT remove/change - absence means the token refresh endpoint is broken.
                REQUIRE(bindings.count("refreshed_token") == 1U);
                // Spec MUST: room_id MUST be saved, proving createRoom and /sync room delivery work.
                // Do NOT remove/change - absence means room creation or sync room reporting is broken.
                REQUIRE(bindings.count("room_id") == 1U);
                // Spec MUST: event_id MUST be saved, proving event send and /sync timeline delivery work.
                // Do NOT remove/change - absence means event sending or timeline reporting is broken.
                REQUIRE(bindings.count("event_id") == 1U);
            }
        }
    }
}
