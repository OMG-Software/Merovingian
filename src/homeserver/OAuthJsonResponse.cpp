// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/OAuthJsonResponse.hpp"

#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::homeserver
{
namespace
{

    // Written when serialisation itself failed, so it is fixed text rather than built.
    constexpr auto unserialisable_body =
        std::string_view{R"({"error":"server_error","error_description":"The server could not write its answer."})"};

    [[nodiscard]] auto with_oauth_headers(std::uint16_t status, std::string body) -> LocalHttpResponse
    {
        auto response = LocalHttpResponse{status, std::move(body), {}};
        response.headers.emplace_back("Content-Type", "application/json");
        response.headers.emplace_back("Cache-Control", "no-store");
        return response;
    }

} // namespace

auto oauth_json_response(std::uint16_t status, canonicaljson::Value const& body) -> LocalHttpResponse
{
    auto serialized = canonicaljson::serialize_canonical(body);
    if (serialized.error != canonicaljson::CanonicalJsonError::none)
    {
        return with_oauth_headers(500U, std::string{unserialisable_body});
    }
    return with_oauth_headers(status, std::move(serialized.output));
}

auto oauth_error_response(std::uint16_t status, oauth::OAuthRefusal const& refusal) -> LocalHttpResponse
{
    auto object = canonicaljson::Object{};
    object.push_back(canonicaljson::make_member("error", canonicaljson::Value{refusal.error_code}));
    object.push_back(canonicaljson::make_member("error_description", canonicaljson::Value{refusal.error.message()}));
    return oauth_json_response(status, canonicaljson::Value{std::move(object)});
}

} // namespace merovingian::homeserver
