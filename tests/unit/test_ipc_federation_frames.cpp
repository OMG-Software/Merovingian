// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/ipc/federation_ipc_frames.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

using merovingian::homeserver::LocalHttpRequest;
using merovingian::homeserver::LocalHttpResponse;
using merovingian::ipc::deserialize_fed_request;
using merovingian::ipc::deserialize_fed_response;
using merovingian::ipc::ipc_json_get_str;
using merovingian::ipc::ipc_json_str;
using merovingian::ipc::serialize_fed_request;
using merovingian::ipc::serialize_fed_response;

} // namespace

SCENARIO("IPC JSON escaping preserves common special characters", "[ipc][federation][json]")
{
    GIVEN("a string containing JSON metacharacters")
    {
        auto const raw = std::string{"line1\nline2\tquote\"backslash\\"};

        WHEN("it is escaped for an IPC frame")
        {
            auto const escaped = ipc_json_str(raw);

            THEN("control characters become escape sequences and quotes/backslashes are escaped")
            {
                REQUIRE(escaped.find("\\n") != std::string::npos);
                REQUIRE(escaped.find("\\t") != std::string::npos);
                REQUIRE(escaped.find("\\\"") != std::string::npos);
                REQUIRE(escaped.find("\\\\") != std::string::npos);
            }
        }
    }
}

SCENARIO("IPC JSON string extraction round-trips simple escaped values", "[ipc][federation][json]")
{
    GIVEN("a JSON object with an escaped string value")
    {
        auto const json = std::string{R"({"room_id":"!room:example.com","type":"m.room.message"})"};

        WHEN("the room_id value is extracted")
        {
            THEN("the original unescaped string is returned")
            {
                REQUIRE(ipc_json_get_str(json, "room_id") == "!room:example.com");
            }
        }

        WHEN("a missing key is requested")
        {
            THEN("an empty string is returned")
            {
                REQUIRE(ipc_json_get_str(json, "missing").empty());
            }
        }
    }
}

SCENARIO("fed_request frame round-trips a LocalHttpRequest", "[ipc][federation][frame]")
{
    GIVEN("a typical inbound federation request")
    {
        auto original = LocalHttpRequest{};
        original.method = "PUT";
        original.target = "/_matrix/federation/v1/send/txn-1";
        original.body = R"({"origin":"remote.example","pdus":[]})";
        original.remote_addr = "203.0.113.1";

        WHEN("it is serialized and deserialized")
        {
            auto const serialized = serialize_fed_request(original);
            auto const roundtripped = deserialize_fed_request(serialized);

            THEN("method, target, body and remote address are preserved")
            {
                REQUIRE(roundtripped.method == original.method);
                REQUIRE(roundtripped.target == original.target);
                REQUIRE(roundtripped.body == original.body);
                REQUIRE(roundtripped.remote_addr == original.remote_addr);
            }
        }
    }
}

SCENARIO("fed_request frame escapes body content that contains JSON delimiters", "[ipc][federation][frame]")
{
    GIVEN("a federation request whose body contains quotes and backslashes")
    {
        auto original = LocalHttpRequest{};
        original.method = "PUT";
        original.target = "/_matrix/federation/v1/invite/!room:example.com/$ev";
        original.body = std::string{R"({"key":"value\"with\"quotes"})"};
        original.remote_addr = "203.0.113.1";

        WHEN("it is serialized and deserialized")
        {
            auto const roundtripped = deserialize_fed_request(serialize_fed_request(original));

            THEN("the body is identical to the original")
            {
                REQUIRE(roundtripped.body == original.body);
            }
        }
    }
}

SCENARIO("fed_request frame preserves headers", "[ipc][federation][frame]")
{
    GIVEN("a federation request with custom headers")
    {
        auto original = LocalHttpRequest{};
        original.method = "GET";
        original.target = "/_matrix/federation/v1/state/!room:example.com";
        original.headers.push_back({"Authorization", "X-Matrix origin=...,destination=..."});
        original.headers.push_back({"Content-Type", "application/json"});

        WHEN("it is serialized and deserialized")
        {
            auto const roundtripped = deserialize_fed_request(serialize_fed_request(original));

            THEN("all headers are preserved in order")
            {
                REQUIRE(roundtripped.headers.size() == 2U);
                REQUIRE(roundtripped.headers[0].name == "Authorization");
                REQUIRE(roundtripped.headers[0].value == "X-Matrix origin=...,destination=...");
                REQUIRE(roundtripped.headers[1].name == "Content-Type");
                REQUIRE(roundtripped.headers[1].value == "application/json");
            }
        }
    }
}

SCENARIO("fed_response frame round-trips a LocalHttpResponse", "[ipc][federation][frame]")
{
    GIVEN("a typical federation response")
    {
        auto original = LocalHttpResponse{};
        original.status = 200U;
        original.body = R"({"origin":"local.example","pdus":[]})";
        original.headers.push_back({"Content-Type", "application/json"});

        WHEN("it is serialized and deserialized")
        {
            auto const roundtripped = deserialize_fed_response(serialize_fed_response(original));

            THEN("status, body and headers are preserved")
            {
                REQUIRE(roundtripped.status == original.status);
                REQUIRE(roundtripped.body == original.body);
                REQUIRE(roundtripped.headers.size() == 1U);
                REQUIRE(roundtripped.headers[0].first == "Content-Type");
                REQUIRE(roundtripped.headers[0].second == "application/json");
            }
        }
    }
}

SCENARIO("fed_response frame handles non-200 statuses and special body characters", "[ipc][federation][frame]")
{
    GIVEN("a 404 response whose body contains JSON special characters")
    {
        auto original = LocalHttpResponse{};
        original.status = 404U;
        original.body = std::string{R"({"errcode":"M_NOT_FOUND","error":"can't \"find\" it"})"};
        original.headers.push_back({"Server", "merovingian"});

        WHEN("it is serialized and deserialized")
        {
            auto const roundtripped = deserialize_fed_response(serialize_fed_response(original));

            THEN("status, body and headers are preserved exactly")
            {
                REQUIRE(roundtripped.status == 404U);
                REQUIRE(roundtripped.body == original.body);
                REQUIRE(roundtripped.headers[0].first == "Server");
                REQUIRE(roundtripped.headers[0].second == "merovingian");
            }
        }
    }
}

SCENARIO("IPC JSON string extraction handles every escape sequence", "[ipc][federation][json]")
{
    GIVEN("a JSON object containing escaped control characters")
    {
        auto const json = std::string{R"({"value":"bell\bform\fnewline\nreturn\rtab\tquote\"slash\\"})"};

        WHEN("the value is extracted")
        {
            THEN("every escape is decoded back to the original byte")
            {
                auto const expected = std::string{"bell\bform\fnewline\nreturn\rtab\tquote\"slash\\"};
                REQUIRE(ipc_json_get_str(json, "value") == expected);
            }
        }

        AND_WHEN("a key is missing")
        {
            THEN("an empty string is returned")
            {
                REQUIRE(ipc_json_get_str(json, "missing").empty());
            }
        }
    }
}

SCENARIO("IPC JSON escaping covers control characters", "[ipc][federation][json]")
{
    GIVEN("a string containing a null byte and common escapes")
    {
        auto raw = std::string{"newline\nreturn\rtab\t"};
        raw += '\0';
        raw += "end";

        WHEN("it is escaped for an IPC frame")
        {
            auto const escaped = ipc_json_str(raw);

            THEN("control characters are represented as JSON unicode escapes")
            {
                REQUIRE(escaped.find("\\n") != std::string::npos);
                REQUIRE(escaped.find("\\r") != std::string::npos);
                REQUIRE(escaped.find("\\t") != std::string::npos);
                REQUIRE(escaped.find("\\u0000") != std::string::npos);
            }
        }
    }
}

SCENARIO("fed_response frame defaults invalid or missing status to 500", "[ipc][federation][frame]")
{
    GIVEN("a response JSON with status 0")
    {
        auto const json = R"({"type":"fed_response","status":0,"body":"{}"})";

        WHEN("it is deserialized")
        {
            auto const response = deserialize_fed_response(json);

            THEN("the status is normalized to 500")
            {
                REQUIRE(response.status == 500U);
                REQUIRE(response.body == "{}");
            }
        }
    }

    GIVEN("a response JSON with a status above the HTTP range")
    {
        auto const json = R"({"type":"fed_response","status":1234,"body":"error"})";

        WHEN("it is deserialized")
        {
            auto const response = deserialize_fed_response(json);

            THEN("the status is normalized to 500")
            {
                REQUIRE(response.status == 500U);
                REQUIRE(response.body == "error");
            }
        }
    }

    GIVEN("a response JSON with whitespace after the status key")
    {
        auto const json = R"({"type":"fed_response","status": 418,"body":"teapot"})";

        WHEN("it is deserialized")
        {
            auto const response = deserialize_fed_response(json);

            THEN("the whitespace is tolerated and the status is preserved")
            {
                REQUIRE(response.status == 418U);
                REQUIRE(response.body == "teapot");
            }
        }
    }
}

SCENARIO("fed_request frame preserves the X-Matrix access_token across IPC", "[ipc][federation][frame][security]")
{
    GIVEN("an inbound federation request with an X-Matrix Authorization header")
    {
        auto original = LocalHttpRequest{};
        original.method = "PUT";
        original.target = "/_matrix/federation/v1/send/txn123";
        original.remote_addr = "203.0.113.5";
        // access_token carries the full Authorization header value; handle_federation_http_request()
        // reads request.access_token for X-Matrix parsing rather than re-scanning raw headers.
        original.access_token = "X-Matrix origin=\"remote.example\",destination=\"local.example\","
                                "key=\"ed25519:abc\",sig=\"base64sighere\"";
        original.body = R"({"pdus":[]})";

        WHEN("the request is serialized and deserialized for IPC")
        {
            auto const roundtripped = deserialize_fed_request(serialize_fed_request(original));

            THEN("access_token is preserved so X-Matrix auth succeeds in the worker")
            {
                REQUIRE(roundtripped.access_token == original.access_token);
            }

            THEN("all other fields are also preserved")
            {
                REQUIRE(roundtripped.method == original.method);
                REQUIRE(roundtripped.target == original.target);
                REQUIRE(roundtripped.remote_addr == original.remote_addr);
                REQUIRE(roundtripped.body == original.body);
            }
        }
    }

    GIVEN("an inbound federation request with no Authorization header")
    {
        auto original = LocalHttpRequest{};
        original.method = "GET";
        original.target = "/_matrix/federation/v1/key/server";
        original.remote_addr = "203.0.113.5";

        WHEN("the request is serialized and deserialized for IPC")
        {
            auto const roundtripped = deserialize_fed_request(serialize_fed_request(original));

            THEN("access_token remains empty")
            {
                REQUIRE(roundtripped.access_token.empty());
            }
        }
    }
}

SCENARIO("fed_request frame tolerates empty bodies and skipped headers", "[ipc][federation][frame]")
{
    GIVEN("a request with an empty body and no headers")
    {
        auto original = LocalHttpRequest{};
        original.method = "GET";
        original.target = "/_matrix/federation/v1/key/server";
        original.remote_addr = "203.0.113.1";

        WHEN("it is serialized and deserialized")
        {
            auto const roundtripped = deserialize_fed_request(serialize_fed_request(original));

            THEN("method, target and remote address are preserved and the body is empty")
            {
                REQUIRE(roundtripped.method == original.method);
                REQUIRE(roundtripped.target == original.target);
                REQUIRE(roundtripped.remote_addr == original.remote_addr);
                REQUIRE(roundtripped.body.empty());
                REQUIRE(roundtripped.headers.empty());
            }
        }
    }

    GIVEN("a request whose headers include an empty name")
    {
        auto original = LocalHttpRequest{};
        original.method = "GET";
        original.target = "/_matrix/federation/v1/query/profile";
        original.headers.push_back({"", "ignored"});
        original.headers.push_back({"X-Valid", "kept"});

        WHEN("it is serialized and deserialized")
        {
            auto const roundtripped = deserialize_fed_request(serialize_fed_request(original));

            THEN("the empty-name header is dropped and the valid header is kept")
            {
                REQUIRE(roundtripped.headers.size() == 1U);
                REQUIRE(roundtripped.headers[0].name == "X-Valid");
                REQUIRE(roundtripped.headers[0].value == "kept");
            }
        }
    }
}