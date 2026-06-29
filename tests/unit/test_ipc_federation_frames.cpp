// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/ipc/federation_ipc_frames.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

using merovingian::homeserver::LocalHttpRequest;
using merovingian::homeserver::LocalHttpResponse;
using merovingian::http::OutboundError;
using merovingian::http::OutboundHeader;
using merovingian::http::OutboundRequest;
using merovingian::http::OutboundResult;
using merovingian::ipc::deserialize_fed_request;
using merovingian::ipc::deserialize_fed_response;
using merovingian::ipc::deserialize_outbound_http_request;
using merovingian::ipc::deserialize_outbound_http_response;
using merovingian::ipc::ipc_json_get_str;
using merovingian::ipc::ipc_json_str;
using merovingian::ipc::serialize_fed_request;
using merovingian::ipc::serialize_fed_response;
using merovingian::ipc::serialize_outbound_http_request;
using merovingian::ipc::serialize_outbound_http_response;

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

// --- outbound_http_request frames ------------------------------------------------

SCENARIO("outbound_http_request round-trips a minimal GET request", "[ipc][federation][outbound]")
{
    GIVEN("a minimal GET request with a single pinned address and default timeouts")
    {
        auto original = OutboundRequest{};
        original.method = "GET";
        original.url = "https://matrix.example.com:8448/_matrix/federation/v1/query/profile"
                       "?user_id=%40alice%3Aexample.com";
        original.pinned_addresses.push_back("198.51.100.1:8448");

        WHEN("it is serialized and deserialized over IPC")
        {
            auto const rt = deserialize_outbound_http_request(serialize_outbound_http_request(original));

            THEN("method, URL and pinned address are preserved")
            {
                REQUIRE(rt.method == original.method);
                REQUIRE(rt.url == original.url);
                REQUIRE(rt.pinned_addresses.size() == 1U);
                REQUIRE(rt.pinned_addresses[0] == "198.51.100.1:8448");
                REQUIRE(rt.body.empty());
                REQUIRE(rt.headers.empty());
            }

            THEN("default timeout values survive the round-trip")
            {
                REQUIRE(rt.connect_timeout_seconds == 10U);
                REQUIRE(rt.total_timeout_seconds == 60U);
            }
        }
    }
}

SCENARIO("outbound_http_request round-trips a POST request with a JSON body", "[ipc][federation][outbound]")
{
    GIVEN("a POST send_join request carrying a signed event body")
    {
        auto original = OutboundRequest{};
        original.method = "POST";
        original.url = "https://remote.example:8448/_matrix/federation/v1/send_join/!room:remote.example/$ev";
        original.headers.push_back({"Content-Type", "application/json"});
        original.headers.push_back({"Authorization", "X-Matrix origin=\"local.example\",destination=\"remote.example\","
                                                     "key=\"ed25519:K001\",sig=\"base64sighere==\""});
        original.body =
            R"({"type":"m.room.member","state_key":"@alice:local.example","content":{"membership":"join"}})";
        original.pinned_addresses.push_back("203.0.113.10:8448");

        WHEN("it is serialized and deserialized over IPC")
        {
            auto const rt = deserialize_outbound_http_request(serialize_outbound_http_request(original));

            THEN("method, URL, body, and all headers are preserved")
            {
                REQUIRE(rt.method == "POST");
                REQUIRE(rt.url == original.url);
                REQUIRE(rt.body == original.body);
                REQUIRE(rt.headers.size() == 2U);
                REQUIRE(rt.headers[0].name == "Content-Type");
                REQUIRE(rt.headers[0].value == "application/json");
                REQUIRE(rt.headers[1].name == "Authorization");
                REQUIRE(rt.headers[1].value.find("X-Matrix") != std::string::npos);
            }
        }
    }
}

SCENARIO("outbound_http_request preserves multiple pinned addresses in order", "[ipc][federation][outbound]")
{
    GIVEN("a request with three distinct pinned IP addresses from server discovery")
    {
        auto original = OutboundRequest{};
        original.method = "GET";
        original.url = "https://matrix.example.com:8448/_matrix/federation/v1/key/server";
        original.pinned_addresses.push_back("198.51.100.1:8448");
        original.pinned_addresses.push_back("198.51.100.2:8448");
        original.pinned_addresses.push_back("198.51.100.3:8448");

        WHEN("it is serialized and deserialized over IPC")
        {
            auto const rt = deserialize_outbound_http_request(serialize_outbound_http_request(original));

            THEN("all three addresses are present and in the original order")
            {
                REQUIRE(rt.pinned_addresses.size() == 3U);
                REQUIRE(rt.pinned_addresses[0] == "198.51.100.1:8448");
                REQUIRE(rt.pinned_addresses[1] == "198.51.100.2:8448");
                REQUIRE(rt.pinned_addresses[2] == "198.51.100.3:8448");
            }
        }
    }
}

SCENARIO("outbound_http_request preserves non-default timeout and max body size configuration",
         "[ipc][federation][outbound]")
{
    GIVEN("a request with custom connect_timeout, total_timeout and max_response_body_bytes")
    {
        auto original = OutboundRequest{};
        original.method = "PUT";
        original.url = "https://matrix.example.com:8448/_matrix/federation/v1/send/txn-1";
        original.connect_timeout_seconds = 15U;
        original.total_timeout_seconds = 90U;
        original.max_response_body_bytes = 1024U * 1024U; // 1 MiB instead of default 16 MiB

        WHEN("it is serialized and deserialized over IPC")
        {
            auto const rt = deserialize_outbound_http_request(serialize_outbound_http_request(original));

            THEN("all three numeric configuration fields are preserved exactly")
            {
                REQUIRE(rt.connect_timeout_seconds == 15U);
                REQUIRE(rt.total_timeout_seconds == 90U);
                REQUIRE(rt.max_response_body_bytes == 1024U * 1024U);
            }
        }
    }
}

SCENARIO("outbound_http_request tolerates an empty body with no headers or pinned addresses",
         "[ipc][federation][outbound]")
{
    GIVEN("a bare request with only method and URL populated")
    {
        auto original = OutboundRequest{};
        original.method = "DELETE";
        original.url = "https://matrix.example.com:8448/_matrix/federation/v1/send/txn-empty";

        WHEN("it is serialized and deserialized over IPC")
        {
            auto const rt = deserialize_outbound_http_request(serialize_outbound_http_request(original));

            THEN("method and URL are preserved and all optional collections remain empty")
            {
                REQUIRE(rt.method == "DELETE");
                REQUIRE(rt.url == original.url);
                REQUIRE(rt.body.empty());
                REQUIRE(rt.headers.empty());
                REQUIRE(rt.pinned_addresses.empty());
            }
        }
    }
}

SCENARIO("outbound_http_request escapes JSON-hostile characters in the URL", "[ipc][federation][outbound]")
{
    GIVEN("a URL that contains ampersands, equals signs and percent-encoded sequences")
    {
        auto original = OutboundRequest{};
        original.method = "GET";
        // Query-parameter URL that would corrupt naive JSON string assembly
        original.url = "https://matrix.example.com:8448/_matrix/federation/v1/query/profile"
                       "?user_id=%40alice%3Aexample.com&field=name&field=avatar_url";
        original.pinned_addresses.push_back("198.51.100.1:8448");

        WHEN("it is serialized and deserialized over IPC")
        {
            auto const rt = deserialize_outbound_http_request(serialize_outbound_http_request(original));

            THEN("the URL is byte-identical to the original after the round-trip")
            {
                REQUIRE(rt.url == original.url);
            }
        }
    }
}

// --- outbound_http_response frames -----------------------------------------------

SCENARIO("outbound_http_response round-trips a successful 200 response", "[ipc][federation][outbound]")
{
    GIVEN("a successful 200 response carrying a JSON body")
    {
        auto original = OutboundResult{};
        original.ok = true;
        original.response.status = 200U;
        original.response.body = R"({"origin":"remote.example","pdus":[]})";
        original.error = OutboundError::none;

        WHEN("it is serialized and deserialized over IPC")
        {
            auto const rt = deserialize_outbound_http_response(serialize_outbound_http_response(original));

            THEN("ok is true, HTTP status is 200, body is preserved, and error code is none")
            {
                REQUIRE(rt.ok);
                REQUIRE(rt.response.status == 200U);
                REQUIRE(rt.response.body == original.response.body);
                REQUIRE(rt.error == OutboundError::none);
            }
        }
    }
}

SCENARIO("outbound_http_response round-trips a network failure with error detail", "[ipc][federation][outbound]")
{
    GIVEN("a failed result indicating the remote server was unreachable")
    {
        auto original = OutboundResult{};
        original.ok = false;
        original.response.status = 0U;
        original.error = OutboundError::connection_failed;
        original.error_detail = "connect() refused by 198.51.100.1:8448";

        WHEN("it is serialized and deserialized over IPC")
        {
            auto const rt = deserialize_outbound_http_response(serialize_outbound_http_response(original));

            THEN("ok is false, error_detail is preserved, and error code is network_error")
            {
                REQUIRE_FALSE(rt.ok);
                REQUIRE(rt.error_detail == original.error_detail);
                // The specific error variant is normalised to network_error on deserialization;
                // callers use ok + http_status as the primary signal.
                REQUIRE(rt.error == OutboundError::network_error);
            }
        }
    }
}

SCENARIO("outbound_http_response round-trips a non-2xx response that was received without transport error",
         "[ipc][federation][outbound]")
{
    GIVEN("a 403 Forbidden response where the HTTP exchange itself succeeded")
    {
        auto original = OutboundResult{};
        original.ok = true;
        original.response.status = 403U;
        original.response.body = R"({"errcode":"M_FORBIDDEN","error":"You are not allowed to join this room."})";
        original.error = OutboundError::none;

        WHEN("it is serialized and deserialized over IPC")
        {
            auto const rt = deserialize_outbound_http_response(serialize_outbound_http_response(original));

            THEN("ok is true, status is 403, body is preserved, and error code is none")
            {
                REQUIRE(rt.ok);
                REQUIRE(rt.response.status == 403U);
                REQUIRE(rt.response.body == original.response.body);
                REQUIRE(rt.error == OutboundError::none);
            }
        }
    }
}

SCENARIO("outbound_http_response normalises any failure error code to network_error after deserialization",
         "[ipc][federation][outbound]")
{
    GIVEN("failed results with different specific error codes")
    {
        auto timeout_result = OutboundResult{};
        timeout_result.ok = false;
        timeout_result.error = OutboundError::timeout;
        timeout_result.error_detail = "request timed out after 60s";

        auto tls_result = OutboundResult{};
        tls_result.ok = false;
        tls_result.error = OutboundError::tls_verification_failed;
        tls_result.error_detail = "certificate verification failed";

        WHEN("a timeout result is serialized and deserialized")
        {
            auto const rt = deserialize_outbound_http_response(serialize_outbound_http_response(timeout_result));

            THEN("the error code is network_error and error_detail is preserved")
            {
                REQUIRE_FALSE(rt.ok);
                REQUIRE(rt.error == OutboundError::network_error);
                REQUIRE(rt.error_detail == timeout_result.error_detail);
            }
        }

        WHEN("a TLS failure result is serialized and deserialized")
        {
            auto const rt = deserialize_outbound_http_response(serialize_outbound_http_response(tls_result));

            THEN("the error code is also normalised to network_error")
            {
                REQUIRE_FALSE(rt.ok);
                REQUIRE(rt.error == OutboundError::network_error);
                REQUIRE(rt.error_detail == tls_result.error_detail);
            }
        }
    }
}