// SPDX-License-Identifier: GPL-3.0-or-later
// The remote device-list cache (G14, ADR-0560, ADR-0561): a remote user who shares a joined room with a local user
// has their device list fetched once with GET /user/devices, kept up to date by m.device_list_update EDUs in
// stream_id order, and served from the cache to /keys/query. An update that changes nothing is not reported in
// device_lists.changed again; a gap in the sequence makes the next query fetch the list afresh.
// Tags: [integration][federation][device_lists][g14].
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md, "Device Management": "When a server wishes to determine a remote
// user's device list for the first time, it should populate a local cache ... subsequent updates to the cache should
// be applied by consuming m.device_list_update EDUs." "If a server receives an EDU which refers to a prev_id it does
// not recognise, it must resynchronise its list". GET /user/devices: `stream_id` "is matched with the stream_id field
// in m.device_list_update EDUs in order to incrementally update the returned device_list".

#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "../support/TlsMockServer.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/PersistentMembership.hpp"
#include "merovingian/federation/EduDispositionStatus.hpp"
#include "merovingian/federation/InboundIngestion.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/TestOnlyForcedOutboundResolution.hpp"
#include "merovingian/homeserver/TlsServerContextResult.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/Tls.hpp"
#include "merovingian/net/TcpAcceptor.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace merovingian::tests;

namespace
{

constexpr auto remote_server = std::string_view{"remote.example.org"};
constexpr auto bob = std::string_view{"@bob:remote.example.org"};
constexpr auto shared_room = std::string_view{"!shared:example.org"};

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // The key query signs its federation requests with the runtime's signing secret.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto device_keys_json(std::string_view device_id) -> std::string
{
    auto const device = std::string{device_id};
    return std::string{R"({"user_id":")"} + std::string{bob} + R"(","device_id":")" + device +
           R"(","algorithms":["m.olm.v1.curve25519-aes-sha2"],"keys":{"curve25519:)" + device + R"(":"curvekey)" +
           device + R"(","ed25519:)" + device + R"(":"edkey)" + device + R"("}})";
}

// GET /user/devices/{userId} for bob at `stream_id`, with the named devices.
[[nodiscard]] auto user_devices_body(std::int64_t stream_id, std::vector<std::string_view> const& devices)
    -> std::string
{
    auto body = std::string{R"({"user_id":")"} + std::string{bob} + R"(","stream_id":)" + std::to_string(stream_id) +
                R"(,"devices":[)";
    auto first = true;
    for (auto const device : devices)
    {
        body += first ? "" : ",";
        first = false;
        body += std::string{R"({"device_id":")"} + std::string{device} + R"(","device_display_name":"Phone )" +
                std::string{device} + R"(","keys":)" + device_keys_json(device) + "}";
    }
    return body + "]}";
}

[[nodiscard]] auto update_edu(std::int64_t stream_id, std::int64_t prev_id, std::string_view device_id) -> std::string
{
    return std::string{R"({"user_id":")"} + std::string{bob} + R"(","device_id":")" + std::string{device_id} +
           R"(","stream_id":)" + std::to_string(stream_id) + R"(,"prev_id":[)" + std::to_string(prev_id) +
           R"(],"device_display_name":"Phone )" + std::string{device_id} + R"(","keys":)" +
           device_keys_json(device_id) + "}";
}

// A started server where alice (local) and bob (remote) are both joined to one room, and bob's server is a
// loopback TLS peer that answers the given requests in turn (a path substring selects each answer).
class CacheFixture final
{
public:
    explicit CacheFixture(std::vector<std::pair<std::string, std::string>> answers)
        : started{merovingian::homeserver::start_client_server(registration_enabled_config())}
        , m_answers{std::move(answers)}
    {
        REQUIRE(started.started);
        alice_token = register_alice();
        auto& store = started.runtime.homeserver.database.persistent_store;
        store.memberships.push_back({std::string{shared_room}, alice_id, "join", 0U});
        store.memberships.push_back({std::string{shared_room}, std::string{bob}, "join", 0U});

        REQUIRE(m_tls.ok());
        REQUIRE(m_acceptor.has_value());
        REQUIRE(m_acceptor->bind("127.0.0.1", 0U).ok);
        auto const port = m_acceptor->bound_port();
        REQUIRE(port > 0U);
        started.runtime.homeserver.test_forced_outbound_resolution[std::string{remote_server}] =
            merovingian::homeserver::TestOnlyForcedOutboundResolution{
                "localhost", port, {"127.0.0.1"}, m_certificate.certificate_pem};
        m_server = std::thread{[this]() {
            tls_mock::run_path_dispatch_tls_server(*m_acceptor, *m_tls.context, m_answers, &m_requests);
        }};
    }

    ~CacheFixture()
    {
        close_peer();
    }
    CacheFixture(CacheFixture const&) = delete;
    auto operator=(CacheFixture const&) -> CacheFixture& = delete;
    CacheFixture(CacheFixture&&) = delete;
    auto operator=(CacheFixture&&) -> CacheFixture& = delete;

    // Waits for the peer to have served every answer, then closes it: a later outbound call is refused at once.
    auto close_peer() -> std::vector<std::string> const&
    {
        if (m_server.joinable())
        {
            m_server.join();
        }
        m_acceptor.reset();
        return m_requests;
    }

    [[nodiscard]] auto query_bob() -> merovingian::canonicaljson::Object
    {
        auto const response = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/keys/query", alice_token,
                              std::string{R"({"device_keys":{")"} + std::string{bob} + R"(":[]}})"});
        REQUIRE(response.response.status == 200U);
        return parse_object(response.response.body);
    }

    auto deliver(std::string const& content) -> void
    {
        auto envelope = merovingian::federation::InboundEduEnvelope{};
        envelope.type = merovingian::federation::EduType::device_list_update;
        envelope.edu_type = "m.device_list_update";
        envelope.origin = std::string{remote_server};
        envelope.content_json = content;
        REQUIRE(started.runtime.homeserver.federation.edu_sink != nullptr);
        REQUIRE(started.runtime.homeserver.federation.edu_sink(envelope).status ==
                merovingian::federation::EduDispositionStatus::accepted);
    }

    // The stream position of alice's latest device-list row about bob, or nullopt when there is none.
    [[nodiscard]] auto bob_change_position() const -> std::optional<std::uint64_t>
    {
        auto latest = std::optional<std::uint64_t>{};
        for (auto const& change : started.runtime.homeserver.database.persistent_store.device_list_changes)
        {
            if (change.observer_user_id == alice_id && change.subject_user_id == bob &&
                (!latest.has_value() || change.stream_id > *latest))
            {
                latest = change.stream_id;
            }
        }
        return latest;
    }

    merovingian::homeserver::ClientServerStartResult started;
    std::string alice_id{};
    std::string alice_token{};

private:
    [[nodiscard]] auto register_alice() -> std::string
    {
        auto const registration = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(registration.response.status == 200U);
        auto const body = parse_object(registration.response.body);
        auto const* user_id = string_member(body, "user_id");
        auto const* token = string_member(body, "access_token");
        REQUIRE(user_id != nullptr);
        REQUIRE(token != nullptr);
        alice_id = *user_id;
        return *token;
    }

    tls_mock::TlsTestCertificate m_certificate{tls_mock::write_test_tls_certificate()};
    merovingian::homeserver::TlsServerContextResult m_tls{merovingian::homeserver::make_tls_server_context(
        m_certificate.certificate_file, m_certificate.private_key_file)};
    std::optional<merovingian::net::TcpAcceptor> m_acceptor{std::in_place};
    std::vector<std::pair<std::string, std::string>> m_answers;
    std::vector<std::string> m_requests{};
    std::thread m_server{};
};

[[nodiscard]] auto bob_devices(merovingian::canonicaljson::Object const& body)
    -> merovingian::canonicaljson::Object const*
{
    auto const* device_keys = object_member_as_object(body, "device_keys");
    return device_keys == nullptr ? nullptr : object_member_as_object(*device_keys, bob);
}

[[nodiscard]] auto names_remote_failure(merovingian::canonicaljson::Object const& body) -> bool
{
    auto const* failures = object_member_as_object(body, "failures");
    return failures != nullptr && object_member(*failures, remote_server) != nullptr;
}

[[nodiscard]] auto count_containing(std::vector<std::string> const& requests, std::string_view text) -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(requests, [text](std::string const& request) {
        return request.find(text) != std::string::npos;
    }));
}

constexpr auto user_devices_path = std::string_view{"/_matrix/federation/v1/user/devices/%40bob%3Aremote.example.org"};

} // namespace

SCENARIO("A remote user's device list is fetched once and later key queries are answered from the cache",
         "[integration][federation][device_lists][g14]")
{
    GIVEN("alice shares a room with bob, whose server answers one GET /user/devices")
    {
        REQUIRE(sodium_init() >= 0);
        auto fixture = CacheFixture{
            {
             {std::string{user_devices_path},
                 tls_mock::json_http_response("200 OK", user_devices_body(5, {"BDEV"}))},
             }
        };

        WHEN("alice queries bob's keys twice, and bob's server is gone before the second query")
        {
            auto const first = fixture.query_bob();
            auto const& requests = fixture.close_peer();
            auto const second = fixture.query_bob();

            THEN("the first query fetched bob's whole list with GET /user/devices")
            {
                REQUIRE(count_containing(requests, std::string{"GET "} + std::string{user_devices_path}) == 1U);
                auto const* devices = bob_devices(first);
                REQUIRE(devices != nullptr);
                REQUIRE(object_member(*devices, "BDEV") != nullptr);
            }

            AND_THEN("the second query is answered from the cache, with no failure for bob's server")
            {
                auto const* devices = bob_devices(second);
                REQUIRE(devices != nullptr);
                auto const* device = object_member_as_object(*devices, "BDEV");
                REQUIRE(device != nullptr);
                REQUIRE(string_member(*device, "device_id") != nullptr);
                REQUIRE(*string_member(*device, "device_id") == "BDEV");
                auto const* unsigned_data = object_member_as_object(*device, "unsigned");
                REQUIRE(unsigned_data != nullptr);
                REQUIRE(string_member(*unsigned_data, "device_display_name") != nullptr);
                REQUIRE(*string_member(*unsigned_data, "device_display_name") == "Phone BDEV");
                REQUIRE_FALSE(names_remote_failure(second));
            }
        }
    }
}

SCENARIO("A device-list update in sequence changes the cached list once, and its repeat is not reported again",
         "[integration][federation][device_lists][g14]")
{
    GIVEN("bob's list is cached at stream_id 5 and bob's server is then gone")
    {
        REQUIRE(sodium_init() >= 0);
        auto fixture = CacheFixture{
            {
             {std::string{user_devices_path},
                 tls_mock::json_http_response("200 OK", user_devices_body(5, {"BDEV"}))},
             }
        };
        std::ignore = fixture.query_bob();
        std::ignore = fixture.close_peer();

        WHEN("bob's server sends the update with stream_id 6 that follows 5, adding BNEW, and then sends it again")
        {
            fixture.deliver(update_edu(6, 5, "BNEW"));
            auto const after_first = fixture.bob_change_position();
            fixture.deliver(update_edu(6, 5, "BNEW"));
            auto const after_repeat = fixture.bob_change_position();
            auto const query = fixture.query_bob();

            THEN("the first update is reported to alice, the repeat writes nothing")
            {
                REQUIRE(after_first.has_value());
                REQUIRE(after_repeat == after_first);
            }

            AND_THEN("the next key query returns both devices from the cache")
            {
                auto const* devices = bob_devices(query);
                REQUIRE(devices != nullptr);
                REQUIRE(object_member(*devices, "BDEV") != nullptr);
                REQUIRE(object_member(*devices, "BNEW") != nullptr);
                REQUIRE_FALSE(names_remote_failure(query));
            }
        }
    }
}

SCENARIO("A device-list update after a gap is reported and makes the next key query fetch the list again",
         "[integration][federation][device_lists][g14]")
{
    GIVEN("bob's list is cached at stream_id 5, and bob's server will answer a second GET /user/devices")
    {
        REQUIRE(sodium_init() >= 0);
        auto fixture = CacheFixture{
            {
             {std::string{user_devices_path},
                 tls_mock::json_http_response("200 OK", user_devices_body(5, {"BDEV"}))},
             {std::string{user_devices_path},
                 tls_mock::json_http_response("200 OK", user_devices_body(9, {"BDEV", "BLOST", "BNEW"}))},
             }
        };
        std::ignore = fixture.query_bob();

        WHEN("an update arrives whose prev_id 8 this server never saw, and alice queries again")
        {
            fixture.deliver(update_edu(9, 8, "BNEW"));
            auto const reported = fixture.bob_change_position();
            auto const query = fixture.query_bob();
            auto const& requests = fixture.close_peer();

            THEN("the update is reported, and the list was fetched afresh with the device the gap hid")
            {
                REQUIRE(reported.has_value());
                REQUIRE(count_containing(requests, std::string{"GET "} + std::string{user_devices_path}) == 2U);
                auto const* devices = bob_devices(query);
                REQUIRE(devices != nullptr);
                REQUIRE(object_member(*devices, "BLOST") != nullptr);
                REQUIRE(object_member(*devices, "BNEW") != nullptr);
            }
        }
    }
}

SCENARIO("A remote user who no longer shares a room is not answered from the cache",
         "[integration][federation][device_lists][g14]")
{
    GIVEN("bob's list is cached, and then bob leaves the only room he shared with alice")
    {
        REQUIRE(sodium_init() >= 0);
        auto const keys_query_answer = std::string{R"({"device_keys":{")"} + std::string{bob} + R"(":{"BOTHER":)" +
                                       device_keys_json("BOTHER") + "}}}";
        auto fixture = CacheFixture{
            {
             {std::string{user_devices_path},
                 tls_mock::json_http_response("200 OK", user_devices_body(5, {"BDEV"}))},
             {"/_matrix/federation/v1/user/keys/query", tls_mock::json_http_response("200 OK", keys_query_answer)},
             }
        };
        std::ignore = fixture.query_bob();
        for (auto& membership : fixture.started.runtime.homeserver.database.persistent_store.memberships)
        {
            if (membership.user_id == bob)
            {
                membership.membership = "leave";
            }
        }

        WHEN("alice queries bob's keys again")
        {
            auto const query = fixture.query_bob();
            auto const& requests = fixture.close_peer();

            THEN("bob's server is asked with POST /user/keys/query and its answer, not the cached list, is returned")
            {
                REQUIRE(count_containing(requests, "POST /_matrix/federation/v1/user/keys/query") == 1U);
                auto const* devices = bob_devices(query);
                REQUIRE(devices != nullptr);
                REQUIRE(object_member(*devices, "BOTHER") != nullptr);
                REQUIRE(object_member(*devices, "BDEV") == nullptr);
            }
        }
    }
}
