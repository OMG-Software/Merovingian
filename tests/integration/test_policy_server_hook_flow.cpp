// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// F-42 (ADR-0361): the external trust-and-safety policy server hook. OutboundClient::perform resolves nothing
// and refuses a request without pinned addresses, and the hook never set any, so with the real transport it
// failed before opening a socket on every call: fail-closed deployments refused every guarded workflow and
// allow_without_result deployments never asked the server. The hook now resolves the operator-configured host
// itself (the operator chose the destination, as for an appservice, so the SSRF deny-list does not apply),
// inside the lock-release scope, and its calls are admitted through a bounded budget because each holds a
// request thread for the round trip.
//
// Docs: docs/user-manual.md "security.trust_safety.policy_server_*"; docs/trust-safety.md.
// The room-ID scenario at the end is the interaction recorded with F-82 (rooms.createroom-pre-v12-room-id-
// from-localroom-vector-size): the longer the hook's window, the likelier a concurrent creation takes the
// room ID a pre-v12 createRoom computed before the hook.
// Tags: [policy_server_hook].

#include "../support/ScopedThreadJoin.hpp"
#include "../support/TlsTestCertificate.hpp"
#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "../support/TlsMockServer.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/federation/ResolvedAddressSet.hpp"
#include "merovingian/federation/ServerDiscoveryNetwork.hpp"
#include "merovingian/federation/SrvRecord.hpp"
#include "merovingian/federation/WellKnownServerResult.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/TlsServerContextResult.hpp"
#include "merovingian/homeserver/Tls.hpp"
#include "merovingian/net/TcpAcceptor.hpp"
#include "merovingian/trust_safety/PolicyAction.hpp"
#include "merovingian/trust_safety/PolicyServerHook.hpp"
#include "merovingian/trust_safety/PolicySurface.hpp"
#include "merovingian/trust_safety/PolicyEngine.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian;
namespace tls_mock = merovingian::tests::tls_mock;

// Resolves every host to loopback, as an operator's DNS would resolve the policy server's name to its address.
// Records what it was asked, so a test can see that the hook resolved the configured host.
class LoopbackNetwork final : public federation::ServerDiscoveryNetwork
{
public:
    [[nodiscard]] auto fetch_well_known(std::string_view, std::uint32_t) -> federation::WellKnownServerResult override
    {
        return {};
    }
    [[nodiscard]] auto lookup_srv(std::string_view) -> std::vector<federation::SrvRecord> override
    {
        return {};
    }
    [[nodiscard]] auto lookup_addresses(std::string_view host, std::uint16_t port)
        -> federation::ResolvedAddressSet override
    {
        asked_host = std::string{host};
        asked_port = port;
        return {true, {"127.0.0.1"}, {}};
    }

    std::string asked_host{};
    std::uint16_t asked_port{0U};
};

// Resolves nothing.
class UnresolvableNetwork final : public federation::ServerDiscoveryNetwork
{
public:
    [[nodiscard]] auto fetch_well_known(std::string_view, std::uint32_t) -> federation::WellKnownServerResult override
    {
        return {};
    }
    [[nodiscard]] auto lookup_srv(std::string_view) -> std::vector<federation::SrvRecord> override
    {
        return {};
    }
    [[nodiscard]] auto lookup_addresses(std::string_view, std::uint16_t) -> federation::ResolvedAddressSet override
    {
        return {false, {}, "no such host"};
    }
};

[[nodiscard]] auto hook_config(std::string url, bool allow_without_result) -> config::Config
{
    auto security = config::SecurityConfig{};
    security.secrets.master_key_file = tests::shared_master_key_file();
    tests::enable_token_registration(security);
    security.trust_safety.enabled = true;
    security.trust_safety.policy_server_url = std::move(url);
    security.trust_safety.policy_server_allow_without_result = allow_without_result;
    return {config::ServerConfig{},           config::ListenersConfig{}, tests::in_memory_database_config(), security,
            config::ClientRateLimitsConfig{}, config::LogModulesConfig{}};
}

// A TLS mock of the policy server on loopback, and a runtime configured to use it through a resolver that maps its
// name to loopback and trusts its certificate.
struct MockPolicyServer final
{
    tls_mock::TlsTestCertificate certificate{tls_mock::write_test_tls_certificate()};
    homeserver::TlsServerContextResult tls_context{
        homeserver::make_tls_server_context(certificate.certificate_file, certificate.private_key_file)};
    net::TcpAcceptor acceptor{};
    std::uint16_t port{0U};

    MockPolicyServer()
    {
        REQUIRE(tls_context.ok());
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        port = acceptor.bound_port();
        REQUIRE(port > 0U);
    }

    [[nodiscard]] auto url() const -> std::string
    {
        return "https://localhost:" + std::to_string(port) + "/check";
    }
};

void point_runtime_at(homeserver::HomeserverRuntime& runtime, MockPolicyServer const& mock)
{
    runtime.discovery_network = std::make_unique<LoopbackNetwork>();
    runtime.test_policy_server_trusted_ca_pem = mock.certificate.certificate_pem;
}

// Asks the hook about a federation origin; the mock answers once with `http_response`.
struct HookAnswer final
{
    trust_safety::PolicyServerHook hook;
    std::string request_seen;
};

[[nodiscard]] auto ask_mock(std::string const& http_response) -> HookAnswer
{
    auto mock = MockPolicyServer{};
    auto started = homeserver::start_client_server(hook_config(mock.url(), false));
    REQUIRE(started.started);
    auto& runtime = started.runtime.homeserver;
    point_runtime_at(runtime, mock);
    auto request_seen = std::string{};
    auto server_thread = std::thread{[&]() {
        tls_mock::run_one_shot_tls_server(mock.acceptor, *mock.tls_context.context, http_response, &request_seen);
    }};
    auto const server_join = tls_mock::ScopedThreadJoin{server_thread};
    auto hook = homeserver::resolve_policy_server_hook(runtime, trust_safety::PolicySurface::federation, "bad.example");
    return {std::move(hook), std::move(request_seen)};
}

} // namespace

SCENARIO("the policy server hook reaches the configured server, pinned to the address its host resolves to",
         "[integration][trust-safety][policy_server_hook][f42]")
{
    GIVEN("trust and safety enabled with an https policy server URL, and a resolver and CA trust for a local mock")
    {
        WHEN("the policy server answers deny")
        {
            auto const answer =
                ask_mock(tls_mock::json_http_response("200 OK", R"({"action":"deny","summary":"abusive server"})"));

            THEN("the hook carries the decision, and the request was the documented POST of surface and entity")
            {
                CHECK(answer.hook.reachable);
                CHECK(answer.hook.decision_received);
                CHECK(answer.hook.action == trust_safety::PolicyAction::deny);
                CHECK_FALSE(trust_safety::policy_server_hook_allows(answer.hook).allowed);
                CHECK(answer.request_seen.starts_with("POST /check "));
                CHECK(answer.request_seen.find("\"surface\":\"federation\"") != std::string::npos);
                CHECK(answer.request_seen.find("\"entity\":\"bad.example\"") != std::string::npos);
            }
        }

        WHEN("the policy server answers allow")
        {
            auto const answer = ask_mock(tls_mock::json_http_response("200 OK", R"({"action":"allow"})"));

            THEN("the hook carries an allow decision")
            {
                CHECK(answer.hook.reachable);
                CHECK(answer.hook.decision_received);
                CHECK(trust_safety::policy_server_hook_allows(answer.hook).allowed);
            }
        }

        WHEN("the policy server answers with an error status")
        {
            auto const answer = ask_mock(tls_mock::json_http_response("500 Internal Server Error", "{}"));

            THEN("it was reached but gave no usable decision, which the configured default then decides")
            {
                CHECK(answer.hook.reachable);
                CHECK_FALSE(answer.hook.decision_received);
                CHECK_FALSE(trust_safety::policy_server_hook_allows(answer.hook).allowed);
            }
        }

        WHEN("the policy server answers with a body that is not a decision")
        {
            auto const answer = ask_mock(tls_mock::json_http_response("200 OK", "not json at all"));

            THEN("it was reached but gave no usable decision")
            {
                CHECK(answer.hook.reachable);
                CHECK_FALSE(answer.hook.decision_received);
            }
        }
    }
}

SCENARIO("a policy server host that does not resolve leaves the hook unreachable, and the configured default decides",
         "[integration][trust-safety][policy_server_hook][f42]")
{
    GIVEN("trust and safety enabled and a resolver that knows no host")
    {
        WHEN("a guarded workflow asks the hook")
        {
            THEN("it is unreachable and the fail-open or fail-closed setting decides")
            {
                for (auto const allow_without_result : {false, true})
                {
                    CAPTURE(allow_without_result);
                    auto started = homeserver::start_client_server(
                        hook_config("https://policy.example.org/check", allow_without_result));
                    REQUIRE(started.started);
                    auto& runtime = started.runtime.homeserver;
                    runtime.discovery_network = std::make_unique<UnresolvableNetwork>();

                    auto const hook = homeserver::resolve_policy_server_hook(
                        runtime, trust_safety::PolicySurface::registration, "@a:b");

                    CHECK_FALSE(hook.reachable);
                    CHECK_FALSE(hook.decision_received);
                    CHECK(trust_safety::policy_server_hook_allows(hook).allowed == allow_without_result);
                }
            }
        }
    }
}

SCENARIO("the host is looked up exactly as the operator configured it, without the SSRF deny-list",
         "[integration][trust-safety][policy_server_hook][f42]")
{
    GIVEN("a policy server on a loopback address, which federation lookups would refuse")
    {
        auto mock = MockPolicyServer{};
        auto started = homeserver::start_client_server(hook_config(mock.url(), false));
        REQUIRE(started.started);
        auto& runtime = started.runtime.homeserver;
        auto network = std::make_unique<LoopbackNetwork>();
        auto const* const observed = network.get();
        runtime.discovery_network = std::move(network);
        runtime.test_policy_server_trusted_ca_pem = mock.certificate.certificate_pem;
        auto const http_response = tls_mock::json_http_response("200 OK", R"({"action":"allow"})");
        auto server_thread = std::thread{[&]() {
            tls_mock::run_one_shot_tls_server(mock.acceptor, *mock.tls_context.context, http_response);
        }};
        auto const server_join = tls_mock::ScopedThreadJoin{server_thread};

        WHEN("the hook is asked")
        {
            auto const hook =
                homeserver::resolve_policy_server_hook(runtime, trust_safety::PolicySurface::federation, "x.example");

            THEN("it resolved the configured host and port, and the loopback server was reached")
            {
                CHECK(observed->asked_host == "localhost");
                CHECK(observed->asked_port == mock.port);
                CHECK(hook.reachable);
                CHECK(hook.decision_received);
            }
        }
    }
}

SCENARIO("policy server calls are admitted through a bounded budget, and a call over it counts as no decision",
         "[integration][trust-safety][policy_server_hook][f42][admission]")
{
    GIVEN("a runtime whose policy-server budget has a surface's whole share in flight")
    {
        auto mock = MockPolicyServer{};
        auto started = homeserver::start_client_server(hook_config(mock.url(), false));
        REQUIRE(started.started);
        auto& runtime = started.runtime.homeserver;
        point_runtime_at(runtime, mock);
        auto const& policy = runtime.client_outbound_proxy_policy;
        REQUIRE(policy.policy_server_per_surface_cap >= 1U);
        REQUIRE(policy.policy_server_global_cap >= 2U);
        auto held = std::vector<http::InFlightBudget::Slot>{};
        for (auto index = std::uint32_t{0U}; index < policy.policy_server_per_surface_cap; ++index)
        {
            auto slot = runtime.policy_server_budget->try_acquire("federation", policy.policy_server_global_cap,
                                                                  policy.policy_server_per_surface_cap);
            REQUIRE(slot.has_value());
            held.push_back(std::move(*slot));
        }
        // Nothing serves the mock: a call that was admitted would fail to be answered, one that was not makes none.

        WHEN("another federation call asks the hook")
        {
            auto const hook =
                homeserver::resolve_policy_server_hook(runtime, trust_safety::PolicySurface::federation, "x.example");

            THEN("it is refused at once as unreachable, and the budget is as it was")
            {
                CHECK_FALSE(hook.reachable);
                CHECK_FALSE(hook.decision_received);
                CHECK_FALSE(trust_safety::policy_server_hook_allows(hook).allowed);
                CHECK(runtime.policy_server_budget->active() == policy.policy_server_per_surface_cap);
            }
        }

        WHEN("a call for a different surface asks the hook while federation holds its whole share")
        {
            auto const http_response = tls_mock::json_http_response("200 OK", R"({"action":"allow"})");
            auto server_thread = std::thread{[&]() {
                tls_mock::run_one_shot_tls_server(mock.acceptor, *mock.tls_context.context, http_response);
            }};
            auto const server_join = tls_mock::ScopedThreadJoin{server_thread};
            auto const hook =
                homeserver::resolve_policy_server_hook(runtime, trust_safety::PolicySurface::registration, "@a:b");

            THEN("it is still admitted and reaches the server, and its place is released afterwards")
            {
                CHECK(hook.reachable);
                CHECK(hook.decision_received);
                CHECK(runtime.policy_server_budget->active() == policy.policy_server_per_surface_cap);
            }
        }

        WHEN("a held call finishes and the surface asks again")
        {
            held.pop_back();
            auto const http_response = tls_mock::json_http_response("200 OK", R"({"action":"allow"})");
            auto server_thread = std::thread{[&]() {
                tls_mock::run_one_shot_tls_server(mock.acceptor, *mock.tls_context.context, http_response);
            }};
            auto const server_join = tls_mock::ScopedThreadJoin{server_thread};
            auto const hook =
                homeserver::resolve_policy_server_hook(runtime, trust_safety::PolicySurface::federation, "x.example");

            THEN("it is admitted and gets the answer")
            {
                CHECK(hook.reachable);
                CHECK(hook.decision_received);
            }
        }
    }
}

SCENARIO("a refused policy server call follows allow_without_result, as any failure to get a decision does",
         "[integration][trust-safety][policy_server_hook][f42][admission]")
{
    GIVEN("the surface's share of the budget in flight")
    {
        WHEN("a media download asks the hook")
        {
            THEN("the answer is the configured one: refused when closed, allowed when open")
            {
                for (auto const allow_without_result : {false, true})
                {
                    CAPTURE(allow_without_result);
                    auto started = homeserver::start_client_server(
                        hook_config("https://policy.example.org/check", allow_without_result));
                    REQUIRE(started.started);
                    auto& runtime = started.runtime.homeserver;
                    auto const& policy = runtime.client_outbound_proxy_policy;
                    auto held = std::vector<http::InFlightBudget::Slot>{};
                    for (auto index = std::uint32_t{0U}; index < policy.policy_server_per_surface_cap; ++index)
                    {
                        auto slot = runtime.policy_server_budget->try_acquire("media", policy.policy_server_global_cap,
                                                                              policy.policy_server_per_surface_cap);
                        REQUIRE(slot.has_value());
                        held.push_back(std::move(*slot));
                    }

                    auto const hook =
                        homeserver::resolve_policy_server_hook(runtime, trust_safety::PolicySurface::media, "abc");

                    CHECK(trust_safety::policy_server_hook_allows(hook).allowed == allow_without_result);
                }
            }
        }
    }
}

// The interaction with F-82: a pre-v12 room ID is "!room<N>" from the number of rooms, computed before the hook,
// and the hook releases runtime.mutex. A creation that runs inside that window took the same number.
SCENARIO("two pre-v12 rooms created while the first one waits on the policy server get different room IDs",
         "[integration][trust-safety][policy_server_hook][f42][f82]")
{
    GIVEN("trust and safety enabled and two registered users")
    {
        auto started = homeserver::start_client_server(hook_config("https://policy.example.org/check", false));
        REQUIRE(started.started);
        auto& client = started.runtime;
        auto& runtime = client.homeserver;
        auto bob_token = std::string{};
        auto bob_status = std::uint16_t{0U};
        auto bob_body = std::string{};
        auto armed = false;
        runtime.trust_safety_policy_server = [&](trust_safety::PolicySurface surface, std::string_view) {
            // The hook runs with runtime.mutex released. While alice's creation waits on it, bob's creates a room.
            if (surface == trust_safety::PolicySurface::room && armed)
            {
                armed = false;
                auto const nested = homeserver::handle_client_server_request(
                    client, {"POST", "/_matrix/client/v3/createRoom", bob_token, R"({"room_version":"6"})"});
                bob_status = nested.response.status;
                bob_body = nested.response.body;
            }
            auto hook = trust_safety::PolicyServerHook{};
            hook.enabled = true;
            hook.reachable = true;
            hook.decision_received = true;
            hook.action = trust_safety::PolicyAction::allow;
            return hook;
        };
        auto const register_account = [&client](std::string_view localpart) {
            auto const registration = homeserver::handle_client_server_request(
                client,
                {"POST", "/_matrix/client/v3/register", {}, tests::registration_json(localpart, "CorrectHorse7!")});
            REQUIRE(registration.response.status == 200U);
            auto const parsed = canonicaljson::parse_lossless(registration.response.body);
            REQUIRE(parsed.error == canonicaljson::ParseError::none);
            auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
            REQUIRE(object != nullptr);
            auto const member = std::ranges::find_if(*object, [](auto const& entry) {
                return entry.key == "access_token";
            });
            REQUIRE(member != object->end());
            return std::get<std::string>(member->value->storage());
        };
        auto const alice_token = register_account("alice");
        bob_token = register_account("bob");
        armed = true;

        WHEN("alice creates a version 6 room and bob creates one inside her policy server call")
        {
            auto const alice_room = homeserver::handle_client_server_request(
                client, {"POST", "/_matrix/client/v3/createRoom", alice_token, R"({"room_version":"6"})"});

            THEN("both succeed, with different room IDs, and both rooms exist")
            {
                CHECK(bob_status == 200U);
                CHECK(alice_room.response.status == 200U);
                auto const room_id_of = [](std::string const& body) {
                    auto const parsed = canonicaljson::parse_lossless(body);
                    auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
                    if (object == nullptr)
                    {
                        return std::string{};
                    }
                    auto const member = std::ranges::find_if(*object, [](auto const& entry) {
                        return entry.key == "room_id";
                    });
                    return member == object->end() ? std::string{} : std::get<std::string>(member->value->storage());
                };
                auto const alice_id = room_id_of(alice_room.response.body);
                auto const bob_id = room_id_of(bob_body);
                CHECK_FALSE(alice_id.empty());
                CHECK_FALSE(bob_id.empty());
                CHECK(alice_id != bob_id);
                CHECK(runtime.database.rooms.size() == 2U);
            }
        }
    }
}
