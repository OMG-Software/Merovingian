// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Run-3 C14 (ADR-0672). Storing a signature found its row with a linear search of the server-wide `key_signatures`
// vector and committed one statement per signature, and the cap check and the key-publishing merge each read rows of
// other signers and other keys, all under the runtime lock. Policy: an upload is one transaction, the signer's rows
// come from a per-signer index, a key's signatures come from a (target user, target key) index, and a replacement
// updates the row in place.
//
// Spec: client-server-api.md, POST /keys/signatures/upload (signatures are stored per signed key; a repeated upload
// replaces the earlier signature) and POST /keys/query (the key carries the signatures uploaded for it).

#include "../support/E2eeCapsSupport.hpp"
#include "merovingian/database/PersistentDeviceKey.hpp"
#include "merovingian/database/PersistentKeySignature.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

namespace
{

namespace hs = merovingian::homeserver;
namespace db = merovingian::database;
using merovingian::tests::caps_config;
using merovingian::tests::register_and_login_alice;

constexpr auto alice = std::string_view{"@alice:example.org"};

[[nodiscard]] auto signature_json(std::string_view signer) -> std::string
{
    return std::string{R"({"user_id":"@alice:example.org","signatures":{")"} + std::string{signer} +
           R"(":{"ed25519:SSK":"sig"}}})";
}

// A body signing `count` of alice's keys, named D0 .. D<count-1>.
[[nodiscard]] auto upload_body(std::size_t count, std::string_view signature = "sig") -> std::string
{
    auto body = std::string{R"({"@alice:example.org":{)"};
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        body += index == 0U ? "" : ",";
        body += "\"D" + std::to_string(index) +
                R"(":{"user_id":"@alice:example.org","signatures":{"@alice:example.org":{)" + R"("ed25519:SSK":")" +
                std::string{signature} + R"("}}})";
    }
    body += "}}";
    return body;
}

[[nodiscard]] auto upload(hs::ClientServerRuntime& runtime, std::string const& token, std::string body)
    -> hs::LocalHttpResponse
{
    return hs::handle_client_server_request(
               runtime, {"POST", "/_matrix/client/v3/keys/signatures/upload", token, std::move(body)})
        .response;
}

auto add_other_signers(hs::ClientServerRuntime& runtime, std::size_t count) -> void
{
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        auto const signer = "@signer" + std::to_string(index) + ":example.org";
        REQUIRE(db::store_key_signature(
            runtime.homeserver.database.persistent_store,
            {signer, "@bob:example.org", "KEY" + std::to_string(index), signature_json(signer)}));
    }
}

} // namespace

SCENARIO("a signature upload is one transaction and reads only the signer's own rows",
         "[homeserver][client-server][e2ee][cost][security][c14]")
{
    GIVEN("300 signature rows by other signers and a logged-in user")
    {
        auto started = hs::start_client_server(caps_config(100U, 10000U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& store = runtime.homeserver.database.persistent_store;
        auto const token = register_and_login_alice(runtime);
        add_other_signers(runtime, 300U);

        WHEN("the user uploads signatures for 20 keys, and then the same 20 again")
        {
            auto const commits_before = db::committed_transaction_count(store);
            auto const first = upload(runtime, token, upload_body(20U));
            auto const commits_after_first = db::committed_transaction_count(store);
            auto const rows_before_second = store.key_rows_examined.value();
            auto const second = upload(runtime, token, upload_body(20U, "newer"));
            auto const commits_after_second = db::committed_transaction_count(store);
            auto const rows_after_second = store.key_rows_examined.value();
            auto const third = upload(runtime, token, upload_body(40U, "third"));
            auto const commits_after_third = db::committed_transaction_count(store);

            THEN("an upload commits a fixed number of times whatever its size, and the repeat reads the signer's 20 "
                 "rows and replaces them in place")
            {
                REQUIRE(first.status == 200U);
                REQUIRE(second.status == 200U);
                // An upload commits once for its signatures plus a fixed few for the device-list change it
                // announces, so a 20-key and a 40-key upload commit the same number of times.
                REQUIRE(third.status == 200U);
                REQUIRE(commits_after_third - commits_after_second == commits_after_first - commits_before);
                REQUIRE(rows_after_second - rows_before_second == 20U);
                REQUIRE(store.key_signatures.size() == 340U);
                auto replaced = std::size_t{0U};
                for (auto const& row : store.key_signatures)
                {
                    replaced += static_cast<std::size_t>(row.signer_user_id == alice &&
                                                         row.json.find("third") != std::string::npos);
                }
                REQUIRE(replaced == 40U);
            }
        }

        WHEN("the indexes are rebuilt, as after a reload, and a row is pushed directly")
        {
            REQUIRE(upload(runtime, token, upload_body(5U)).status == 200U);
            db::rebuild_key_signature_index(store);
            store.key_signatures.push_back({std::string{alice}, std::string{alice}, "D0", signature_json(alice)});
            auto const rows = store.key_signatures.size();
            auto const response = upload(runtime, token, upload_body(5U, "after"));

            THEN("the upload heals the stale indexes and updates the rows, adding none")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(store.key_signatures.size() == rows);
                auto replaced = std::size_t{0U};
                for (auto const& row : store.key_signatures)
                {
                    replaced += static_cast<std::size_t>(row.signer_user_id == alice &&
                                                         row.json.find("after") != std::string::npos);
                }
                REQUIRE(replaced == 5U);
            }
        }
    }
}

SCENARIO("publishing a key merges only the signatures of that key",
         "[homeserver][client-server][e2ee][cost][security][c14]")
{
    GIVEN("a user with one device key, two signatures on it and 500 on keys that do not exist")
    {
        auto started = hs::start_client_server(caps_config(100U, 10000U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& store = runtime.homeserver.database.persistent_store;
        auto const token = register_and_login_alice(runtime);
        REQUIRE(db::store_device_key(
            store,
            {std::string{alice}, "DEV0",
             R"({"algorithms":["m.megolm.v1.aes-sha2"],"device_id":"DEV0","keys":{"ed25519:DEV0":"k"},"user_id":"@alice:example.org"})"}));
        for (auto index = std::size_t{0U}; index < 500U; ++index)
        {
            auto const signer = "@signer" + std::to_string(index) + ":example.org";
            REQUIRE(db::store_key_signature(
                store, {signer, std::string{alice}, "FAKE" + std::to_string(index), signature_json(signer)}));
        }
        REQUIRE(db::store_key_signature(
            store, {"@s1:example.org", std::string{alice}, "DEV0", signature_json("@s1:example.org")}));
        REQUIRE(db::store_key_signature(
            store, {"@s2:example.org", std::string{alice}, "DEV0", signature_json("@s2:example.org")}));

        WHEN("the user's keys are queried")
        {
            auto const before = store.key_rows_examined.value();
            auto const response =
                hs::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/keys/query", token,
                                                           R"({"device_keys":{"@alice:example.org":[]}})"})
                    .response;

            THEN("the device key is answered and exactly its two signature rows were read")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("\"DEV0\"") != std::string::npos);
                REQUIRE(store.key_rows_examined.value() - before == 2U);
            }
        }
    }
}
