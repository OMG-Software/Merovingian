// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation_worker/args.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

namespace
{

using merovingian::federation_worker::parse_worker_args;

auto parse(std::vector<char const*> const& args) -> merovingian::federation_worker::ParsedWorkerArgs
{
    return parse_worker_args(static_cast<int>(args.size()), args.data());
}

} // namespace

SCENARIO("parse_worker_args requires --config and --ipc-fd", "[federation-worker][args]")
{
    GIVEN("no arguments")
    {
        WHEN("they are parsed")
        {
            auto const result = parse({"merovingian-fed-worker"});

            THEN("an error is returned")
            {
                REQUIRE(result.error.has_value());
            }
        }
    }

    GIVEN("only --config")
    {
        WHEN("they are parsed")
        {
            auto const result = parse({"merovingian-fed-worker", "--config", "/etc/merovingian.toml"});

            THEN("an error is returned because --ipc-fd is missing")
            {
                REQUIRE(result.error.has_value());
            }
        }
    }

    GIVEN("only --ipc-fd")
    {
        WHEN("they are parsed")
        {
            auto const result = parse({"merovingian-fed-worker", "--ipc-fd", "7"});

            THEN("an error is returned because --config is missing")
            {
                REQUIRE(result.error.has_value());
            }
        }
    }
}

SCENARIO("parse_worker_args captures required arguments", "[federation-worker][args]")
{
    GIVEN("valid --config and --ipc-fd arguments")
    {
        WHEN("they are parsed")
        {
            auto const result = parse({
                "merovingian-fed-worker",
                "--config",
                "/etc/merovingian.toml",
                "--ipc-fd",
                "7",
            });

            THEN("no error is reported and the values are captured")
            {
                REQUIRE_FALSE(result.error.has_value());
                REQUIRE(result.config_path == "/etc/merovingian.toml");
                REQUIRE(result.ipc_fd == 7);
            }
        }
    }
}

SCENARIO("parse_worker_args defaults shard index to 0", "[federation-worker][args]")
{
    GIVEN("arguments without --shard")
    {
        WHEN("they are parsed")
        {
            auto const result = parse({
                "merovingian-fed-worker",
                "--config",
                "/etc/merovingian.toml",
                "--ipc-fd",
                "7",
            });

            THEN("shard index defaults to 0")
            {
                REQUIRE(result.shard_index == 0U);
            }
        }
    }
}

SCENARIO("parse_worker_args accepts an explicit shard index", "[federation-worker][args]")
{
    GIVEN("a --shard argument")
    {
        WHEN("a non-zero shard is provided")
        {
            auto const result = parse({
                "merovingian-fed-worker",
                "--config",
                "/etc/merovingian.toml",
                "--ipc-fd",
                "8",
                "--shard",
                "3",
            });

            THEN("the shard index is captured")
            {
                REQUIRE_FALSE(result.error.has_value());
                REQUIRE(result.shard_index == 3U);
            }
        }
    }
}

SCENARIO("parse_worker_args rejects invalid or incomplete values", "[federation-worker][args]")
{
    GIVEN("--ipc-fd without a value")
    {
        WHEN("it is parsed")
        {
            auto const result = parse({
                "merovingian-fed-worker",
                "--config",
                "/etc/merovingian.toml",
                "--ipc-fd",
            });

            THEN("an error is reported")
            {
                REQUIRE(result.error.has_value());
            }
        }
    }

    GIVEN("an unparseable --ipc-fd")
    {
        WHEN("it is parsed")
        {
            auto const result = parse({
                "merovingian-fed-worker",
                "--config",
                "/etc/merovingian.toml",
                "--ipc-fd",
                "not-a-fd",
            });

            THEN("an error is reported")
            {
                REQUIRE(result.error.has_value());
            }
        }
    }

    GIVEN("an unparseable --shard")
    {
        WHEN("it is parsed")
        {
            auto const result = parse({
                "merovingian-fed-worker",
                "--config",
                "/etc/merovingian.toml",
                "--ipc-fd",
                "9",
                "--shard",
                "abc",
            });

            THEN("an error is reported")
            {
                REQUIRE(result.error.has_value());
            }
        }
    }
}
