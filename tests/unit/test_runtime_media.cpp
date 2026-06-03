// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config.hpp"
#include "merovingian/media/runtime_media.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Runtime media config parses bounded media limits", "[media][runtime]")
{
    GIVEN("configuration with bounded media limits")
    {
        auto security = merovingian::config::SecurityConfig{};
        security.media.max_upload_size = "25MiB";
        security.media.remote_fetch_timeout = "45s";
        auto const config = merovingian::config::Config {
            merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},
            security,
            merovingian::config::ClientRateLimitsConfig{},
            merovingian::config::LogModulesConfig{},
};

        WHEN("the runtime media config is created")
        {
            auto const runtime_media = merovingian::media::make_runtime_media_config(config);

            THEN("bounded operational values are parsed")
            {
                REQUIRE(runtime_media.max_upload_bytes == 26214400U);
                REQUIRE(runtime_media.remote_fetch_timeout_seconds == 45U);
                REQUIRE(runtime_media.quarantine_unknown_mime);
                REQUIRE(runtime_media.enable_av_scanner);
                REQUIRE(runtime_media.private_address_fetches_blocked);
                REQUIRE(runtime_media.decode_in_sandbox);
            }
        }
    }
}

SCENARIO("Runtime media summary exposes bounded operational values", "[media][runtime]")
{
    GIVEN("a runtime media config")
    {
        auto runtime_media = merovingian::media::RuntimeMediaConfig{};
        runtime_media.max_upload_bytes = 52428800U;
        runtime_media.remote_fetch_timeout_seconds = 30U;
        runtime_media.private_address_fetches_blocked = true;
        runtime_media.decode_in_sandbox = true;

        WHEN("the media summary is generated")
        {
            auto const summary = merovingian::media::media_summary(runtime_media);

            THEN("the expected operational values are present")
            {
                REQUIRE(summary.find("max_upload_bytes=52428800") != std::string::npos);
                REQUIRE(summary.find("remote_fetch_timeout_seconds=30") != std::string::npos);
                REQUIRE(summary.find("private_address_fetches_blocked=true") != std::string::npos);
                REQUIRE(summary.find("decode_in_sandbox=true") != std::string::npos);
            }
        }
    }
}
