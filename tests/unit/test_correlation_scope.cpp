// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/observability/CorrelationContext.hpp"
#include "merovingian/observability/CorrelationScope.hpp"
#include "merovingian/observability/observability.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>

namespace
{

[[nodiscard]] auto published_request_id() -> std::optional<std::string>
{
    auto const* context = merovingian::observability::current_correlation_context();
    if (context == nullptr)
    {
        return std::nullopt;
    }
    return context->request_id;
}

} // namespace

SCENARIO("A correlation scope publishes its own copy of the context", "[observability][correlation]")
{
    GIVEN("no correlation scope is active on this thread")
    {
        REQUIRE_FALSE(published_request_id().has_value());

        WHEN("a scope is opened from a context that is then changed")
        {
            auto source = merovingian::observability::CorrelationContext{"req-1", "trace-1", "span-1"};
            auto const scope = merovingian::observability::CorrelationScope{source};
            source.request_id = "changed";

            THEN("the scope still publishes the context it was opened with")
            {
                CHECK(published_request_id() == std::optional<std::string>{"req-1"});
            }
        }

        WHEN("a scope is opened from a context that is then destroyed")
        {
            auto source = std::optional<merovingian::observability::CorrelationContext>{
                merovingian::observability::CorrelationContext{"req-2", "trace-2", "span-2"}
            };
            auto const scope = merovingian::observability::CorrelationScope{*source};
            source.reset();

            THEN("the published context is still readable and unchanged")
            {
                CHECK(published_request_id() == std::optional<std::string>{"req-2"});
            }
        }

        WHEN("a scope is opened inside another scope and closed")
        {
            auto const outer_context = merovingian::observability::CorrelationContext{"outer", "trace", "span"};
            auto const outer = merovingian::observability::CorrelationScope{outer_context};
            {
                auto const inner = merovingian::observability::CorrelationScope{
                    merovingian::observability::CorrelationContext{"inner", "trace", "span"}
                };
                CHECK(published_request_id() == std::optional<std::string>{"inner"});
            }

            THEN("the outer context is published again")
            {
                CHECK(published_request_id() == std::optional<std::string>{"outer"});
            }
        }

        WHEN("every scope has closed")
        {
            {
                auto const scope = merovingian::observability::CorrelationScope{
                    merovingian::observability::CorrelationContext{"short", "trace", "span"}
                };
            }

            THEN("no context is published")
            {
                CHECK_FALSE(published_request_id().has_value());
            }
        }
    }
}
