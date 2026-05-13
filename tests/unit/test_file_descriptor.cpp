// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/file_descriptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <unistd.h>

SCENARIO("FileDescriptor defaults to invalid", "[core][file_descriptor]")
{
    GIVEN("the invalid file descriptor sentinel")
    {
        auto constexpr invalid_fd = merovingian::core::FileDescriptor::invalid;

        WHEN("a default FileDescriptor is constructed")
        {
            auto fd = merovingian::core::FileDescriptor{};

            THEN("it is invalid and stores the sentinel")
            {
                REQUIRE_FALSE(fd.valid());
                REQUIRE(fd.get() == invalid_fd);
            }
        }
    }
}

SCENARIO("FileDescriptor can release ownership", "[core][file_descriptor]")
{
    GIVEN("a pipe wrapped by FileDescriptor objects")
    {
        int raw_fds[2]{};
        REQUIRE(::pipe(raw_fds) == 0);

        auto read_end = merovingian::core::FileDescriptor{raw_fds[0]};
        auto write_end = merovingian::core::FileDescriptor{raw_fds[1]};

        WHEN("the read end is released")
        {
            auto const released = read_end.release();

            THEN("the wrapper no longer owns it")
            {
                REQUIRE_FALSE(read_end.valid());
                REQUIRE(released == raw_fds[0]);
            }

            static_cast<void>(::close(released));
        }
    }
}
