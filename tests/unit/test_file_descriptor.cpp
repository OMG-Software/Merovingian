// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/core/file_descriptor.hpp>

#include <catch2/catch_test_macros.hpp>

#include <unistd.h>

TEST_CASE("FileDescriptor defaults to invalid", "[core][file_descriptor]") {
    // Given / When
    auto fd = merovingian::core::FileDescriptor{};

    // Then
    REQUIRE_FALSE(fd.valid());
    REQUIRE(fd.get() == merovingian::core::FileDescriptor::invalid);
}

TEST_CASE("FileDescriptor can release ownership", "[core][file_descriptor]") {
    // Given
    int raw_fds[2]{};
    REQUIRE(::pipe(raw_fds) == 0);

    auto read_end = merovingian::core::FileDescriptor{raw_fds[0]};
    auto write_end = merovingian::core::FileDescriptor{raw_fds[1]};

    // When
    auto const released = read_end.release();

    // Then
    REQUIRE_FALSE(read_end.valid());
    REQUIRE(released == raw_fds[0]);

    static_cast<void>(::close(released));
}
