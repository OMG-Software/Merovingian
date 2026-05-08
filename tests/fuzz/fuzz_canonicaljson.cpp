// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstddef>
#include <cstdint>

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size)
    -> int {
    static_cast<void>(data);
    static_cast<void>(size);

    return 0;
}
