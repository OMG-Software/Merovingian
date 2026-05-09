// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/crypto/random.hpp>

namespace merovingian::crypto
{

auto random_size_is_allowed(std::size_t size) noexcept -> bool
{
    return size > 0U && size <= 4096U;
}

} // namespace merovingian::crypto
