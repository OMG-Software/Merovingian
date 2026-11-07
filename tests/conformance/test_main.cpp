// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/catch_report_arguments.hpp"

#include <catch2/catch_session.hpp>

#include <string>
#include <vector>

auto main(int argc, char* argv[]) -> int
{
    auto const arguments = merovingian::tests::catch_report_arguments(argc, argv);
    auto pointers = std::vector<char const*>{};
    for (auto const& argument : arguments)
    {
        pointers.push_back(argument.c_str());
    }
    return Catch::Session{}.run(static_cast<int>(pointers.size()), pointers.data());
}
