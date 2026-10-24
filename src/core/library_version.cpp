// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/library_version.hpp"

#include <bit>
#include <string>
#include <string_view>

#include <dlfcn.h>

namespace merovingian::core
{

auto describe_library(std::string_view name, std::string_view runtime_version, std::string_view build_version,
                      void const* address_in_library) -> LibraryVersion
{
    auto library = LibraryVersion{
        std::string{name}, Linkage::static_linked, std::string{runtime_version}, std::string{build_version}, {}};

    auto in_library = Dl_info{};
    if (address_in_library == nullptr || ::dladdr(address_in_library, &in_library) == 0 ||
        in_library.dli_fbase == nullptr)
    {
        return library;
    }
    // This function is compiled into the executable (or, in a test, its test binary), so the
    // object holding it is the one a statically linked library shares.
    auto in_this_binary = Dl_info{};
    auto const* const this_function = std::bit_cast<void const*>(&describe_library);
    if (::dladdr(this_function, &in_this_binary) != 0 && in_this_binary.dli_fbase == in_library.dli_fbase)
    {
        return library;
    }
    library.linkage = Linkage::dynamic;
    library.shared_object = in_library.dli_fname != nullptr ? std::string{in_library.dli_fname} : std::string{};
    return library;
}

auto library_version_log_line(LibraryVersion const& library) -> std::string
{
    auto line = library.name;
    line += library.runtime_version.empty() ? " version not reported" : " " + library.runtime_version;
    if (library.linkage == Linkage::dynamic)
    {
        line += " (dynamic";
        if (!library.shared_object.empty())
        {
            line += ", " + library.shared_object;
        }
        if (!library.build_version.empty())
        {
            line += "; built against " + library.build_version;
        }
        return line + ")";
    }
    line += " (static";
    if (!library.build_version.empty() &&
        (library.runtime_version.empty() || library.build_version != library.runtime_version))
    {
        line += "; built against " + library.build_version;
    }
    return line + ")";
}

} // namespace merovingian::core
