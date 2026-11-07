// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/file_descriptor.hpp"

#include <string>

namespace merovingian::crypto
{

// ISO-7: one opened master key file. `identity` (as master_key_file_identity
// describes it) and the bytes load_master_key_material(opened) reads come from
// the same descriptor, so a cache keyed on the identity can never hold a key
// derived from a file swapped in between the two. Every derived-key cache opens
// the file once this way; opening for the identity and again for the bytes is
// the race this exists to close.
struct OpenedMasterKeyFile final
{
    core::FileDescriptor file;
    std::string identity{};
};

} // namespace merovingian::crypto
