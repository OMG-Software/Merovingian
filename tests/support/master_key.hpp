// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <atomic>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

#include <sodium.h>

namespace merovingian::tests
{

// Write a unique 256-bit master key file to the system temp directory and return
// its path. Each call produces a distinct file so parallel meson test jobs do not
// overwrite each other's key material.
inline auto master_key_file() -> std::string
{
    static auto const s_salt = std::random_device{}();
    static std::atomic<unsigned> s_counter{0U};
    auto const filename =
        "merovingian-master-" + std::to_string(s_salt) + "-" + std::to_string(s_counter.fetch_add(1U)) + ".key";
    auto const path = std::filesystem::temp_directory_path() / filename;
    auto output = std::ofstream{path, std::ios::binary};

    auto key = std::vector<unsigned char>(crypto_generichash_KEYBYTES);
    randombytes_buf(key.data(), key.size());
    output.write(reinterpret_cast<char const*>(key.data()), static_cast<std::streamsize>(key.size()));
    return path.string();
}

} // namespace merovingian::tests
