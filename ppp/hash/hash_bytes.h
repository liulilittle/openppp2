#pragma once

#include <ppp/stdafx.h>

namespace ppp
{
    namespace hash
    {
        size_t _Hash_bytes(const void* ptr, size_t len, size_t seed) noexcept;
        size_t _Fnv_hash_bytes(const void* ptr, size_t len, size_t hash) noexcept;
    }
}