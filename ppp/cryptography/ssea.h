#pragma once

#include <ppp/stdafx.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp
{
    namespace cryptography
    {
        class ssea
        {
        public:
            static void                     shuffle_data(char* encoded_data, int data_size, int key) noexcept;
            static void                     unshuffle_data(char* encoded_data, int data_size, int key) noexcept;
            static int                      delta_encode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int data_size, std::shared_ptr<Byte>& output) noexcept;
            static int                      delta_decode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int data_size, std::shared_ptr<Byte>& output) noexcept;
            static std::shared_ptr<Byte>    base94_encode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen, int& outlen) noexcept;
            static std::shared_ptr<Byte>    base94_decode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen, int& outlen) noexcept;
            static ppp::string              base94_decimal(uint64_t v) noexcept;
            static uint64_t                 base94_decimal(const ppp::string& v) noexcept;
            static uint64_t                 base94_decimal(const void* data, int datalen) noexcept;
        };
    }
}