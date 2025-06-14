#pragma once 

#include <ppp/stdafx.h>
#include <ppp/threading/BufferswapAllocator.h>

#if defined(__AES_NI__)
#if defined(__x86_64__) || defined(_M_X64) || defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
#if !defined(__AES_NI_IMPL__)
#define  __AES_NI_IMPL__ 1
#endif
#endif
#endif

namespace aesni { 
    bool                            aes_cpu_is_support() noexcept;

    class AES {
    public:
        bool                        TryAttach(const void* key, const void* iv, bool __i128m) noexcept;
        bool                        IsAttached() noexcept { return NULL != key_; }
        static bool                 Support(const ppp::string& method, bool* __i128m = NULL, ppp::string* __rname = NULL) noexcept;

    public:
        std::shared_ptr<ppp::Byte>  Encrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, ppp::Byte* data, int datalen, int& outlen) noexcept { return Process(allocator, data, datalen, outlen, true); } 
        std::shared_ptr<ppp::Byte>  Decrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, ppp::Byte* data, int datalen, int& outlen) noexcept { return Process(allocator, data, datalen, outlen, false); } 

    private:
        const void*     key_     = NULL;
        const void*     iv_      = NULL;
        bool            __i128m_ = false;

        std::shared_ptr<ppp::Byte>  Process(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, ppp::Byte* data, int datalen, int& outlen, bool enc) noexcept;
    };
}