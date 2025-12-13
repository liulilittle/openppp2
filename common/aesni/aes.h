#pragma once 

#include <ppp/stdafx.h>
#include <ppp/threading/BufferswapAllocator.h>

#if defined(__SIMD__)
#if defined(__x86_64__) || defined(_M_X64) || defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
#if !defined(__AES_NI_IMPL__)
#define  __AES_NI_IMPL__ 1
#endif
#endif
#endif

namespace aesni { 
    bool                                    aes_cpu_is_support() noexcept;

    class AES {     
    public:
        AES() noexcept;

    public:     
        bool                                TryAttach(const void* key, const void* iv, bool __i128m, bool __bgctr) noexcept;
        bool                                IsAttached() noexcept { return NULL != iv_; }
        static bool                         Support(const ppp::string& method, bool* __i128m = NULL, bool* __bgctr = NULL, ppp::string* __rname = NULL) noexcept;

    public:     
        std::shared_ptr<ppp::Byte>          Encrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, ppp::Byte* data, int datalen, int& outlen) noexcept { return Process(allocator, data, datalen, outlen, true); } 
        std::shared_ptr<ppp::Byte>          Decrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, ppp::Byte* data, int datalen, int& outlen) noexcept { return Process(allocator, data, datalen, outlen, false); } 

    private:        
        std::shared_ptr<ppp::Byte>          Process(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, ppp::Byte* data, int datalen, int& outlen, bool enc) noexcept;

    private:        
        using                               RoundKey             = std::array<uint8_t, 16>;

        const void*                         iv_         = NULL;

        struct {
            bool                            __i128m_    : 1;
            bool                            __bgctr_    : 7;
        };

        std::shared_ptr<RoundKey>           __round_key_;       
    };
}