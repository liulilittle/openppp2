#include <common/aesni/aes.h>

#if defined(__AES_NI_IMPL__)
#include <wmmintrin.h>   // AES instruction set
#include <emmintrin.h>   // SSE2 instruction set
#include <string.h>

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

#include <ppp/stdafx.h>
#include <ppp/IDisposable.h>

namespace aesni {
    bool aes_cpu_is_support() noexcept {
#if defined(__AES_NI_IMPL__)
#if defined(__GNUC__) || defined(__clang__)
        unsigned int ecx = 0;
        __asm__ __volatile__(
            "cpuid"
            : "=c" (ecx)
            : "a" (1)
            : "%ebx", "%edx"
        );

        return (ecx & (1 << 25)) != 0;
#elif defined(_MSC_VER) && (defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86))
        unsigned int ecxv = 0;
        _asm {
            mov eax, 1;
            cpuid;
            mov dword ptr[ecxv], ecx;
        }

        return (ecxv & (1 << 25)) != 0;
#else
        int info[4];
        __cpuidex(info, 1, 0);

        return (info[2] & (1 << 25)) != 0;
#endif
#else
        return false;
#endif
    }

#if defined(__AES_NI_IMPL__)
    void aes128_cfb_decrypt(uint8_t* plaintext, const uint8_t* ciphertext, size_t len, const uint8_t* iv, const __m128i* round_key) noexcept;
    void aes128_gcm_decrypt(uint8_t* plaintext, const uint8_t* ciphertext, size_t len, const uint8_t* iv, size_t iv_len, const __m128i* round_key) noexcept;
    void aes256_cfb_decrypt(uint8_t* plaintext, const uint8_t* ciphertext, size_t len, const uint8_t* iv, const __m128i* round_key) noexcept;
    void aes256_gcm_decrypt(uint8_t* plaintext, const uint8_t* ciphertext, size_t len, const uint8_t* iv, size_t iv_len, const __m128i* round_key) noexcept;

    void aes256_gcm_encrypt(uint8_t* ciphertext, const uint8_t* plaintext, size_t len, const uint8_t* iv, size_t iv_len, const __m128i* round_key) noexcept;
    void aes256_cfb_encrypt(uint8_t* ciphertext, const uint8_t* plaintext, size_t len, const uint8_t* iv, const __m128i* round_key) noexcept;
    void aes128_cfb_encrypt(uint8_t* ciphertext, const uint8_t* plaintext, size_t len, const uint8_t* iv, const __m128i* round_key) noexcept;
    void aes128_gcm_encrypt(uint8_t* ciphertext, const uint8_t* plaintext, size_t len, const uint8_t* iv, size_t iv_len, const __m128i* round_key) noexcept;
    
    void aes128_gcm_key_expansion(const uint8_t* key, __m128i* round_key) noexcept;
    void aes256_gcm_key_expansion(const uint8_t* key, __m128i* round_key) noexcept;
    void aes128_cfb_key_expansion(const uint8_t* key, __m128i* round_key) noexcept;
    void aes256_cfb_key_expansion(const uint8_t* key, __m128i* round_key) noexcept;

    static inline void aes_encrypt_feedback(__m128i* round_key, uint8_t* ciphertext, const uint8_t* plaintext, size_t len, const uint8_t* iv, bool __i128m) noexcept {
        if (__i128m) {
            aes128_cfb_encrypt(ciphertext, plaintext, len, iv, round_key);
        }
        else {
            aes256_cfb_encrypt(ciphertext, plaintext, len, iv, round_key);
        }
    }

    static inline void aes_decrypt_feedback(__m128i* round_key, uint8_t* plaintext, const uint8_t* ciphertext, size_t len, const uint8_t* iv, bool __i128m) noexcept {
        if (__i128m) {
            aes128_cfb_decrypt(plaintext, ciphertext, len, iv, round_key);
        }
        else {
            aes256_cfb_decrypt(plaintext, ciphertext, len, iv, round_key);
        }
    }

    // OpenSSL AEAD/128-256/GCM algorithm IVV length is 12 by default.
    static inline void aes_encrypt_gcounter(__m128i* round_key, uint8_t* ciphertext, const uint8_t* plaintext, size_t len, const uint8_t* iv, bool __i128m) noexcept {
        if (__i128m) {
            aes128_gcm_encrypt(ciphertext, plaintext, len, iv, 12, round_key);
        }
        else {
            aes256_gcm_encrypt(ciphertext, plaintext, len, iv, 12, round_key);
        }
    }

    static inline void aes_decrypt_gcounter(__m128i* round_key, uint8_t* plaintext, const uint8_t* ciphertext, size_t len, const uint8_t* iv, bool __i128m) noexcept {
        if (__i128m) {
            aes128_gcm_decrypt(plaintext, ciphertext, len, iv, 12, round_key);
        }
        else {
            aes256_gcm_decrypt(plaintext, ciphertext, len, iv, 12, round_key);
        }
    }
#endif

    bool AES::TryAttach(const void* key, const void* iv, bool __i128m, bool __bgctr) noexcept {
        if (NULL == key || NULL == iv) {
            return false;
        }

        bool supported = aes_cpu_is_support();
        if (!supported) {
            return false;
        }

#if defined(__AES_NI_IMPL__)
        __round_key_ = ppp::make_shared_alloc<RoundKey>(15);
        if (NULL == __round_key_) {
            return false;
        }

        iv_      = iv;
        __i128m_ = __i128m;
        __bgctr_ = __bgctr;

        /* register */ __m128i* round_key = (__m128i*)__round_key_.get();
        if (__i128m) {
            __bgctr ? aes128_gcm_key_expansion((uint8_t*)key, round_key) : aes128_cfb_key_expansion((uint8_t*)key, round_key);
        }
        else {
            __bgctr ? aes256_gcm_key_expansion((uint8_t*)key, round_key) : aes256_cfb_key_expansion((uint8_t*)key, round_key);
        }

        return true;
#else
        return false;
#endif
    }

    bool AES::Support(const ppp::string& method, bool* __i128m, bool* __bgctr, ppp::string* __rname) noexcept {
        bool supported = aes_cpu_is_support();
        if (!supported) {
            return false;
        }

        if (NULL != __bgctr) {
            *__bgctr = false;
        }

        if (NULL != __i128m) {
            *__i128m = false;
        }

        if (method == "simd-aes-128-cfb") {
            if (NULL != __i128m) {
                *__i128m = true;
            }

            if (NULL != __rname) {
                *__rname = PPP_DEFAULT_KEY_PROTOCOL;
            }

            return true;
        }

        if (method == "simd-aes-256-cfb") {
            if (NULL != __rname) {
                *__rname = PPP_DEFAULT_KEY_TRANSPORT;
            }

            return true;
        }

        if (method == "simd-aes-128-gcm") {
            if (NULL != __i128m) {
                *__i128m = true;
            }

            if (NULL != __rname) {
                *__rname = "aes-128-gcm";
            }

            if (NULL != __bgctr) {
                *__bgctr = true;
            }

            return true;
        }

        if (method == "simd-aes-256-gcm") {
            if (NULL != __rname) {
                *__rname = "aes-256-gcm";
            }

            if (NULL != __bgctr) {
                *__bgctr = true;
            }

            return true;
        }

        return false;
    }

    AES::AES() noexcept 
        : __i128m_(false)
        , __bgctr_(false) {

    }

    std::shared_ptr<ppp::Byte> AES::Process(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, ppp::Byte* data, int datalen, int& outlen, bool enc) noexcept {
#if !defined(__AES_NI_IMPL__)
        outlen = ~0;
        return NULL;
#else
        outlen = 0;
        if (datalen < 0 || (NULL == data && datalen != 0)) {
            outlen = ~0;
            return NULL;
        }

        if (datalen == 0) {
            return NULL;
        }

        std::shared_ptr<ppp::Byte> ciphertext = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, datalen + 1);
        if (NULL == ciphertext) {
            return NULL;
        }

        if (__bgctr_) {
            if (enc) {
                aes_encrypt_gcounter((__m128i*)__round_key_.get(), (uint8_t*)ciphertext.get(), (uint8_t*)data, datalen, (uint8_t*)iv_, __i128m_);
            }
            else {
                aes_decrypt_gcounter((__m128i*)__round_key_.get(), (uint8_t*)ciphertext.get(), (uint8_t*)data, datalen, (uint8_t*)iv_, __i128m_);
            }
        }
        else {
            if (enc) {
                aes_encrypt_feedback((__m128i*)__round_key_.get(), (uint8_t*)ciphertext.get(), (uint8_t*)data, datalen, (uint8_t*)iv_, __i128m_);
            }
            else {
                aes_decrypt_feedback((__m128i*)__round_key_.get(), (uint8_t*)ciphertext.get(), (uint8_t*)data, datalen, (uint8_t*)iv_, __i128m_);
            }
        }

        outlen = datalen;
        return ciphertext;
#endif
    }
}