#include <common/aesni/aes.h>

#if defined(__AES_NI_IMPL__)

#include <wmmintrin.h>   // AES instruction set
#include <emmintrin.h>   // SSE2 instruction set
#include <smmintrin.h>   // SSE4.1 (GHASH usage)
#include <tmmintrin.h>   // SSSE3 (GHASH usage)
#include <string.h>
#include <iostream>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#if defined(_MSC_VER)
#include <cstdlib>
#define __builtin_bswap32(x) _byteswap_ulong(x)
#define __builtin_bswap64(x) _byteswap_uint64(x)
#else
#define __builtin_bswap32(x) __builtin_bswap32(x)
#define __builtin_bswap64(x) __builtin_bswap64(x)
#endif

namespace aesni {
    // AES-256 Key Expansion (generates 14 round keys)
    void aes256_gcm_key_expansion(const uint8_t* key, __m128i* round_key) noexcept {
        // Load initial key (256 bits = 32 bytes)
        __m128i key1 = _mm_loadu_si128((const __m128i*)key);       // First 128 bits
        __m128i key2 = _mm_loadu_si128((const __m128i*)(key + 16)); // Last 128 bits

        round_key[0] = key1;  // Round key 0
        round_key[1] = key2;  // Round key 1

        // Key expansion process (manually unrolled for all rounds)
        __m128i temp = _mm_aeskeygenassist_si128(key2, 0x01); // Generate auxiliary key
        temp = _mm_shuffle_epi32(temp, 0xFF);                 // Byte shuffle
        key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4)); // Shift and XOR
        key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 8));
        key1 = _mm_xor_si128(key1, temp);                    // Add round constant
        round_key[2] = key1;  // Round key 2

        temp = _mm_aeskeygenassist_si128(key1, 0x00);
        temp = _mm_shuffle_epi32(temp, 0xAA);
        key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
        key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 8));
        key2 = _mm_xor_si128(key2, temp);
        round_key[3] = key2;  // Round key 3

        temp = _mm_aeskeygenassist_si128(key2, 0x02);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
        key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 8));
        key1 = _mm_xor_si128(key1, temp);
        round_key[4] = key1;  // Round key 4

        temp = _mm_aeskeygenassist_si128(key1, 0x00);
        temp = _mm_shuffle_epi32(temp, 0xAA);
        key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
        key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 8));
        key2 = _mm_xor_si128(key2, temp);
        round_key[5] = key2;  // Round key 5

        temp = _mm_aeskeygenassist_si128(key2, 0x04);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
        key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 8));
        key1 = _mm_xor_si128(key1, temp);
        round_key[6] = key1;  // Round key 6

        temp = _mm_aeskeygenassist_si128(key1, 0x00);
        temp = _mm_shuffle_epi32(temp, 0xAA);
        key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
        key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 8));
        key2 = _mm_xor_si128(key2, temp);
        round_key[7] = key2;  // Round key 7

        temp = _mm_aeskeygenassist_si128(key2, 0x08);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
        key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 8));
        key1 = _mm_xor_si128(key1, temp);
        round_key[8] = key1;  // Round key 8

        temp = _mm_aeskeygenassist_si128(key1, 0x00);
        temp = _mm_shuffle_epi32(temp, 0xAA);
        key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
        key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 8));
        key2 = _mm_xor_si128(key2, temp);
        round_key[9] = key2;  // Round key 9

        temp = _mm_aeskeygenassist_si128(key2, 0x10);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
        key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 8));
        key1 = _mm_xor_si128(key1, temp);
        round_key[10] = key1; // Round key 10

        temp = _mm_aeskeygenassist_si128(key1, 0x00);
        temp = _mm_shuffle_epi32(temp, 0xAA);
        key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
        key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 8));
        key2 = _mm_xor_si128(key2, temp);
        round_key[11] = key2; // Round key 11

        temp = _mm_aeskeygenassist_si128(key2, 0x20);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
        key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 8));
        key1 = _mm_xor_si128(key1, temp);
        round_key[12] = key1; // Round key 12

        temp = _mm_aeskeygenassist_si128(key1, 0x00);
        temp = _mm_shuffle_epi32(temp, 0xAA);
        key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
        key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 8));
        key2 = _mm_xor_si128(key2, temp);
        round_key[13] = key2; // Round key 13

        temp = _mm_aeskeygenassist_si128(key2, 0x40);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
        key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 8));
        key1 = _mm_xor_si128(key1, temp);
        round_key[14] = key1; // Round key 14
    }

    // AES-256 Encrypt single 128-bit block
    static inline __m128i aes256_encrypt_block(__m128i block, const __m128i* round_key) noexcept {
        block = _mm_xor_si128(block, round_key[0]); // Initial round key addition

        // Perform 13 full AES rounds
        for (int i = 1; i < 14; i++) {
            block = _mm_aesenc_si128(block, round_key[i]); // AES encryption instruction
        }

        // Final round (no MixColumns)
        block = _mm_aesenclast_si128(block, round_key[14]);
        return block;
    }

    // Shift right 128-bit register
    static inline __m128i shift_right(__m128i v) noexcept {
        return _mm_srli_si128(v, 8);
    }

    // Shift left 128-bit register
    static inline __m128i shift_left(__m128i v) noexcept {
        return _mm_slli_si128(v, 8);
    }

    // GHASH core function
    static inline __m128i ghash_reduce(__m128i a, __m128i b) noexcept {
        __m128i t1 = _mm_clmulepi64_si128(a, b, 0x00);
        __m128i t2 = _mm_clmulepi64_si128(a, b, 0x11);
        __m128i t3 = _mm_clmulepi64_si128(a, b, 0x01);
        __m128i t4 = _mm_clmulepi64_si128(a, b, 0x10);
        __m128i t5 = _mm_xor_si128(t3, t4);

        t1 = _mm_xor_si128(t1, _mm_slli_si128(t5, 8));
        t2 = _mm_xor_si128(t2, _mm_srli_si128(t5, 8));

        // Modular reduction (GF(2^128) mod x^128 + x^7 + x^2 + x + 1)
        __m128i t6 = _mm_srli_epi32(t1, 31);
        t1 = _mm_slli_epi32(t1, 1);

        __m128i t7 = _mm_srli_epi32(t2, 31);
        t2 = _mm_slli_epi32(t2, 1);

        t2 = _mm_or_si128(t2, _mm_srli_si128(t6, 12));
        t1 = _mm_or_si128(t1, _mm_slli_si128(t7, 4));

        __m128i t8 = _mm_srli_epi32(t1, 31);
        t1 = _mm_slli_epi32(t1, 1);
        t2 = _mm_or_si128(t2, _mm_srli_si128(t8, 12));

        __m128i reduction = _mm_set_epi32(0, 0, 0, 0x87);
        t2 = _mm_xor_si128(t2, _mm_slli_si128(t8, 4));
        t2 = _mm_xor_si128(t2, _mm_clmulepi64_si128(_mm_srli_si128(t1, 8), reduction, 0x00));
        t1 = _mm_xor_si128(_mm_slli_si128(t1, 8), _mm_clmulepi64_si128(_mm_srli_si128(t1, 8), reduction, 0x10));

        return _mm_xor_si128(t1, t2);
    }

    // Calculate GHASH value (supports chain calling)
    static inline __m128i ghash(const __m128i& H, const uint8_t* data, size_t len, const __m128i& initial_state = _mm_setzero_si128()) noexcept {
        __m128i X = initial_state;
        size_t blocks = len / 16;

        for (size_t i = 0; i < blocks; i++) {
            __m128i block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + i * 16));
            X = _mm_xor_si128(X, block);
            X = ghash_reduce(X, H);
        }

        // Handle remaining partial block
        if (len % 16 != 0) {
            uint8_t last_block[16] = { 0 };
            memcpy(last_block, data + blocks * 16, len % 16);

            __m128i block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(last_block));
            X = _mm_xor_si128(X, block);
            X = ghash_reduce(X, H);
        }

        return X;
    }

    // GCTR mode encryption/decryption
    static inline void gctr(uint8_t* out, const uint8_t* in, size_t len, const __m128i* round_key, __m128i icb) noexcept {
        __m128i cb = icb;
        size_t blocks = len / 16;
        size_t remaining = len % 16;

        // Handle full blocks
        for (size_t i = 0; i < blocks; i++) {
            __m128i keystream = aes256_encrypt_block(cb, round_key);
            __m128i in_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + i * 16));
            __m128i out_block = _mm_xor_si128(in_block, keystream);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + i * 16), out_block);

            // Fix counter increment (big-endian handling)
            uint8_t* cb_ptr = reinterpret_cast<uint8_t*>(&cb);
            uint32_t counter_val;
            memcpy(&counter_val, cb_ptr + 12, 4);

            counter_val = __builtin_bswap32(counter_val);
            counter_val++;
            counter_val = __builtin_bswap32(counter_val);
            memcpy(cb_ptr + 12, &counter_val, 4);
        }

        // Handle remaining bytes
        if (remaining > 0) {
            __m128i keystream = aes256_encrypt_block(cb, round_key);
            const uint8_t* src = in + blocks * 16;
            uint8_t* dst = out + blocks * 16;

            for (size_t i = 0; i < remaining; i++) {
                dst[i] = src[i] ^ reinterpret_cast<uint8_t*>(&keystream)[i];
            }
        }
    }

    // AES-256-GCM encryption
    void aes256_gcm_encrypt(uint8_t* ciphertext, const uint8_t* plaintext, size_t len, const uint8_t* iv, size_t iv_len, const __m128i* round_key) noexcept {
        // Step 1: Compute H = E_k(0^128)
        __m128i H = aes256_encrypt_block(_mm_setzero_si128(), round_key);

        // Step 2: Generate initial counter block J0
        __m128i J0;
        if (iv_len == 12) {
            uint8_t j0_bytes[16];
            memcpy(j0_bytes, iv, 12);

            j0_bytes[12] = 0x00;
            j0_bytes[13] = 0x00;
            j0_bytes[14] = 0x00;
            j0_bytes[15] = 0x01;  // Big-endian counter initialization
            J0 = _mm_loadu_si128(reinterpret_cast<__m128i*>(j0_bytes));
        }
        else {
            J0 = ghash(H, iv, iv_len);
        }

        // Step 3: Encrypt data
        __m128i icb = J0;
        uint8_t* icb_ptr = reinterpret_cast<uint8_t*>(&icb);
        uint32_t counter_val;
        memcpy(&counter_val, icb_ptr + 12, 4);

        counter_val = __builtin_bswap32(counter_val);
        counter_val++;
        counter_val = __builtin_bswap32(counter_val);
        memcpy(icb_ptr + 12, &counter_val, 4);

        gctr(ciphertext, plaintext, len, round_key, icb);
    }

    // AES-256-GCM decryption
    void aes256_gcm_decrypt(uint8_t* plaintext, const uint8_t* ciphertext, size_t len, const uint8_t* iv, size_t iv_len, const __m128i* round_key) noexcept {
        // Step 1: Compute H = E_k(0^128)
        __m128i H = aes256_encrypt_block(_mm_setzero_si128(), round_key);

        // Step 2: Generate initial counter block J0
        __m128i J0;
        if (iv_len == 12) {
            uint8_t j0_bytes[16];
            memcpy(j0_bytes, iv, 12);

            j0_bytes[12] = 0x00;
            j0_bytes[13] = 0x00;
            j0_bytes[14] = 0x00;
            j0_bytes[15] = 0x01;  // Big-endian counter initialization
            J0 = _mm_loadu_si128(reinterpret_cast<__m128i*>(j0_bytes));
        }
        else {
            J0 = ghash(H, iv, iv_len);
        }

        __m128i icb = J0;
        uint8_t* icb_ptr = reinterpret_cast<uint8_t*>(&icb);
        uint32_t counter_val;
        memcpy(&counter_val, icb_ptr + 12, 4);

        counter_val = __builtin_bswap32(counter_val);
        counter_val++;
        counter_val = __builtin_bswap32(counter_val);
        memcpy(icb_ptr + 12, &counter_val, 4);

        gctr(plaintext, ciphertext, len, round_key, icb);
    }
}

#ifdef __builtin_bswap32
#undef __builtin_bswap32
#endif

#endif