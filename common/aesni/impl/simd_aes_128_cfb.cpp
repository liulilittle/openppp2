#include <common/aesni/aes.h>

#if defined(__AES_NI_IMPL__)

#include <wmmintrin.h>   // AES instruction set
#include <emmintrin.h>   // SSE2 instruction set
#include <string.h>
#include <iostream>

namespace aesni {
    // AES-128 key expansion (generates 11 round keys)
   void aes128_cfb_key_expansion(const uint8_t* key, __m128i* round_key) noexcept {
        round_key[0] = _mm_loadu_si128((const __m128i*)key);

        // Unroll the loop to provide correct round constants for each round
        __m128i temp = _mm_aeskeygenassist_si128(round_key[0], 0x01);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        round_key[1] = _mm_xor_si128(round_key[0], _mm_slli_si128(round_key[0], 4));
        round_key[1] = _mm_xor_si128(round_key[1], _mm_slli_si128(round_key[1], 8));
        round_key[1] = _mm_xor_si128(round_key[1], temp);

        temp = _mm_aeskeygenassist_si128(round_key[1], 0x02);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        round_key[2] = _mm_xor_si128(round_key[1], _mm_slli_si128(round_key[1], 4));
        round_key[2] = _mm_xor_si128(round_key[2], _mm_slli_si128(round_key[2], 8));
        round_key[2] = _mm_xor_si128(round_key[2], temp);

        temp = _mm_aeskeygenassist_si128(round_key[2], 0x04);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        round_key[3] = _mm_xor_si128(round_key[2], _mm_slli_si128(round_key[2], 4));
        round_key[3] = _mm_xor_si128(round_key[3], _mm_slli_si128(round_key[3], 8));
        round_key[3] = _mm_xor_si128(round_key[3], temp);

        temp = _mm_aeskeygenassist_si128(round_key[3], 0x08);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        round_key[4] = _mm_xor_si128(round_key[3], _mm_slli_si128(round_key[3], 4));
        round_key[4] = _mm_xor_si128(round_key[4], _mm_slli_si128(round_key[4], 8));
        round_key[4] = _mm_xor_si128(round_key[4], temp);

        temp = _mm_aeskeygenassist_si128(round_key[4], 0x10);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        round_key[5] = _mm_xor_si128(round_key[4], _mm_slli_si128(round_key[4], 4));
        round_key[5] = _mm_xor_si128(round_key[5], _mm_slli_si128(round_key[5], 8));
        round_key[5] = _mm_xor_si128(round_key[5], temp);

        temp = _mm_aeskeygenassist_si128(round_key[5], 0x20);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        round_key[6] = _mm_xor_si128(round_key[5], _mm_slli_si128(round_key[5], 4));
        round_key[6] = _mm_xor_si128(round_key[6], _mm_slli_si128(round_key[6], 8));
        round_key[6] = _mm_xor_si128(round_key[6], temp);

        temp = _mm_aeskeygenassist_si128(round_key[6], 0x40);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        round_key[7] = _mm_xor_si128(round_key[6], _mm_slli_si128(round_key[6], 4));
        round_key[7] = _mm_xor_si128(round_key[7], _mm_slli_si128(round_key[7], 8));
        round_key[7] = _mm_xor_si128(round_key[7], temp);

        temp = _mm_aeskeygenassist_si128(round_key[7], 0x80);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        round_key[8] = _mm_xor_si128(round_key[7], _mm_slli_si128(round_key[7], 4));
        round_key[8] = _mm_xor_si128(round_key[8], _mm_slli_si128(round_key[8], 8));
        round_key[8] = _mm_xor_si128(round_key[8], temp);

        temp = _mm_aeskeygenassist_si128(round_key[8], 0x1B);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        round_key[9] = _mm_xor_si128(round_key[8], _mm_slli_si128(round_key[8], 4));
        round_key[9] = _mm_xor_si128(round_key[9], _mm_slli_si128(round_key[9], 8));
        round_key[9] = _mm_xor_si128(round_key[9], temp);

        temp = _mm_aeskeygenassist_si128(round_key[9], 0x36);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        round_key[10] = _mm_xor_si128(round_key[9], _mm_slli_si128(round_key[9], 4));
        round_key[10] = _mm_xor_si128(round_key[10], _mm_slli_si128(round_key[10], 8));
        round_key[10] = _mm_xor_si128(round_key[10], temp);
    }

    // AES-128 encrypts a single 128-bit block
    static inline __m128i aes128_encrypt_block(__m128i block, const __m128i* round_key) noexcept {
        block = _mm_xor_si128(block, round_key[0]); // Initial round key addition

        // Perform 9 full AES rounds
        for (int i = 1; i < 10; i++) {
            block = _mm_aesenc_si128(block, round_key[i]);
        }

        // Final round (without MixColumns)
        block = _mm_aesenclast_si128(block, round_key[10]);
        return block;
    }

    // AES-128-CFB encryption
    void aes128_cfb_encrypt(uint8_t* ciphertext, const uint8_t* plaintext, size_t len, const uint8_t* iv, const __m128i* round_key) noexcept {
        __m128i feedback = _mm_loadu_si128((const __m128i*)iv); // Initialize feedback register
        size_t blocks = len / 16;    // Number of full blocks
        size_t remaining = len % 16; // Number of remaining bytes

        // Process full blocks
        for (size_t i = 0; i < blocks; i++) {
            // Generate keystream
            __m128i keystream = aes128_encrypt_block(feedback, round_key);
            // Load current plaintext block
            __m128i plain_block = _mm_loadu_si128((const __m128i*)(plaintext + i * 16));
            // XOR to generate ciphertext block
            __m128i cipher_block = _mm_xor_si128(plain_block, keystream);

            // Store ciphertext block
            _mm_storeu_si128((__m128i*)(ciphertext + i * 16), cipher_block);

            // Update feedback register (using newly generated ciphertext)
            feedback = cipher_block;
        }

        // Process partial block
        if (remaining > 0) {
            // Generate partial keystream
            __m128i keystream = aes128_encrypt_block(feedback, round_key);
            const uint8_t* src = plaintext + blocks * 16;
            uint8_t* dst = ciphertext + blocks * 16;

            // Process remaining data byte by byte using XOR
            for (size_t i = 0; i < remaining; i++) {
                dst[i] = src[i] ^ ((uint8_t*)&keystream)[i];
            }
        }
    }

    // AES-128-CFB decryption
    void aes128_cfb_decrypt(uint8_t* plaintext, const uint8_t* ciphertext, size_t len, const uint8_t* iv, const __m128i* round_key) noexcept {
        __m128i feedback = _mm_loadu_si128((const __m128i*)iv); // Initialize feedback register
        size_t blocks = len / 16;    // Number of full blocks
        size_t remaining = len % 16; // Number of remaining bytes

        // Process full blocks
        for (size_t i = 0; i < blocks; i++) {
            // Generate keystream
            __m128i keystream = aes128_encrypt_block(feedback, round_key);
            // Load current ciphertext block
            __m128i cipher_block = _mm_loadu_si128((const __m128i*)(ciphertext + i * 16));
            // XOR to generate plaintext block
            __m128i plain_block = _mm_xor_si128(cipher_block, keystream);

            // Store plaintext block
            _mm_storeu_si128((__m128i*)(plaintext + i * 16), plain_block);

            // Update feedback register (using current ciphertext)
            feedback = cipher_block;
        }

        // Process partial block
        if (remaining > 0) {
            // Generate partial keystream
            __m128i keystream = aes128_encrypt_block(feedback, round_key);
            const uint8_t* src = ciphertext + blocks * 16;
            uint8_t* dst = plaintext + blocks * 16;

            // Process remaining data byte by byte using XOR
            for (size_t i = 0; i < remaining; i++) {
                dst[i] = src[i] ^ ((uint8_t*)&keystream)[i];
            }
        }
    }
}

#endif