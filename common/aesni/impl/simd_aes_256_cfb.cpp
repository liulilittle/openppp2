#include <common/aesni/aes.h>

#if defined(__AES_NI_IMPL__)

#include <wmmintrin.h>   // AES instruction set
#include <emmintrin.h>   // SSE2 instruction set
#include <algorithm>
#include <string.h>
#include <iostream>

namespace aesni {
    // AES-256 Key Expansion (generates 14 round keys)
    void aes256_cfb_key_expansion(const uint8_t* key, __m128i* round_key) noexcept {
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

    // CFB decryption's AES inputs are known from the ciphertext: block i uses
    // the IV for i=0 and ciphertext[i-1] otherwise. Encrypt four independent
    // feedback blocks in an interleaved schedule to hide AESENC latency.
    static inline void aes256_encrypt_blocks4(__m128i& b0, __m128i& b1,
        __m128i& b2, __m128i& b3, const __m128i* round_key) noexcept {
        b0 = _mm_xor_si128(b0, round_key[0]);
        b1 = _mm_xor_si128(b1, round_key[0]);
        b2 = _mm_xor_si128(b2, round_key[0]);
        b3 = _mm_xor_si128(b3, round_key[0]);
#define AES256_ENC_ROUND4(n) \
        b0 = _mm_aesenc_si128(b0, round_key[n]); \
        b1 = _mm_aesenc_si128(b1, round_key[n]); \
        b2 = _mm_aesenc_si128(b2, round_key[n]); \
        b3 = _mm_aesenc_si128(b3, round_key[n])
        AES256_ENC_ROUND4(1);
        AES256_ENC_ROUND4(2);
        AES256_ENC_ROUND4(3);
        AES256_ENC_ROUND4(4);
        AES256_ENC_ROUND4(5);
        AES256_ENC_ROUND4(6);
        AES256_ENC_ROUND4(7);
        AES256_ENC_ROUND4(8);
        AES256_ENC_ROUND4(9);
        AES256_ENC_ROUND4(10);
        AES256_ENC_ROUND4(11);
        AES256_ENC_ROUND4(12);
        AES256_ENC_ROUND4(13);
#undef AES256_ENC_ROUND4
        b0 = _mm_aesenclast_si128(b0, round_key[14]);
        b1 = _mm_aesenclast_si128(b1, round_key[14]);
        b2 = _mm_aesenclast_si128(b2, round_key[14]);
        b3 = _mm_aesenclast_si128(b3, round_key[14]);
    }

    // AES-256-CFB Encryption
    void aes256_cfb_encrypt(uint8_t* ciphertext, const uint8_t* plaintext, size_t len, const uint8_t* iv, const __m128i* round_key) noexcept {
        __m128i feedback = _mm_loadu_si128((const __m128i*)iv); // Initialize feedback register
        size_t blocks = len / 16;    // Number of full blocks
        size_t remaining = len % 16; // Remaining bytes

        // Process full blocks
        for (size_t i = 0; i < blocks; i++) {
            // Generate keystream
            __m128i keystream = aes256_encrypt_block(feedback, round_key);
            // Load current plaintext block
            __m128i plain_block = _mm_loadu_si128((const __m128i*)(plaintext + i * 16));
            // XOR to produce ciphertext block
            __m128i cipher_block = _mm_xor_si128(plain_block, keystream);

            // Store ciphertext block
            _mm_storeu_si128((__m128i*)(ciphertext + i * 16), cipher_block);

            // Update feedback register (use newly generated ciphertext)
            feedback = cipher_block;
        }

        // Process partial block
        if (remaining > 0) {
            // Generate partial keystream
            __m128i keystream = aes256_encrypt_block(feedback, round_key);
            const uint8_t* src = plaintext + blocks * 16;
            uint8_t* dst = ciphertext + blocks * 16;

            // Process remaining data byte-by-byte with XOR
            for (size_t i = 0; i < remaining; i++) {
                dst[i] = src[i] ^ ((uint8_t*)&keystream)[i];
            }
        }
    }

    // AES-256-CFB Decryption
    void aes256_cfb_decrypt(uint8_t* plaintext, const uint8_t* ciphertext, size_t len, const uint8_t* iv, const __m128i* round_key) noexcept {
        __m128i feedback = _mm_loadu_si128((const __m128i*)iv); // Initialize feedback register
        size_t blocks = len / 16;    // Number of full blocks
        size_t remaining = len % 16; // Remaining bytes

        // CFB decryption blocks are parallelizable because each AES input is
        // the previous ciphertext block, not the previous plaintext output.
        size_t i = 0;
        for (; i + 4 <= blocks; i += 4) {
            const __m128i c0 = _mm_loadu_si128((const __m128i*)(ciphertext + (i + 0) * 16));
            const __m128i c1 = _mm_loadu_si128((const __m128i*)(ciphertext + (i + 1) * 16));
            const __m128i c2 = _mm_loadu_si128((const __m128i*)(ciphertext + (i + 2) * 16));
            const __m128i c3 = _mm_loadu_si128((const __m128i*)(ciphertext + (i + 3) * 16));
            __m128i b0 = feedback;
            __m128i b1 = c0;
            __m128i b2 = c1;
            __m128i b3 = c2;
            aes256_encrypt_blocks4(b0, b1, b2, b3, round_key);
            _mm_storeu_si128((__m128i*)(plaintext + (i + 0) * 16), _mm_xor_si128(c0, b0));
            _mm_storeu_si128((__m128i*)(plaintext + (i + 1) * 16), _mm_xor_si128(c1, b1));
            _mm_storeu_si128((__m128i*)(plaintext + (i + 2) * 16), _mm_xor_si128(c2, b2));
            _mm_storeu_si128((__m128i*)(plaintext + (i + 3) * 16), _mm_xor_si128(c3, b3));
            feedback = c3;
        }

        // Process remaining full blocks with the simple scalar fallback.
        for (; i < blocks; i++) {
            // Generate keystream
            __m128i keystream = aes256_encrypt_block(feedback, round_key);
            // Load current ciphertext block
            __m128i cipher_block = _mm_loadu_si128((const __m128i*)(ciphertext + i * 16));
            // XOR to produce plaintext block
            __m128i plain_block = _mm_xor_si128(cipher_block, keystream);

            // Store plaintext block
            _mm_storeu_si128((__m128i*)(plaintext + i * 16), plain_block);

            // Update feedback register (use current ciphertext)
            feedback = cipher_block;
        }

        // Process partial block
        if (remaining > 0) {
            // Generate partial keystream
            __m128i keystream = aes256_encrypt_block(feedback, round_key);
            const uint8_t* src = ciphertext + blocks * 16;
            uint8_t* dst = plaintext + blocks * 16;

            // Process remaining data byte-by-byte with XOR
            for (size_t i = 0; i < remaining; i++) {
                dst[i] = src[i] ^ ((uint8_t*)&keystream)[i];
            }
        }
    }
}

#endif
