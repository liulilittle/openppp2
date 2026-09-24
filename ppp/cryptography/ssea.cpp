#include <ppp/cryptography/ssea.h>
#include <ppp/diagnostics/Error.h>
#include "ssea_simd/sse_dispatch.h"

/**
 * @file ssea.cpp
 * @brief Implements custom shuffle, delta, Base94, and XOR masking helpers.
 */

// -----------------------------------------------------------------------------
// Constants for Base94 encoding/decoding.
// Base94 uses 94 printable ASCII characters (from 0x20 to 0x7E, excluding '\' for compatibility).
// The ratio 11/9 > log(256)/log(94) ensures that 9 input bytes can be encoded into 11 output chars.
// -----------------------------------------------------------------------------
enum
{
    BASE94_SYMBOL_COUNT = 94,               // Number of symbols in Base94 alphabet
    BASE94_INPUT_BLOCK_SIZE = 9,             // Optimal input block size (bytes)
    BASE94_OUTPUT_BLOCK_SIZE = 11,           // Optimal output block size (characters)
};

namespace ppp
{
    namespace cryptography
    {
        /**
         * @brief Permutes bytes in place using an index/key derived swap strategy.
         * @param encoded_data Mutable target buffer.
         * @param data_size Number of bytes in @p encoded_data.
         * @param key Permutation key.
         */
        // -----------------------------------------------------------------------------
        // Shuffles a character array using a key. This is a deterministic permutation
        // based on XOR of index and key, then modulo size. Used for obfuscation.
        // -----------------------------------------------------------------------------
        // Parameters:
        //   encoded_data - pointer to the data array to shuffle (in-place)
        //   data_size    - number of elements in the array
        //   key          - 32-bit key controlling the permutation
        // -----------------------------------------------------------------------------
        void ssea::shuffle_data(char* encoded_data, int data_size, uint32_t key) noexcept
        {
            ::ssea::ssea_dispatch().shuffle_data(encoded_data, data_size, key);
        }

        /**
         * @brief Reverses @ref shuffle_data using the same key and size.
         * @param encoded_data Mutable target buffer.
         * @param data_size Number of bytes in @p encoded_data.
         * @param key Permutation key originally used for shuffling.
         */
        // -----------------------------------------------------------------------------
        // Reverses the shuffle performed by shuffle_data. Since the shuffle is its own
        // inverse when the loop is run backwards, this restores the original order.
        // -----------------------------------------------------------------------------
        // Parameters:
        //   encoded_data - pointer to the data array to unshuffle (in-place)
        //   data_size    - number of elements in the array
        //   key          - same key used for shuffling
        // -----------------------------------------------------------------------------
        void ssea::unshuffle_data(char* encoded_data, int data_size, uint32_t key) noexcept
        {
            ::ssea::ssea_dispatch().unshuffle_data(encoded_data, data_size, key);
        }

        /**
         * @brief Encodes input bytes as deltas between adjacent elements.
         * @param allocator Buffer allocator used for output storage.
         * @param data Input byte sequence.
         * @param data_size Input length in bytes.
         * @param kf Initial adjustment for the first byte.
         * @param output Receives the allocated output buffer.
         * @return Encoded byte count on success; otherwise 0.
         */
        // -----------------------------------------------------------------------------
        // Delta encoding: transforms a byte sequence into differences between consecutive
        // bytes, with the first byte adjusted by a constant kf. This can reduce entropy
        // for certain data patterns (e.g., smooth signals).
        // -----------------------------------------------------------------------------
        // Parameters:
        //   allocator  - memory allocator for the output buffer
        //   data       - input data bytes
        //   data_size  - number of input bytes
        //   kf         - initial offset for the first byte
        //   output     - (output) shared pointer to the allocated encoded buffer
        // Returns:
        //   Size of the encoded data (same as input size) on success, 0 on failure.
        // -----------------------------------------------------------------------------
        int ssea::delta_encode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int data_size, int kf, std::shared_ptr<Byte>& output) noexcept
        {
            if (NULLPTR == data || data_size < 1)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SseaDeltaEncodeInvalidInput);
                return 0;
            }

            // Try SIMD-accelerated path first; fall back to scalar on failure.
            std::unique_ptr<uint8_t[]> simd_out;
            int simd_len = ::ssea::ssea_dispatch().delta_encode(data, data_size, kf, simd_out);
            if (simd_len > 0 && simd_out)
            {
                output = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, simd_len);
                if (NULLPTR == output)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return 0;
                }
                std::memcpy(output.get(), simd_out.get(), simd_len);
                return simd_len;
            }

            // Allocate output buffer of same size as input
            output = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, data_size);
            if (NULLPTR == output)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return 0;
            }

            Byte* tail = (Byte*)data;
            Byte* endl = tail + data_size;

            Byte* p = output.get();
            // First byte: original first byte minus kf
            *p++ = static_cast<Byte>(*tail++ - kf);

            // Subsequent bytes: current byte minus previous byte
            while (tail != endl)
            {
                *p++ = *tail - *(tail - 1);
                tail++;
            }
            
            return data_size;
        }

        /**
         * @brief Decodes data produced by @ref delta_encode.
         * @param allocator Buffer allocator used for output storage.
         * @param data Delta-encoded byte sequence.
         * @param data_size Input length in bytes.
         * @param kf Initial adjustment used at encode time.
         * @param output Receives the allocated output buffer.
         * @return Decoded byte count on success; otherwise 0.
         */
        // -----------------------------------------------------------------------------
        // Delta decoding: reverses delta_encode by reconstructing the original bytes
        // from the differences.
        // -----------------------------------------------------------------------------
        // Parameters:
        //   allocator  - memory allocator for the output buffer
        //   data       - encoded delta data
        //   data_size  - number of encoded bytes
        //   kf         - initial offset used in encoding
        //   output     - (output) shared pointer to the decoded original buffer
        // Returns:
        //   Size of the decoded data (same as input size) on success, 0 on failure.
        // -----------------------------------------------------------------------------
        int ssea::delta_decode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int data_size, int kf, std::shared_ptr<Byte>& output) noexcept
        {
            if (NULLPTR == data || data_size < 1)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SseaDeltaDecodeInvalidInput);
                return 0;
            }

            // Try SIMD-accelerated path first; fall back to scalar on failure.
            std::unique_ptr<uint8_t[]> simd_out;
            int simd_len = ::ssea::ssea_dispatch().delta_decode(data, data_size, kf, simd_out);
            if (simd_len > 0 && simd_out)
            {
                output = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, simd_len);
                if (NULLPTR == output)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return 0;
                }
                std::memcpy(output.get(), simd_out.get(), simd_len);
                return simd_len;
            }

            output = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, data_size);
            if (NULLPTR == output)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return 0;
            }

            Byte* tail = (Byte*)data;
            Byte* endl = tail + data_size;

            Byte* p = output.get();
            // First byte: encoded first byte plus kf restores original first byte
            *p++ = static_cast<Byte>(*tail++ + kf);

            // Subsequent bytes: current encoded delta plus previous restored byte
            while (tail != endl)
            {
                Byte by = *(p - 1);
                *p++ = by + *tail;
                tail++;
            }

            return data_size;
        }

        /**
         * @brief Encodes binary bytes with the project-specific Base94 mapping.
         * @param allocator Buffer allocator used for output storage.
         * @param data Input bytes.
         * @param datalen Input length in bytes.
         * @param kf Per-byte offset subtracted before mapping.
         * @param outlen Receives encoded output length.
         * @return Managed encoded buffer or NULLPTR on failure.
         */
        // -----------------------------------------------------------------------------
        // Base94 encoding: maps arbitrary binary data to a string of 94 printable ASCII
        // characters (0x20–0x7E). Each input byte is first adjusted by subtracting kf,
        // then if the value is < 93 it becomes one character; if >=93 it is split into
        // two characters (using base-93 as a kind of "overflow" encoding). This is a
        // custom, non‑standard Base94 variant.
        // -----------------------------------------------------------------------------
        // Parameters:
        //   allocator - memory allocator for the output buffer
        //   data      - input binary data
        //   datalen   - number of input bytes
        //   kf        - offset subtracted from each byte before encoding
        //   outlen    - (output) length of the encoded string (in characters)
        // Returns:
        //   Shared pointer to the encoded null‑terminated string (or NULLPTR on error)
        // -----------------------------------------------------------------------------
        std::shared_ptr<Byte> ssea::base94_encode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen, int kf, int& outlen) noexcept
        {
            static constexpr int BASE94_RADIX = BASE94_SYMBOL_COUNT;   // 94
            static constexpr int BASE93_RADIX = BASE94_RADIX - 1;      // 93

            Byte* bytes = (Byte*)data;
            outlen = 0;

            if (NULLPTR == data || datalen < 1)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SseaBase94EncodeInvalidInput);
                return NULLPTR;
            }

            // Try SIMD-accelerated path first; fall back to scalar on failure.
            {
                std::unique_ptr<uint8_t[]> simd_out;
                int simd_len = ::ssea::ssea_dispatch().base94_encode(data, datalen, kf, simd_out);
                if (simd_len > 0 && simd_out)
                {
                    std::shared_ptr<Byte> bucket_managed = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, simd_len);
                    if (NULLPTR != bucket_managed)
                    {
                        std::memcpy(bucket_managed.get(), simd_out.get(), simd_len);
                        outlen = simd_len;
                    }
                    return bucket_managed;
                }
            }

            // Scalar fallback: First pass computes the length, second pass encodes.
            int bucket_length = 0;
            for (int i = 0; i < datalen; i++)
            {
                Byte b = static_cast<Byte>(bytes[i] - kf);
                if (b >= BASE93_RADIX)
                {
                    bucket_length += 2;
                }
                else
                {
                    bucket_length++;
                }
            }

            std::shared_ptr<Byte> bucket_managed = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, bucket_length);
            if (NULLPTR != bucket_managed)
            {
                Byte* bucket = bucket_managed.get();
                for (int i = 0; i < datalen; i++)
                {
                    Byte b = static_cast<Byte>(bytes[i] - kf);
                    if (b >= BASE93_RADIX)
                    {
                        *bucket++ = '\x20' + (((b / BASE93_RADIX) - 1) + BASE93_RADIX);
                        *bucket++ = '\x20' + (b % BASE93_RADIX);
                    }
                    else
                    {
                        *bucket++ = '\x20' + b;
                    }
                }

                outlen = bucket_length;
            }

            return bucket_managed;
        }

        /**
         * @brief Decodes bytes generated by @ref base94_encode.
         * @param allocator Buffer allocator used for output storage.
         * @param data Encoded Base94 byte sequence.
         * @param datalen Input length in bytes.
         * @param kf Per-byte offset added after decoding.
         * @param outlen Receives decoded byte count.
         * @return Managed decoded buffer or NULLPTR on failure.
         */
        // -----------------------------------------------------------------------------
        // Base94 decoding: reverses base94_encode. It validates that all characters are
        // in the printable range (>=0x20) and that the encoding is consistent.
        // -----------------------------------------------------------------------------
        // Parameters:
        //   allocator - memory allocator for the output buffer
        //   data      - input Base94 string (bytes, not necessarily null‑terminated)
        //   datalen   - number of characters in the string
        //   kf        - offset added back to each decoded byte
        //   outlen    - (output) length of the decoded binary data
        // Returns:
        //   Shared pointer to the decoded binary data (or NULLPTR on error)
        // -----------------------------------------------------------------------------
        std::shared_ptr<Byte> ssea::base94_decode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen, int kf, int& outlen) noexcept
        {
            static constexpr int BASE94_RADIX = BASE94_SYMBOL_COUNT;   // 94
            static constexpr int BASE93_RADIX = BASE94_RADIX - 1;      // 93

            Byte* bytes = (Byte*)data;
            outlen = 0;

            if (NULLPTR == data || datalen < 1)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SseaBase94DecodeInvalidInput);
                return NULLPTR;
            }

            // Try SIMD-accelerated path first; fall back to scalar on failure.
            // SIMD decode validates input internally and returns 0 on any error,
            // so the scalar fallback below preserves the detailed error codes.
            {
                std::unique_ptr<uint8_t[]> simd_out;
                int simd_len = ::ssea::ssea_dispatch().base94_decode(data, datalen, kf, simd_out);
                if (simd_len > 0 && simd_out)
                {
                    std::shared_ptr<Byte> bucket_managed = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, simd_len);
                    if (NULLPTR != bucket_managed)
                    {
                        std::memcpy(bucket_managed.get(), simd_out.get(), simd_len);
                        outlen = simd_len;
                    }
                    return bucket_managed;
                }
            }

            // Scalar fallback with detailed error codes: validate input and compute output length.
            int bucket_length = datalen;
            for (int i = 0; i < datalen; i++)
            {
                Byte b = bytes[i];
                if (b < '\x20')
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SseaBase94DecodeCharBelowPrintable);
                    return NULLPTR;   // Character below printable range
                }

                b -= '\x20';
                if (b > BASE94_RADIX)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SseaBase94DecodeCharOutOfAlphabet);
                    return NULLPTR;   // Character beyond the 94 symbols
                }

                if (b >= BASE93_RADIX)
                {
                    // This is a two-character escape; need to check next character exists.
                    if (++i < datalen)
                    {
                        b = bytes[i];
                        if (b < '\x20')
                        {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SseaBase94DecodeEscapeCharBelowPrintable);
                            return NULLPTR;
                        }

                        b -= '\x20';
                        if (b > BASE93_RADIX)
                        {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SseaBase94DecodeEscapeCharOutOfRange);
                            return NULLPTR;
                        }
                    }
                    else
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SseaBase94DecodeTruncatedEscape);
                        return NULLPTR;   // Unexpected end of string
                    }

                    // Two characters decode to one byte, so output length decreases by 1
                    bucket_length--;
                }
            }

            // Allocate output buffer
            std::shared_ptr<Byte> bucket_managed = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, bucket_length);
            if (NULLPTR != bucket_managed)
            {
                Byte* bucket = bucket_managed.get();
                for (int i = 0; i < datalen; i++)
                {
                    Byte b = bytes[i] - '\x20';
                    if (b >= BASE93_RADIX)
                    {
                        // Reconstruct the original byte: ((b - 93) + 1) * 93 + next_char
                        int v = (((b - BASE93_RADIX) + 1) * BASE93_RADIX) + (bytes[++i] - '\x20');
                        if (v > 0xff)
                        {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SseaBase94DecodeValueOverflow);
                            return NULLPTR;   // Decoded value out of byte range
                        }

                        *bucket++ = static_cast<Byte>(v + kf);
                    }
                    else
                    {
                        *bucket++ = static_cast<Byte>(b + kf);
                    }
                }

                outlen = bucket_length;
            }
            return bucket_managed;
        }
        
        /**
         * @brief Decodes a Base94 string to an unsigned integer.
         * @param v Base94 text.
         * @return Parsed integer value, or 0 for invalid input.
         */
        // -----------------------------------------------------------------------------
        // Converts a Base94 string (std::string) into its numeric (uint64_t) value.
        // Useful for compact representation of small integers.
        // -----------------------------------------------------------------------------
        // Parameters:
        //   v - Base94 encoded string
        // Returns:
        //   Decoded integer, or 0 if invalid.
        // -----------------------------------------------------------------------------
        uint64_t ssea::base94_decimal(const ppp::string& v) noexcept
        {
            return base94_decimal(v.data(), v.size());
        }

        /**
         * @brief Decodes Base94 bytes to an unsigned integer.
         * @param data Base94 byte sequence.
         * @param datalen Number of bytes in @p data.
         * @return Parsed integer value, or 0 for invalid input.
         */
        // -----------------------------------------------------------------------------
        // Converts a Base94 string (raw data) into a uint64_t.
        // -----------------------------------------------------------------------------
        // Parameters:
        //   data    - pointer to the Base94 characters
        //   datalen - number of characters
        // Returns:
        //   Decoded integer, or 0 on error (invalid characters or overflow).
        // -----------------------------------------------------------------------------
        uint64_t ssea::base94_decimal(const void* data, int datalen) noexcept
        {
            uint8_t* p = (uint8_t*)data;
            if (NULLPTR == p || datalen < 1)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SseaBase94DecimalInvalidInput);
                return 0;
            }

            uint64_t n = 0;
            for (uint8_t* k = p + datalen; p != k; )
            {
                uint8_t b = *p++;
                if (b < '\x20')
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SseaBase94DecimalCharBelowPrintable);
                    return 0;
                }

                b -= '\x20';
                if (b >= BASE94_SYMBOL_COUNT)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SseaBase94DecimalCharOutOfAlphabet);
                    return 0;
                }

                n = n * BASE94_SYMBOL_COUNT + b;
            }
            return n;
        }

        /**
         * @brief Encodes an unsigned integer as Base94 text.
         * @param v Integer value.
         * @return Minimal-length Base94 representation.
         */
        // -----------------------------------------------------------------------------
        // Converts a uint64_t into its Base94 string representation.
        // The result uses the minimum number of characters.
        // -----------------------------------------------------------------------------
        // Parameters:
        //   v - integer to encode
        // Returns:
        //   Base94 string (without null terminator)
        // -----------------------------------------------------------------------------
        ppp::string ssea::base94_decimal(uint64_t v) noexcept
        {
            int base94_size = 0;
            uint8_t base94[BASE94_OUTPUT_BLOCK_SIZE];  // Max size for 64-bit is 11 (since 94^11 > 2^64)
            {
                uint64_t n = v;
                // Compute number of digits
                do
                {
                    n /= BASE94_SYMBOL_COUNT;
                    base94_size++;
                } while (n > 0);

                int k = 0;
                n = v;
                // Fill digits from least significant to most, then reverse
                do
                {
                    uint8_t c = (n % BASE94_SYMBOL_COUNT) + '\x20';
                    n /= BASE94_SYMBOL_COUNT;
                    base94[(base94_size)-(++k)] = c;   // Store in reverse order
                } while (n > 0);
            }

            return ppp::string(reinterpret_cast<char*>(base94), base94_size);
        }

        /**
         * @brief Produces a pseudo-random 31-bit integer and advances the seed.
         * @param seed Seed pointer modified in place.
         * @return Generated pseudo-random value.
         */
        // -----------------------------------------------------------------------------
        // Simple pseudo‑random number generator (linear congruential).
        // Generates a 31‑bit random integer (0..0x7FFFFFFF) and updates the seed.
        // -----------------------------------------------------------------------------
        // Parameters:
        //   seed - pointer to the seed value (modified in place)
        // Returns:
        //   A pseudo‑random integer.
        // -----------------------------------------------------------------------------
        int ssea::random_next(unsigned int* seed) noexcept /* volatile */
        {
            unsigned int next = *seed;
            int result;

            // Three LCG steps to produce a 31‑bit result
            next *= 1103515245;
            next += 12345;
            result = (unsigned int)(next / 65536) % 2048;

            next *= 1103515245;
            next += 12345;
            result <<= 10;
            result ^= (unsigned int)(next / 65536) % 1024;

            next *= 1103515245;
            next += 12345;
            result <<= 10;
            result ^= (unsigned int)(next / 65536) % 1024;

            *seed = next;
            return result;
        }

        /**
         * @brief Produces a pseudo-random integer in the inclusive range [min, max].
         * @param seed Seed pointer modified in place.
         * @param min Lower inclusive bound.
         * @param max Upper inclusive bound.
         * @return Generated pseudo-random value inside the requested range.
         */
        // -----------------------------------------------------------------------------
        // Returns a random integer in the range [min, max] (inclusive).
        // -----------------------------------------------------------------------------
        // Parameters:
        //   seed - pointer to the seed value
        //   min  - lower bound
        //   max  - upper bound
        // Returns:
        //   Random integer within the range.
        // -----------------------------------------------------------------------------
        int ssea::random_next(unsigned int* seed, int min, int max) noexcept 
        {
            int v = random_next(seed);
            return v % (max - min + 1) + min;
        }

        /**
         * @brief Shared implementation for fixed-key and evolving-key XOR masking.
         * @tparam kf_random_next When true, updates the key between chunks.
         * @param min Inclusive start address.
         * @param max Exclusive end address.
         * @param kf Initial XOR key.
         * @return True when the range is valid and processed; otherwise false.
         */
        // -----------------------------------------------------------------------------
        // Internal template implementing masked XOR over a memory region.
        // The template parameter controls whether the key (kf) is updated after each
        // operation using random_next.
        // -----------------------------------------------------------------------------
        // Parameters:
        //   min - start of memory region (inclusive)
        //   max - end of memory region (exclusive, i.e., one past last byte)
        //   kf  - initial XOR key
        // Returns:
        //   true on success, false if region is invalid (e.g., length negative)
        // -----------------------------------------------------------------------------
        template <bool kf_random_next>
        static bool masked_xor_implement(const void* min, const void* max, int32_t kf) noexcept
        {
            int length = (uint8_t*)max - (uint8_t*)min;
            if (length == 0) 
            {
                return true;
            }

            if (length < 0) 
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SseaMaskedXorInvalidRange);
                return false;
            }

            /** @details Processes full 32-bit words before tail bytes for speed. */
            int count     = length >> 2;          // number of full 32-bit words
            int remainder = length & 3;            // remaining bytes (0..3)

            if constexpr (kf_random_next)
            {
                // If requested, update kf using random_next before processing
                kf = ssea::random_next((unsigned int*)&kf);
            }

            int32_t* p32 = (int32_t*)min;
            // Process 32-bit words
            for (int i = 0; i < count; i++)
            {
                *p32 = *p32 ^ kf;
                p32++;

                if constexpr (kf_random_next)
                {
                    kf = ssea::random_next((unsigned int*)&kf);
                }
            }

            int16_t* p16 = (int16_t*)p32;
            // Process the next 16 bits if remainder >=2
            if (remainder >> 1)
            {
                *p16 = (int16_t)(*p16 ^ kf);
                p16++;

                if constexpr (kf_random_next)
                {
                    kf = ssea::random_next((unsigned int*)&kf);
                }
            }

            int8_t* p8 = (int8_t*)p16;
            // Process the last byte if remainder is odd
            if (remainder & 1) 
            {
                *p8 = (int8_t)(*p8 ^ kf);
            }

            return true;
        }

        /**
         * @brief Applies a fixed XOR key to a mutable memory range.
         * @param min Inclusive start address.
         * @param max Exclusive end address.
         * @param kf Fixed XOR key.
         * @return True on success; false for invalid ranges.
         */
        // -----------------------------------------------------------------------------
        // Applies a fixed XOR mask (kf) to a memory region. The region is processed in
        // 32‑bit, 16‑bit, and 8‑bit chunks for efficiency. This is a simple obfuscation.
        // -----------------------------------------------------------------------------
        // Parameters:
        //   min - start of memory region
        //   max - end of memory region (exclusive)
        //   kf  - 32‑bit XOR key (same for all chunks)
        // Returns:
        //   true on success
        // -----------------------------------------------------------------------------
        bool ssea::masked_xor(const void* min, const void* max, int32_t kf) noexcept
        {
            if (::ssea::ssea_dispatch().masked_xor(min, max, kf))
            {
                return true;
            }
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SseaMaskedXorInvalidRange);
            return false;
        }

        /**
         * @brief Applies XOR masking with a key updated between processed chunks.
         * @param min Inclusive start address.
         * @param max Exclusive end address.
         * @param kf Initial XOR key.
         * @return True on success; false for invalid ranges.
         */
        // -----------------------------------------------------------------------------
        // Applies a XOR mask that changes after each chunk using random_next.
        // The key evolves as the region is processed, increasing obfuscation.
        // -----------------------------------------------------------------------------
        // Parameters:
        //   min - start of memory region
        //   max - end of memory region (exclusive)
        //   kf  - initial key; after each chunk it is updated by random_next
        // Returns:
        //   true on success
        // -----------------------------------------------------------------------------
        bool ssea::masked_xor_random_next(const void* min, const void* max, int32_t kf) noexcept
        {
            if (::ssea::ssea_dispatch().masked_xor_random_next(min, max, kf))
            {
                return true;
            }
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SseaMaskedXorInvalidRange);
            return false;
        }
    }
}
