#include <ppp/cryptography/ssea.h>

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
            if (NULLPTR != encoded_data && data_size > 0)
            {
                // Iterate through the array; for each position i, swap with position j
                for (int i = 0; i < data_size; i++)
                {
                    uint32_t p = (uint32_t)i;
                    // Compute swap index: (i XOR key) modulo data_size
                    uint32_t j = (uint32_t)((p ^ key) % data_size);
                    std::swap(encoded_data[i], encoded_data[j]);
                }
            }
        }

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
            if (NULLPTR != encoded_data && data_size > 0)
            {
                // Iterate backwards to undo the swaps
                for (int i = data_size - 1; i > -1; i--)
                {
                    uint32_t p = (uint32_t)i;
                    uint32_t j = (uint32_t)((p ^ key) % data_size);
                    std::swap(encoded_data[i], encoded_data[j]);
                }
            }
        }

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
                return 0;
            }

            // Allocate output buffer of same size as input
            output = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, data_size);
            if (NULLPTR == output)
            {
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
                return 0;
            }

            output = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, data_size);
            if (NULLPTR == output)
            {
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
        //   Shared pointer to the encoded null‑terminated string (or nullptr on error)
        // -----------------------------------------------------------------------------
        std::shared_ptr<Byte> ssea::base94_encode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen, int kf, int& outlen) noexcept
        {
            static constexpr int BASE94_RADIX = BASE94_SYMBOL_COUNT;   // 94
            static constexpr int BASE93_RADIX = BASE94_RADIX - 1;      // 93

            Byte* bytes = (Byte*)data;
            outlen = 0;

            if (NULLPTR == data || datalen < 1)
            {
                return NULLPTR;
            }

            // First pass: compute the length of the encoded string.
            // We avoid writing to output yet to keep CPU cache friendly (read‑only input).
            int bucket_length = 0;
            for (int i = 0; i < datalen; i++)
            {
                Byte b = static_cast<Byte>(bytes[i] - kf);
                if (b >= BASE93_RADIX)
                {
                    // Values >=93 require two characters
                    bucket_length += 2;
                }
                else
                {
                    bucket_length++;
                }
            }

            // Allocate buffer for the encoded string
            std::shared_ptr<Byte> bucket_managed = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, bucket_length);
            if (NULLPTR != bucket_managed)
            {
                Byte* bucket = bucket_managed.get();
                for (int i = 0; i < datalen; i++)
                {
                    Byte b = static_cast<Byte>(bytes[i] - kf);
                    if (b >= BASE93_RADIX)
                    {
                        // Encode as two characters: first character = 0x20 + ((b/93)-1 + 93)
                        // Note: b/93 is at least 1 (since b>=93), so subtract 1 to map to 0..? then add 93 to push into upper range.
                        *bucket++ = '\x20' + (((b / BASE93_RADIX) - 1) + BASE93_RADIX);
                        // Second character = 0x20 + (b % 93)
                        *bucket++ = '\x20' + (b % BASE93_RADIX);
                    }
                    else
                    {
                        // Single character = 0x20 + b
                        *bucket++ = '\x20' + b;
                    }
                }

                outlen = bucket_length;
            }

            return bucket_managed;
        }

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
        //   Shared pointer to the decoded binary data (or nullptr on error)
        // -----------------------------------------------------------------------------
        std::shared_ptr<Byte> ssea::base94_decode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen, int kf, int& outlen) noexcept
        {
            static constexpr int BASE94_RADIX = BASE94_SYMBOL_COUNT;   // 94
            static constexpr int BASE93_RADIX = BASE94_RADIX - 1;      // 93

            Byte* bytes = (Byte*)data;
            outlen = 0;

            if (NULLPTR == data || datalen < 1)
            {
                return NULLPTR;
            }

            // First pass: validate input and compute output length.
            int bucket_length = datalen;
            for (int i = 0; i < datalen; i++)
            {
                Byte b = bytes[i];
                if (b < '\x20')
                {
                    return NULLPTR;   // Character below printable range
                }

                b -= '\x20';
                if (b > BASE94_RADIX)
                {
                    return NULLPTR;   // Character beyond the 94 symbols
                }

                if (b >= BASE93_RADIX)
                {
                    // This is a two‑character escape; need to check next character exists.
                    if (++i < datalen)
                    {
                        b = bytes[i];
                        if (b < '\x20')
                        {
                            return NULLPTR;
                        }

                        b -= '\x20';
                        if (b > BASE93_RADIX)
                        {
                            return NULLPTR;
                        }
                    }
                    else
                    {
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
                return 0;
            }

            uint64_t n = 0;
            for (uint8_t* k = p + datalen; p != k; )
            {
                uint8_t b = *p++;
                if (b < '\x20')
                {
                    return 0;
                }

                b -= '\x20';
                if (b >= BASE94_SYMBOL_COUNT)
                {
                    return 0;
                }

                n = n * BASE94_SYMBOL_COUNT + b;
            }
            return n;
        }

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
                return false;
            }

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
            return masked_xor_implement<false>(min, max, kf);
        }

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
            return masked_xor_implement<true>(min, max, kf);
        }
    }
}