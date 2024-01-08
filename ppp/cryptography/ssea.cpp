#include <ppp/cryptography/ssea.h>

/* 96 printable characters(include tab)  */
/* remove \ for compatibility            */
/* remove tab for uniformity             */
/* luckly, 11/9 > log(256)/log(94)       */

enum
{
    BASE94_SYMBOL_COUNT = 94,
    BASE94_INPUT_BLOCK_SIZE = 9,
    BASE94_OUTPUT_BLOCK_SIZE = 11,
};

namespace ppp
{
    namespace cryptography
    {
        void ssea::shuffle_data(char* encoded_data, int data_size, int key) noexcept
        {
            if (NULL != encoded_data && data_size > 0)
            {
                for (int i = 0; i < data_size; i++)
                {
                    int j = ((i ^ key) % data_size);
                    std::swap(encoded_data[i], encoded_data[j]);
                }
            }
        }

        void ssea::unshuffle_data(char* encoded_data, int data_size, int key) noexcept
        {
            if (NULL != encoded_data && data_size > 0)
            {
                for (int i = data_size - 1; i > -1; i--)
                {
                    int j = ((i ^ key) % data_size);
                    std::swap(encoded_data[i], encoded_data[j]);
                }
            }
        }

        int ssea::delta_encode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int data_size, std::shared_ptr<Byte>& output) noexcept
        {
            if (NULL == data || data_size < 1)
            {
                return 0;
            }

            output = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, data_size);
            if (NULL == output)
            {
                return 0;
            }

            Byte* tail = (Byte*)data;
            Byte* endl = tail + data_size;

            Byte* p = output.get();
            *p++ = *tail++;
            while (tail != endl)
            {
                *p++ = *tail - *(tail - 1);
                tail++;
            }
            return data_size;
        }

        int ssea::delta_decode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int data_size, std::shared_ptr<Byte>& output) noexcept
        {
            if (NULL == data || data_size < 1)
            {
                return 0;
            }

            output = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, data_size);
            if (NULL == output)
            {
                return 0;
            }

            Byte* tail = (Byte*)data;
            Byte* endl = tail + data_size;

            Byte* p = output.get();
            *p++ = *tail++;
            while (tail != endl)
            {
                *p++ = *(p - 1) + *tail;
                tail++;
            }
            return data_size;
        }

        std::shared_ptr<Byte> ssea::base94_encode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen, int& outlen) noexcept
        {
            static constexpr int BASE94_RADIX = BASE94_SYMBOL_COUNT;
            static constexpr int BASE93_RADIX = BASE94_RADIX - 1;

            Byte* bytes = (Byte*)data;
            outlen = 0;

            if (NULL == data || datalen < 1)
            {
                return NULL;
            }

            int bucket_length = 0;
            for (int i = 0; i < datalen; i++)
            {
                if (bytes[i] >= BASE93_RADIX)
                {
                    bucket_length += 2;
                }
                else
                {
                    bucket_length++;
                }
            }

            std::shared_ptr<Byte> bucket_managed = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, bucket_length);
            if (NULL != bucket_managed)
            {
                Byte* bucket = bucket_managed.get();
                for (int i = 0; i < datalen; i++)
                {
                    Byte b = bytes[i];
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

        std::shared_ptr<Byte> ssea::base94_decode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen, int& outlen) noexcept
        {
            static constexpr int BASE94_RADIX = BASE94_SYMBOL_COUNT;
            static constexpr int BASE93_RADIX = BASE94_RADIX - 1;

            Byte* bytes = (Byte*)data;
            outlen = 0;

            if (NULL == data || datalen < 1)
            {
                return NULL;
            }

            int bucket_length = datalen;
            for (int i = 0; i < datalen; i++)
            {
                Byte b = bytes[i];
                if (b < '\x20')
                {
                    return NULL;
                }

                b -= '\x20';
                if (b > BASE94_RADIX)
                {
                    return NULL;
                }

                if (b >= BASE93_RADIX)
                {
                    if (++i < datalen)
                    {
                        b = bytes[i];
                        if (b < '\x20')
                        {
                            return NULL;
                        }

                        b -= '\x20';
                        if (b > BASE93_RADIX)
                        {
                            return NULL;
                        }
                    }
                    else
                    {
                        return NULL;
                    }

                    bucket_length--;
                }
            }

            std::shared_ptr<Byte> bucket_managed = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, bucket_length);
            if (NULL != bucket_managed)
            {
                Byte* bucket = bucket_managed.get();
                for (int i = 0; i < datalen; i++)
                {
                    Byte b = bytes[i] - '\x20';
                    if (b >= BASE93_RADIX)
                    {
                        int v = (((b - BASE93_RADIX) + 1) * BASE93_RADIX) + (bytes[++i] - '\x20');
                        if (v > 0xff)
                        {
                            return NULL;
                        }

                        *bucket++ = v;
                    }
                    else
                    {
                        *bucket++ = b;
                    }
                }

                outlen = bucket_length;
            }
            return bucket_managed;
        }

        uint64_t ssea::base94_decimal(const ppp::string& v) noexcept
        {
            return base94_decimal(v.data(), v.size());
        }

        uint64_t ssea::base94_decimal(const void* data, int datalen) noexcept
        {
            uint8_t* p = (uint8_t*)data;
            if (NULL == p || datalen < 1)
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
                if (b > BASE94_SYMBOL_COUNT)
                {
                    return 0;
                }

                n = n * BASE94_SYMBOL_COUNT + b;
            }
            return n;
        }

        ppp::string ssea::base94_decimal(uint64_t v) noexcept
        {
            int base94_size = 0;
            uint8_t base94[BASE94_OUTPUT_BLOCK_SIZE];
            {
                uint64_t n = v;
                do
                {
                    n /= BASE94_SYMBOL_COUNT;
                    base94_size++;
                } while (n > 0);

                int k = 0;
                n = v;
                do
                {
                    uint8_t c = (n % BASE94_SYMBOL_COUNT) + '\x20';
                    n /= BASE94_SYMBOL_COUNT;
                    base94[(base94_size)-(++k)] = c;
                } while (n > 0);
            }

            return ppp::string(reinterpret_cast<char*>(base94), base94_size);
        }
    }
}