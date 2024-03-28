#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#include "EVP.h"
#include "digest.h"

namespace ppp {
    namespace cryptography {
        typedef unsigned char* (*SHA_PROC)(const unsigned char*, size_t, unsigned char*);

        static SHA_PROC sha_proc_table[] = {
            SHA1,
            SHA224,
            SHA256,
            SHA384,
            SHA512,
        };

        static size_t sha_len_table[] = {
            SHA_DIGEST_LENGTH,
            SHA224_DIGEST_LENGTH,
            SHA256_DIGEST_LENGTH,
            SHA384_DIGEST_LENGTH,
            SHA512_DIGEST_LENGTH,
        };

        ppp::string hash_hmac(const void* data, int size, DigestAlgorithmic agorithm, bool toupper) noexcept {
            return hash_hmac(data, size, agorithm, true, toupper);
        }

        ppp::string hash_hmac(const void* data, int size, DigestAlgorithmic agorithm, bool hex_or_binarys, bool toupper) noexcept {
            ppp::string digest;
            hash_hmac(data, size, digest, agorithm, hex_or_binarys, toupper);
            return digest;
        }

        bool hash_hmac(const void* data, int size, ppp::string& digest, DigestAlgorithmic agorithm, bool hex_or_binarys, bool toupper) noexcept {
            if (NULL == data || size < 1) {
                data = "";
                size = 0;
            }

            if (agorithm == DigestAlgorithmic_md5) {
                if (hex_or_binarys) {
                    digest = ComputeMD5(ppp::string((char*)data, size), toupper);
                }
                else {
                    Byte md5[16];
                    int md5len;
                    if (!ComputeMD5(ppp::string((char*)data, size), md5, md5len)) {
                        return false;
                    }
                    else {
                        digest = ppp::string((char*)md5, md5len);
                    }
                }
                return true;
            }

            if (agorithm < DigestAlgorithmic_sha1 || agorithm > DigestAlgorithmic_sha512) {
                return false;
            }

            unsigned char digest_sz[SHA512_DIGEST_LENGTH];
            size_t digest_sz_len = sha_len_table[(int)agorithm];

            SHA_PROC sha_proc = sha_proc_table[(int)agorithm];
            sha_proc((unsigned char*)data, size, digest_sz);

            if (!hex_or_binarys) {
                digest = ppp::string((char*)digest_sz, digest_sz_len);
            }
            else {
                char hex_sz[SHA512_DIGEST_LENGTH * 2];
                const char* hex_fmt = toupper ? "%02X" : "02x";
                for (size_t i = 0; i < digest_sz_len; i++) {
                    int ch = digest_sz[i];
                    sprintf(hex_sz + (i * 2), hex_fmt, ch);
                }

                digest = ppp::string(hex_sz, digest_sz_len * 2);
            }
            return true;
        }
    }
}