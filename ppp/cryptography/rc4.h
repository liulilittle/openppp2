#pragma once

#include <ppp/stdafx.h>
#include <ppp/cryptography/digest.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace cryptography {
        bool                                                                    rc4_sbox_impl(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen, bool ascending) noexcept;

        bool                                                                    rc4_sbox(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen) noexcept;

        bool                                                                    rc4_sbox_descending(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen) noexcept;

        bool                                                                    rc4_crypt_sbox(unsigned char* key, int keylen, unsigned char* sbox, int sboxlen, unsigned char* data, int datalen, int subtract, int E) noexcept;

        bool                                                                    rc4_crypt_sbox_c(unsigned char* key, int keylen, unsigned char* sbox, int sboxlen, unsigned char* data, int datalen, int subtract, int E) noexcept;

        bool                                                                    rc4_crypt(unsigned char* key, int keylen, unsigned char* data, int datalen, int subtract, int E) noexcept;

        class RC4 : public std::enable_shared_from_this<RC4> {
        public:
            RC4(const ppp::string& method, const ppp::string& password, int algorithm, int ascending, int subtract, int E) noexcept;

        public:
            std::shared_ptr<Byte>                                               Encrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept;
            std::shared_ptr<Byte>                                               Decrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept;
            std::shared_ptr<RC4>                                                GetReference() noexcept { return this->shared_from_this(); }
            static bool                                                         Support(const ppp::string& method) noexcept;
            static std::shared_ptr<RC4>                                         Create(const ppp::string& method, const ppp::string& password) noexcept;

        private:
            int                                                                 _E        = 0;
            int                                                                 _subtract = 0;
            ppp::string                                                         _method;
            ppp::string                                                         _password;
            std::shared_ptr<Byte>                                               _sbox;
        };

#define PPP_CRYPTOGRAPHY_RC4_DERIVE(DERIVE_CLASS_NAME, DIGEST_ALGORITHM)        \
        class DERIVE_CLASS_NAME : public RC4 {                                  \
        public:                                                                 \
            DERIVE_CLASS_NAME(const ppp::string& method,                        \
                const ppp::string&               password,                      \
                int                              ascending,                     \
                int                              subtract,                      \
                int                              E) noexcept :                  \
            RC4(method, password, DIGEST_ALGORITHM, ascending, subtract, E) {}  \
            DERIVE_CLASS_NAME(const ppp::string& method,                        \
                const ppp::string&               password) noexcept :           \
            DERIVE_CLASS_NAME(method, password, false, 0, 0) {}                 \
        };

        PPP_CRYPTOGRAPHY_RC4_DERIVE(RC4MD5,    DigestAlgorithmic_md5);
        PPP_CRYPTOGRAPHY_RC4_DERIVE(RC4SHA1,   DigestAlgorithmic_sha1);
        PPP_CRYPTOGRAPHY_RC4_DERIVE(RC4SHA224, DigestAlgorithmic_sha224);
        PPP_CRYPTOGRAPHY_RC4_DERIVE(RC4SHA256, DigestAlgorithmic_sha256);
        PPP_CRYPTOGRAPHY_RC4_DERIVE(RC4SHA386, DigestAlgorithmic_sha386);
        PPP_CRYPTOGRAPHY_RC4_DERIVE(RC4SHA512, DigestAlgorithmic_sha512);
#undef PPP_CRYPTOGRAPHY_RC4_DERIVE
    }
}