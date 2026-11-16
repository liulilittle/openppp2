/**
 * @file rc4.h
 * @brief Custom RC4 variant declarations.
 */
#pragma once

#include <ppp/stdafx.h>
#include <ppp/cryptography/digest.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace cryptography {
        /**
         * @brief Initializes an RC4 S-box with optional ascending/descending seed order.
         * @param sbox Target S-box buffer.
         * @param sboxlen S-box length.
         * @param key Key buffer.
         * @param keylen Key length.
         * @param ascending True for ascending initialization order.
         * @return True on success.
         */
        bool                                                                    rc4_sbox_impl(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen, bool ascending) noexcept;

        /**
         * @brief Initializes an RC4 S-box in ascending order.
         * @param sbox Target S-box buffer.
         * @param sboxlen S-box length.
         * @param key Key buffer.
         * @param keylen Key length.
         * @return True on success.
         */
        bool                                                                    rc4_sbox(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen) noexcept;

        /**
         * @brief Initializes an RC4 S-box in descending order.
         * @param sbox Target S-box buffer.
         * @param sboxlen S-box length.
         * @param key Key buffer.
         * @param keylen Key length.
         * @return True on success.
         */
        bool                                                                    rc4_sbox_descending(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen) noexcept;

        /**
         * @brief Encrypts/decrypts data using a provided S-box variant.
         * @param key Key buffer.
         * @param keylen Key length.
         * @param sbox Mutable S-box state buffer.
         * @param sboxlen S-box length.
         * @param data In-place data buffer.
         * @param datalen Data length.
         * @param subtract Additive offset parameter.
         * @param E Non-zero for encryption mode.
         * @return True on success.
         */
        bool                                                                    rc4_crypt_sbox(unsigned char* key, int keylen, unsigned char* sbox, int sboxlen, unsigned char* data, int datalen, int subtract, int E) noexcept;

        /**
         * @brief Encrypts/decrypts data using alternate low-index progression.
         * @param key Key buffer.
         * @param keylen Key length.
         * @param sbox Mutable S-box state buffer.
         * @param sboxlen S-box length.
         * @param data In-place data buffer.
         * @param datalen Data length.
         * @param subtract Additive offset parameter.
         * @param E Non-zero for encryption mode.
         * @return True on success.
         */
        bool                                                                    rc4_crypt_sbox_c(unsigned char* key, int keylen, unsigned char* sbox, int sboxlen, unsigned char* data, int datalen, int subtract, int E) noexcept;

        /**
         * @brief Encrypts/decrypts data with temporary S-box setup.
         * @param key Key buffer.
         * @param keylen Key length.
         * @param data In-place data buffer.
         * @param datalen Data length.
         * @param subtract Additive offset parameter.
         * @param E Non-zero for encryption mode.
         * @return True on success.
         */
        bool                                                                    rc4_crypt(unsigned char* key, int keylen, unsigned char* data, int datalen, int subtract, int E) noexcept;

        /**
         * @brief Stateful RC4 wrapper with method-driven key derivation.
         */
        class RC4 : public std::enable_shared_from_this<RC4> {
        public:
            /**
             * @brief Constructs an RC4 context.
             * @param method Cipher method name.
             * @param password Password/key material.
             * @param algorithm Digest algorithm used to derive S-box key.
             * @param ascending Non-zero to use ascending S-box seed order.
             * @param subtract Additive offset parameter.
             * @param E Non-zero for encryption mode behavior.
             */
            RC4(const ppp::string& method, const ppp::string& password, int algorithm, int ascending, int subtract, int E) noexcept;

        public:
            /**
             * @brief Encrypts input bytes.
             * @param allocator Output buffer allocator.
             * @param data Input data.
             * @param datalen Input length.
             * @param outlen Receives output length.
             * @return Encrypted buffer, or null on failure.
             */
            std::shared_ptr<Byte>                                               Encrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept;
            /** @brief Encrypts into caller-owned @p output of at least @p datalen bytes. */
            bool                                                                EncryptTo(Byte* output, int output_capacity, Byte* data, int datalen, int& outlen) noexcept;
            /**
             * @brief Decrypts input bytes.
             * @param allocator Output buffer allocator.
             * @param data Input data.
             * @param datalen Input length.
             * @param outlen Receives output length.
             * @return Decrypted buffer, or null on failure.
             */
            std::shared_ptr<Byte>                                               Decrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept;
            /** @brief Decrypts @p datalen bytes of @p data in place (the stream operation is symmetric). */
            bool                                                                DecryptInPlace(Byte* data, int datalen) noexcept;
            /** @brief Returns a shared reference to this object. */
            std::shared_ptr<RC4>                                                GetReference() noexcept { return this->shared_from_this(); }
            /**
             * @brief Checks whether a method name is supported.
             * @param method Method name.
             * @return True when supported.
             */
            static bool                                                         Support(const ppp::string& method) noexcept;
            /**
             * @brief Creates an RC4 variant by method name.
             * @param method Method name.
             * @param password Password/key material.
             * @return RC4 instance, or null when unsupported.
             */
            static std::shared_ptr<RC4>                                         Create(const ppp::string& method, const ppp::string& password) noexcept;

        private:
            int                                                                 _E        = 0;
            int                                                                 _subtract = 0;
            ppp::string                                                         _method;
            ppp::string                                                         _password;
            std::shared_ptr<Byte>                                               _sbox;
        };

#define PPP_CRYPTOGRAPHY_RC4_DERIVE(DERIVE_CLASS_NAME, DIGEST_ALGORITHM)        \
        /** @brief RC4 specialization with fixed digest algorithm. */           \
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
        PPP_CRYPTOGRAPHY_RC4_DERIVE(RC4SHA384, DigestAlgorithmic_sha384);
        PPP_CRYPTOGRAPHY_RC4_DERIVE(RC4SHA512, DigestAlgorithmic_sha512);
#undef PPP_CRYPTOGRAPHY_RC4_DERIVE
    }
}
