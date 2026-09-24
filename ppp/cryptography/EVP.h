/**
 * @file EVP.h
 * @brief OpenSSL EVP and digest helper declarations.
 */
#pragma once

#include <ppp/stdafx.h>
#include <ppp/threading/BufferswapAllocator.h>

#include <common/aesni/aes.h>

namespace ppp {
    namespace cryptography {
        /**
         * @brief Symmetric cipher wrapper based on OpenSSL EVP.
         */
        class EVP : public std::enable_shared_from_this<EVP> {
        public:
            /** @brief Mutex type used for external synchronization. */
            typedef std::mutex                                  SynchronizedObject;
            /** @brief RAII lock type for @ref SynchronizedObject. */
            typedef std::lock_guard<SynchronizedObject>         SynchronizedObjectScope;

        public:
            /**
             * @brief Constructs an EVP cipher instance.
             * @param method Cipher method name.
             * @param password Password used for key/IV derivation.
             */
            EVP(const ppp::string& method, const ppp::string& password) noexcept;

        public:
            /**
             * @brief Encrypts a plaintext buffer.
             * @param allocator Target buffer allocator.
             * @param data Input plaintext bytes.
             * @param datalen Input length in bytes.
             * @param outlen Receives output length in bytes.
             * @return Allocated ciphertext buffer, or null on failure.
             */
            std::shared_ptr<Byte>                               Encrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept;
            /**
             * @brief Decrypts a ciphertext buffer.
             * @param allocator Target buffer allocator.
             * @param data Input ciphertext bytes.
             * @param datalen Input length in bytes.
             * @param outlen Receives output length in bytes.
             * @return Allocated plaintext buffer, or null on failure.
             */
            std::shared_ptr<Byte>                               Decrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept;
            /** @brief Returns a shared reference to this object. */
            std::shared_ptr<EVP>                                GetReference() noexcept { return this->shared_from_this(); }
            /** @brief Returns the synchronization object for caller-managed locking. */
            SynchronizedObject&                                 GetSynchronizedObject() noexcept { return _syncobj; }
            /**
             * @brief Checks whether a cipher method name is supported.
             * @param method Cipher method name.
             * @return True when supported.
             */
            static bool                                         Support(const ppp::string& method) noexcept;
            /** @brief Global switch: transparently run aes-*-cfb via AES-NI when the CPU supports it (default on). */
            static void                                         SetSimdAuto(bool enabled) noexcept;
            /** @brief Whether this instance is using the AES-NI hardware path. */
            bool                                                IsHardwareAccelerated() const noexcept;

        private:
            /**
             * @brief Initializes an EVP cipher context for encryption or decryption.
             * @param context Target context instance.
             * @param enc Non-zero for encryption, zero for decryption.
             * @return True on success.
             */
            bool                                                initCipher(std::shared_ptr<EVP_CIPHER_CTX>& context, int enc) noexcept;
            /**
             * @brief Resolves cipher type and derives key/IV material.
             * @param method Cipher method name.
             * @param password Password input.
             * @return True on success.
             */
            bool                                                initKey(const ppp::string& method, const ppp::string password) noexcept;

        private:
            SynchronizedObject                                  _syncobj;
            const EVP_CIPHER*                                   _cipher = NULLPTR;
            std::shared_ptr<Byte>                               _key; // _cipher->key_len
            std::shared_ptr<Byte>                               _iv;
            ppp::string                                         _method;
            ppp::string                                         _password;
            std::shared_ptr<EVP_CIPHER_CTX>                     _encryptCTX;
            std::shared_ptr<EVP_CIPHER_CTX>                     _decryptCTX;
            aesni::AES                                          _aes;
        };

        /**
         * @brief Computes the MD5 hex string for a text input.
         * @param s Input text.
         * @param toupper True for uppercase hex output.
         * @return MD5 digest text.
         */
        ppp::string                                             ComputeMD5(const ppp::string& s, bool toupper) noexcept;
        /**
         * @brief Computes raw MD5 bytes into the provided output buffer.
         * @param s Input text.
         * @param md5 Output buffer for MD5 bytes.
         * @param md5len Input capacity and output length.
         * @return True on success; otherwise false.
         */
        bool                                                    ComputeMD5(const ppp::string& s, const Byte* md5, int& md5len) noexcept;
        /**
         * @brief Computes a digest string using the specified algorithm identifier.
         * @param s Input text.
         * @param algorithm Digest algorithm identifier.
         * @param toupper True for uppercase hexadecimal output.
         * @return Digest string on success, or an empty string on failure.
         */
        ppp::string                                             ComputeDigest(const ppp::string& s, int algorithm, bool toupper) noexcept;
        /**
         * @brief Computes raw digest bytes using the specified algorithm identifier.
         * @param s Input text.
         * @param digest Output buffer for raw digest bytes.
         * @param digestlen Input capacity and output byte count.
         * @param algorithm Digest algorithm identifier.
         * @return True on success; otherwise false.
         */
        bool                                                    ComputeDigest(const ppp::string& s, const Byte* digest, int& digestlen, int algorithm) noexcept;
    }
}
