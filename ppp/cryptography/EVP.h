#pragma once

#include <ppp/stdafx.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace cryptography {
        class EVP : public std::enable_shared_from_this<EVP> {
        public:
            typedef std::mutex                                  SynchronizedObject;
            typedef std::lock_guard<SynchronizedObject>         SynchronizedObjectScope;

        public:
            EVP(const ppp::string& method, const ppp::string& password) noexcept;

        public:
            std::shared_ptr<Byte>                               Encrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept;
            std::shared_ptr<Byte>                               Decrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept;
            std::shared_ptr<EVP>                                GetReference() noexcept { return this->shared_from_this(); }
            SynchronizedObject&                                 GetSynchronizedObject() noexcept { return _syncobj; }
            static bool                                         Support(const ppp::string& method) noexcept;

        private:
            bool                                                initCipher(std::shared_ptr<EVP_CIPHER_CTX>& context, int enc) noexcept;
            bool                                                initKey(const ppp::string& method, const ppp::string password) noexcept;

        private:
            SynchronizedObject                                  _syncobj;
            const EVP_CIPHER*                                   _cipher = NULL;
            std::shared_ptr<Byte>                               _key; // _cipher->key_len
            std::shared_ptr<Byte>                               _iv;
            ppp::string                                         _method;
            ppp::string                                         _password;
            std::shared_ptr<EVP_CIPHER_CTX>                     _encryptCTX;
            std::shared_ptr<EVP_CIPHER_CTX>                     _decryptCTX;
        };

        ppp::string                                             ComputeMD5(const ppp::string& s, bool toupper) noexcept;
        bool                                                    ComputeMD5(const ppp::string& s, const Byte* md5, int& md5len) noexcept;
        ppp::string                                             ComputeDigest(const ppp::string& s, int algorithm, bool toupper) noexcept;
        bool                                                    ComputeDigest(const ppp::string& s, const Byte* digest, int& digestlen, int algorithm) noexcept;
    }
}