#include <stdio.h>
#include <string.h>
#include <string>
#include <sstream>
#include <iostream>

#include "digest.h"
#include "md5.h"
#include "rc4.h"
#include "EVP.h"

namespace ppp {
    namespace cryptography {
        void EVP_cctor() noexcept {
            /* initialize OpenSSL */
            OpenSSL_add_all_ciphers();
            OpenSSL_add_all_digests();
            OpenSSL_add_all_algorithms();

#if defined(_WIN32)
#pragma warning(push)
#pragma warning(disable: 4996)
#else
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
            ERR_load_EVP_strings();
#if defined(_WIN32)
#pragma warning(pop)
#else
#pragma GCC diagnostic pop
#endif

            ERR_load_crypto_strings();
        }

        EVP::EVP(const ppp::string& method, const ppp::string& password) noexcept
            : _cipher(NULL)
            , _method(method)
            , _password(password) {
            if (initKey(method, password)) {
                initCipher(_encryptCTX, 1);
                initCipher(_decryptCTX, 0);
            }
        }

        std::shared_ptr<Byte> EVP::Encrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept {
            outlen = 0;
            if (datalen < 0 || (NULL == data && datalen != 0)) {
                outlen = ~0;
                return NULL;
            }

            if (datalen == 0) {
                return NULL;
            }

            if (NULL == _cipher) {
                return NULL;
            }

            // INIT-CTX
            SynchronizedObjectScope scope(_syncobj);
            if (EVP_CipherInit_ex(_encryptCTX.get(), _cipher, NULL, _key.get(), _iv.get(), 1) < 1) {
                return NULL;
            }

            // ENCR-DATA
            int feedbacklen = datalen + EVP_CIPHER_block_size(_cipher);
            std::shared_ptr<Byte> cipherText = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, feedbacklen);
            if (NULL == cipherText) {
                return NULL;
            }

            if (EVP_CipherUpdate(_encryptCTX.get(),
                cipherText.get(), &feedbacklen, data, datalen) < 1) {
                outlen = ~0;
                return NULL;
            }

            outlen = feedbacklen;
            return cipherText;
        }

        std::shared_ptr<Byte> EVP::Decrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept {
            outlen = 0;
            if (datalen < 0 || (NULL == data && datalen != 0)) {
                outlen = ~0;
                return NULL;
            }

            if (datalen == 0) {
                return NULL;
            }

            if (NULL == _cipher) {
                return NULL;
            }

            // INIT-CTX
            SynchronizedObjectScope scope(_syncobj);
            if (EVP_CipherInit_ex(_decryptCTX.get(), _cipher, NULL, _key.get(), _iv.get(), 0) < 1) {
                return NULL;
            }

            // DECR-DATA
            int feedbacklen = datalen + EVP_CIPHER_block_size(_cipher);
            std::shared_ptr<Byte> cipherText = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, feedbacklen);
            if (NULL == cipherText) {
                return NULL;
            }

            if (EVP_CipherUpdate(_decryptCTX.get(),
                cipherText.get(), &feedbacklen, data, datalen) < 1) {
                feedbacklen = ~0;
                return NULL;
            }

            outlen = feedbacklen;
            return cipherText;
        }

        bool EVP::initCipher(std::shared_ptr<EVP_CIPHER_CTX>& context, int enc) noexcept {
            bool exception = false;
            while (NULL == context.get()) {
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                if (NULL == ctx) {
                    break;
                }

                context = std::shared_ptr<EVP_CIPHER_CTX>(ctx,
                    [](EVP_CIPHER_CTX* context) noexcept {
                        EVP_CIPHER_CTX_cleanup(context);
                        EVP_CIPHER_CTX_free(context);
                    });

                EVP_CIPHER_CTX_init(context.get());
                if ((exception = EVP_CipherInit_ex(context.get(), _cipher, NULL, NULL, NULL, enc) < 1)) {
                    break;
                }

                if ((exception = EVP_CIPHER_CTX_set_key_length(context.get(), EVP_CIPHER_key_length(_cipher)) < 1)) {
                    break;
                }

                if ((exception = EVP_CIPHER_CTX_set_padding(context.get(), 1) < 1)) {
                    break;
                }
            }

            if (exception) {
                context = NULL;
                return false;
            }

            return true;
        }

        bool EVP::Support(const ppp::string& method) noexcept {
            if (method.empty()) {
                return false;
            }

            const EVP_CIPHER* cipher = EVP_get_cipherbyname(method.data());
            return NULL != cipher;
        }

        bool EVP::initKey(const ppp::string& method, const ppp::string password) noexcept {
            _cipher = EVP_get_cipherbyname(method.data());
            if (NULL == _cipher) {
                return false;
            }

            // INIT-IVV
            int ivLen = EVP_CIPHER_iv_length(_cipher);
            _iv = make_shared_alloc<Byte>(ivLen); // RAND_bytes(iv.get(), ivLen);
            if (NULL == _iv) {
                return false;
            }

            _key = make_shared_alloc<Byte>(EVP_CIPHER_key_length(_cipher));
            if (NULL == _key) {
                return false;
            }

            if (EVP_BytesToKey(_cipher, EVP_md5(), NULL, (Byte*)password.data(), (int)password.length(), 1, _key.get(), _iv.get()) < 1) {
                return false;
            }

            /*
            std::stringstream ss; // MD5->RC4
            ss << "Ppp@";
            ss << method;
            ss << ".";
            ss << ppp::string((char*)_key.get(), EVP_CIPHER_key_length(_cipher));
            ss << ".";
            ss << password;
            */

            ppp::string iv_string = "Ppp@" + method + "." + ppp::string((char*)_key.get(), EVP_CIPHER_key_length(_cipher)) + "." + password;
            ComputeMD5(iv_string, _iv.get(), ivLen); // MD5::HEX

            rc4_crypt(_key.get(), EVP_CIPHER_key_length(_cipher), _iv.get(), ivLen, 0, 0);
            return true;
        }

        ppp::string ComputeMD5(const ppp::string& s, bool toupper) noexcept {
            MD5 md5;
            md5.update(s);
            return md5.toString(toupper);
        }

        bool ComputeMD5(const ppp::string& s, const Byte* md5, int& md5len) noexcept {
            if (md5len < 1 || NULL == md5) {
                md5len = 0;
                return false;
            }
            else {
                md5len = md5len > (int)sizeof(MD5::HEX) ? (int)sizeof(MD5::HEX) : md5len;
            }

            MD5 m;
            m.update(s);

            memcpy((void*)md5, m.digest(), md5len);
            return true;
        }

        ppp::string ComputeDigest(const ppp::string& s, int algorithm, bool toupper) noexcept {
            ppp::string hash;
            if (hash_hmac(s.data(), s.size(), hash, (DigestAlgorithmic)algorithm, true, toupper)) {
                return hash;
            }
            else {
                return ppp::string();
            }
        }

        bool ComputeDigest(const ppp::string& s, const Byte* digest, int& digestlen, int algorithm) noexcept {
            if (digestlen < 1 || NULL == digest) {
                digestlen = 0;
                return false;
            }
            else {
                digestlen = digestlen > (int)sizeof(MD5::HEX) ? (int)sizeof(MD5::HEX) : digestlen;
            }

            ppp::string hash;
            if (!hash_hmac(s.data(), s.size(), hash, (DigestAlgorithmic)algorithm, false, false)) {
                digestlen = 0;
                return false;
            }

            int max = std::min<int>(hash.size(), digestlen);
            memcpy((void*)digest, (void*)hash.data(), max);
            return true;
        }
    }
}