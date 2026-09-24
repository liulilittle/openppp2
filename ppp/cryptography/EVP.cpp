#include <stdio.h>
#include <string.h>
#include <string>
#include <sstream>
#include <iostream>
#include <ppp/diagnostics/Error.h>

/**
 * @file EVP.cpp
 * @brief Implements OpenSSL EVP-based cipher helpers and digest adapters.
 */

#include "digest.h"
#include "md5.h"
#include "rc4.h"
#include "EVP.h"

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

namespace ppp {
    namespace cryptography {
        /**
         * @brief Initializes global OpenSSL cipher and digest registries.
         */
        void EVP_cctor() noexcept {
            /** @brief Registers available OpenSSL algorithm providers and string tables. */
            OpenSSL_add_all_ciphers();
            OpenSSL_add_all_digests();
            OpenSSL_add_all_algorithms();

            /**
             * @brief Loads EVP error strings while silencing deprecation warnings on legacy APIs.
             */
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

        /**
         * @brief Constructs an EVP cipher instance and attempts AES-NI acceleration when available.
         * @param method Cipher method name.
         * @param password Password used to derive key and IV.
         */
        static std::atomic<bool> g_evp_simd_auto{true};

        void EVP::SetSimdAuto(bool enabled) noexcept {
            g_evp_simd_auto.store(enabled, std::memory_order_relaxed);
        }

        bool EVP::IsHardwareAccelerated() const noexcept {
            return _aes.IsAttached();
        }

        EVP::EVP(const ppp::string& method, const ppp::string& password) noexcept
            : _cipher(NULLPTR)
            , _method(method)
            , _password(password) {

            ppp::string aes_real_name;
            bool aes128 = false;
            bool aes_gcm = false;

            ppp::string probe_method = method;
            const bool explicit_simd = method.compare(0, 5, "simd-") == 0;

            if (g_evp_simd_auto.load(std::memory_order_relaxed) && !explicit_simd) {
                ppp::string simd_variant = ppp::string("simd-") + method;
                if (aesni::AES::Support(simd_variant)) {
                    probe_method = simd_variant;
                }
            }

            const bool auto_promoted = probe_method != method;
            if (aesni::AES::Support(probe_method, &aes128, &aes_gcm, &aes_real_name)) {
                if (!initKey(aes_real_name, password)) {
                    return;
                }

                if (_aes.TryAttach(_key.get(), _iv.get(), aes128, aes_gcm)) {
                    return;
                }

                // TryAttach may fail after initKey succeeds (for example, round-key allocation failure).
                // Clear the partially initialized OpenSSL state before deciding whether fallback is legal.
                _cipher = NULLPTR;
                _key.reset();
                _iv.reset();

                // Explicit simd-* requests must fail rather than silently changing implementation semantics.
                if (!auto_promoted) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return;
                }
            }

            // Transparent promotion failure falls back to the originally requested OpenSSL method.
            if (!initKey(method, password)) {
                return;
            }

            if (!initCipher(_encryptCTX, 1)) {
                _cipher = NULLPTR;
                _key.reset();
                _iv.reset();
                return;
            }

            if (!initCipher(_decryptCTX, 0)) {
                _encryptCTX.reset();
                _cipher = NULLPTR;
                _key.reset();
                _iv.reset();
            }
        }

        /**
         * @brief Encrypts plaintext bytes with the selected cipher context.
         * @param allocator Output allocator.
         * @param data Input plaintext bytes.
         * @param datalen Input plaintext length.
         * @param outlen Receives encrypted output length, or bitwise-not zero on failure.
         * @return Shared encrypted buffer on success, or null on error.
         */
        std::shared_ptr<Byte> EVP::Encrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept {
            if (_aes.IsAttached()) {
                return _aes.Encrypt(allocator, data, datalen, outlen);
            }

            outlen = 0;
            if (datalen < 0 || (NULLPTR == data && datalen != 0)) {
                outlen = ~0;
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::EvpEncryptInvalidArguments);
                return NULLPTR;
            }

            if (datalen == 0) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::EvpEncryptZeroLengthInput);
                return NULLPTR;
            }

            if (NULLPTR == _cipher || NULLPTR == _encryptCTX) {
                outlen = ~0;
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::CryptoAlgorithmUnsupported);
                return NULLPTR;
            }

            // INIT-CTX
            SynchronizedObjectScope scope(_syncobj);
            if (EVP_CipherInit_ex(_encryptCTX.get(), _cipher, NULLPTR, _key.get(), _iv.get(), 1) < 1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                return NULLPTR;
            }

            // ENCR-DATA
            int feedbacklen = datalen + EVP_CIPHER_block_size(_cipher);
            std::shared_ptr<Byte> cipherText = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, feedbacklen);
            if (NULLPTR == cipherText) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return NULLPTR;
            }

            if (EVP_CipherUpdate(_encryptCTX.get(),
                cipherText.get(), &feedbacklen, data, datalen) < 1) {
                outlen = ~0;
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                return NULLPTR;
            }

            outlen = feedbacklen;
            return cipherText;
        }

        /**
         * @brief Decrypts ciphertext bytes with the selected cipher context.
         * @param allocator Output allocator.
         * @param data Input ciphertext bytes.
         * @param datalen Input ciphertext length.
         * @param outlen Receives decrypted output length, or bitwise-not zero on failure.
         * @return Shared decrypted buffer on success, or null on error.
         */
        std::shared_ptr<Byte> EVP::Decrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept {
            if (_aes.IsAttached()) {
                return _aes.Decrypt(allocator, data, datalen, outlen);
            }

            outlen = 0;
            if (datalen < 0 || (NULLPTR == data && datalen != 0)) {
                outlen = ~0;
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::EvpDecryptInvalidArguments);
                return NULLPTR;
            }

            if (datalen == 0) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::EvpDecryptZeroLengthInput);
                return NULLPTR;
            }

            if (NULLPTR == _cipher || NULLPTR == _decryptCTX) {
                outlen = ~0;
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::CryptoAlgorithmUnsupported);
                return NULLPTR;
            }

            // INIT-CTX
            SynchronizedObjectScope scope(_syncobj);
            if (EVP_CipherInit_ex(_decryptCTX.get(), _cipher, NULLPTR, _key.get(), _iv.get(), 0) < 1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                return NULLPTR;
            }

            // DECR-DATA
            int feedbacklen = datalen + EVP_CIPHER_block_size(_cipher);
            std::shared_ptr<Byte> cipherText = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, feedbacklen);
            if (NULLPTR == cipherText) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return NULLPTR;
            }

            if (EVP_CipherUpdate(_decryptCTX.get(),
                cipherText.get(), &feedbacklen, data, datalen) < 1) {
                outlen = ~0;
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                return NULLPTR;
            }

            outlen = feedbacklen;
            return cipherText;
        }

        /**
         * @brief Creates and initializes an EVP cipher context for encryption or decryption.
         * @param context Receives initialized context on success.
         * @param enc Non-zero for encryption context, zero for decryption context.
         * @return True if context initialization succeeds; otherwise false.
         */
        bool EVP::initCipher(std::shared_ptr<EVP_CIPHER_CTX>& context, int enc) noexcept {
            bool exception = false;
            /**
             * @brief Repeats setup until a context is obtained or an initialization step fails.
             */
            while (!context) {
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                if (!ctx) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    break;
                }

                context = std::shared_ptr<EVP_CIPHER_CTX>(ctx,
                    [](EVP_CIPHER_CTX* context) noexcept {
                        if (context) {
                            EVP_CIPHER_CTX_cleanup(context);
                            EVP_CIPHER_CTX_free(context);
                        }
                    });

                EVP_CIPHER_CTX_init(context.get());
                if ((exception = EVP_CipherInit_ex(context.get(), _cipher, NULLPTR, NULLPTR, NULLPTR, enc) < 1)) {
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
                context = NULLPTR;
                ppp::diagnostics::SetLastErrorCode(0 != enc ? ppp::diagnostics::ErrorCode::ProtocolEncodeFailed : ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                return false;
            }

            return NULLPTR != context;
        }

        /**
         * @brief Checks whether a cipher method is available through OpenSSL EVP or AES-NI wrapper.
         * @param method Cipher method name.
         * @return True if the method is supported.
         */
        bool EVP::Support(const ppp::string& method) noexcept {
            if (method.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::EvpSupportMethodEmpty);
                return false;
            }

            const EVP_CIPHER* cipher = EVP_get_cipherbyname(method.data());
            if (NULLPTR != cipher) {
                return true;
            }

            if (!aesni::AES::Support(method)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::CryptoAlgorithmUnsupported);
                return false;
            }

            return true;
        }

        /**
         * @brief Resolves cipher metadata and derives key/IV data from password input.
         * @param method Cipher method name.
         * @param password Password string used in key derivation.
         * @return True if key and IV are successfully initialized.
         */
        bool EVP::initKey(const ppp::string& method, const ppp::string password) noexcept {
            _cipher = EVP_get_cipherbyname(method.data());
            if (NULLPTR == _cipher) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::CryptoAlgorithmUnsupported);
                return false;
            }

            // INIT-IVV
            int ivLen = EVP_CIPHER_iv_length(_cipher);
            _iv = make_shared_alloc<Byte>(ivLen); // RAND_bytes(iv.get(), ivLen);
            if (NULLPTR == _iv) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return false;
            }

            _key = make_shared_alloc<Byte>(EVP_CIPHER_key_length(_cipher));
            if (NULLPTR == _key) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return false;
            }

            if (EVP_BytesToKey(_cipher, EVP_md5(), NULLPTR, (Byte*)password.data(), (int)password.length(), 1, _key.get(), _iv.get()) < 1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::EvpInitKeyDerivationFailed);
                return false;
            }

            /**
             * @brief Re-hashes and mixes IV material to match the project's legacy compatibility scheme.
             */
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

        /**
         * @brief Computes an MD5 string digest from input text.
         * @param s Input text.
         * @param toupper True for uppercase hexadecimal output.
         * @return MD5 digest text.
         */
        ppp::string ComputeMD5(const ppp::string& s, bool toupper) noexcept {
            MD5 md5;
            md5.update(s);
            return md5.toString(toupper);
        }

        /**
         * @brief Computes raw MD5 bytes into the provided output buffer.
         * @param s Input text.
         * @param md5 Output buffer for MD5 bytes.
         * @param md5len Input capacity and output length.
         * @return True on success; otherwise false.
         */
        bool ComputeMD5(const ppp::string& s, const Byte* md5, int& md5len) noexcept {
            if (md5len < 1 || NULLPTR == md5) {
                md5len = 0;
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::EvpComputeMd5InvalidOutputBuffer);
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

        /**
         * @brief Computes a digest string using the specified algorithm identifier.
         * @param s Input text.
         * @param algorithm Digest algorithm identifier.
         * @param toupper True for uppercase hexadecimal output.
         * @return Digest string on success, or an empty string on failure.
         */
        ppp::string ComputeDigest(const ppp::string& s, int algorithm, bool toupper) noexcept {
            ppp::string hash;
            if (hash_hmac(s.data(), s.size(), hash, (DigestAlgorithmic)algorithm, true, toupper)) {
                return hash;
            }
            else {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::EvpComputeDigestInvalidAlgorithm);
                return ppp::string();
            }
        }

        /**
         * @brief Computes raw digest bytes using the specified algorithm identifier.
         * @param s Input text.
         * @param digest Output buffer for raw digest bytes.
         * @param digestlen Input capacity and output byte count.
         * @param algorithm Digest algorithm identifier.
         * @return True on success; otherwise false.
         */
        bool ComputeDigest(const ppp::string& s, const Byte* digest, int& digestlen, int algorithm) noexcept {
            if (digestlen < 1 || NULLPTR == digest) {
                digestlen = 0;
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryBufferNull);
                return false;
            }
            else {
                digestlen = digestlen > (int)sizeof(MD5::HEX) ? (int)sizeof(MD5::HEX) : digestlen;
            }

            ppp::string hash;
            if (!hash_hmac(s.data(), s.size(), hash, (DigestAlgorithmic)algorithm, false, false)) {
                digestlen = 0;
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::EvpComputeDigestInvalidAlgorithm);
                return false;
            }

            int max = std::min<int>(hash.size(), digestlen);
            memcpy((void*)digest, (void*)hash.data(), max);
            return true;
        }
    }
}
