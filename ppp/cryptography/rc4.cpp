/**
 * @file rc4.cpp
 * @brief Custom RC4 variant implementation used by cryptography helpers.
 */
#include "rc4.h"
#include "digest.h"
#include <ppp/diagnostics/Error.h>

// ============================================================================
// Standard RC4 Implementation (for reference)
// ============================================================================
// The following code shows the standard RC4 algorithm as defined in 1987.
// It uses an S-box of 256 bytes, modulo 256 operations, and the classic
// Key Scheduling Algorithm (KSA) and Pseudo-Random Generation Algorithm (PRGA).
// This standard version is provided here to highlight the deliberate
// modifications made in the custom implementation below.
// ============================================================================

/*
// Standard RC4 KSA (Key Scheduling Algorithm)
void standard_rc4_ksa(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen) {
    // sboxlen must be 256 in standard RC4
    for (int i = 0; i < 256; i++) {
        sbox[i] = (unsigned char)i;
    }

    for (int i = 0, j = 0; i < 256; i++) {
        j = (j + sbox[i] + key[i % keylen]) % 256;
        unsigned char temp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = temp;
    }
}

// Standard RC4 PRGA (Pseudo-Random Generation Algorithm)
// Generates one byte of keystream and updates the S-box.
unsigned char standard_rc4_prga(unsigned char* sbox, int& i, int& j) {
    i = (i + 1) % 256;
    j = (j + sbox[i]) % 256;

    unsigned char temp = sbox[i];
    sbox[i] = sbox[j];
    sbox[j] = temp;

    int t = (sbox[i] + sbox[j]) % 256;
    return sbox[t];
}

// Standard RC4 encryption/decryption (XOR with keystream)
void standard_rc4_crypt(unsigned char* key, int keylen, unsigned char* data, int datalen) {
    unsigned char sbox[256];
    standard_rc4_ksa(sbox, 256, key, keylen);
    
    int i = 0, j = 0;
    for (int n = 0; n < datalen; n++) {
        data[n] ^= standard_rc4_prga(sbox, i, j);
    }
}
*/

// ============================================================================
// Custom RC4 Variant (Modified for VPN Digest Generation)
// All deviations from the standard are documented in the comments below.
// ============================================================================

// RC4_MAXBIT is intentionally defined as 0xff (255) instead of the standard 256.
// Standard RC4 uses an S‑box of 256 bytes; here the size is reduced to 255.
// This changes all modulo operations (which become modulo 255) and thus the key stream.
// The deviation is deliberate, aimed at increasing obfuscation for VPN digest generation.
#ifndef RC4_MAXBIT
/** @brief Custom S-box size constant (255 entries). */
#define RC4_MAXBIT 0xff
#endif

namespace ppp {
    namespace cryptography {
        /**
         * @brief Builds and scrambles the RC4 S-box state.
         * @param sbox Target S-box buffer.
         * @param sboxlen S-box size.
         * @param key Key bytes.
         * @param keylen Key length.
         * @param ascending True for ascending initialization, false for descending.
         * @return True on success.
         */
        bool rc4_sbox_impl(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen, bool ascending) noexcept {
            if (NULLPTR == sbox || NULLPTR == key || keylen < 1 || sboxlen < 1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Rc4SboxInitInvalidArguments);
                return false;
            }

            /**
             * @brief Initializes the S-box in configured order before key scheduling.
             */
            // Fill the S‑box: standard RC4 uses ascending order.
            // Here we also allow descending order as an extra twist.
            for (int i = 0; i < sboxlen; i++) {
                if (ascending) {
                    sbox[i] = (unsigned char)i;
                }
                else {
                    sbox[sboxlen - (i + 1)] = (unsigned char)i;
                }
            }

            /**
             * @brief Executes the KSA permutation phase.
             */
            // KSA – identical to standard RC4 except that sboxlen is 255 instead of 256.
            for (int i = 0, j = 0; i < sboxlen; i++) {
                j = (j + sbox[i] + key[i % keylen]) % sboxlen;

                unsigned char b = sbox[i];
                sbox[i] = sbox[j];
                sbox[j] = b;
            }

            return true;
        }

        /**
         * @brief Initializes an S-box using ascending seed order.
         * @return True on success.
         */
        bool rc4_sbox(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen) noexcept {
            return rc4_sbox_impl(sbox, sboxlen, key, keylen, true);
        }

        /**
         * @brief Initializes an S-box using descending seed order.
         * @return True on success.
         */
        bool rc4_sbox_descending(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen) noexcept {
            return rc4_sbox_impl(sbox, sboxlen, key, keylen, false);
        }

        /**
         * @brief Encrypts/decrypts in place using the custom PRGA variant.
         * @param key Key bytes.
         * @param keylen Key length.
         * @param sbox Mutable S-box state.
         * @param sboxlen S-box size.
         * @param data Data buffer processed in place.
         * @param datalen Number of bytes to process.
         * @param subtract Extra additive offset input.
         * @param E Non-zero for encrypt branch.
         * @return True on success.
         */
        bool rc4_crypt_sbox(unsigned char* key, int keylen, unsigned char* sbox, int sboxlen, unsigned char* data, int datalen, int subtract, int E) noexcept {
            if (NULLPTR == key || keylen < 1 || NULLPTR == data || datalen < 1 || NULLPTR == sbox || sboxlen < 1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Rc4CryptSboxInvalidArguments);
                return false;
            }

            unsigned char x = (unsigned char)(E ? subtract : -subtract); // Extra additive constant for confusion
            /**
             * @brief Core PRGA loop with custom index progression and post-XOR offset.
             */
            for (int i = 0, low = 0, high = 0, mid; i < datalen; i++) {
                // In standard RC4, the first index (usually i) would be incremented by 1 modulo 256.
                // Here we intentionally keep low fixed at 0: low = low % sboxlen = 0.
                low = low % sboxlen;
                high = (high + sbox[i % sboxlen]) % sboxlen; // Non‑standard update mixing data position

                unsigned char b = sbox[low];
                sbox[low] = sbox[high];
                sbox[high] = b;

                mid = (sbox[low] + sbox[high]) % sboxlen; // Standard formula for output index
                if (E) {
                    // Encryption: data = (data xor S[mid]) - x
                    data[i] = (unsigned char)((data[i] ^ sbox[mid]) - x);
                }
                else {
                    // Decryption: data = (data - x) xor S[mid]
                    data[i] = (unsigned char)((data[i] - x) ^ sbox[mid]);
                }
            }

            return true;
        }

        /**
         * @brief Encrypts/decrypts in place using alternate low-index stepping.
         * @param key Key bytes.
         * @param keylen Key length.
         * @param sbox Mutable S-box state.
         * @param sboxlen S-box size.
         * @param data Data buffer processed in place.
         * @param datalen Number of bytes to process.
         * @param subtract Extra additive offset input.
         * @param E Non-zero for encrypt branch.
         * @return True on success.
         */
        bool rc4_crypt_sbox_c(unsigned char* key, int keylen, unsigned char* sbox, int sboxlen, unsigned char* data, int datalen, int subtract, int E) noexcept {
            if (NULLPTR == key || keylen < 1 || NULLPTR == data || datalen < 1 || NULLPTR == sbox || sboxlen < 1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Rc4CryptSboxCInvalidArguments);
                return false;
            }

            unsigned char x = (unsigned char)(E ? subtract : -subtract);
            /**
             * @brief Core PRGA loop where low advances by key length.
             */
            for (int i = 0, low = 0, high = 0, mid; i < datalen; i++) {
                // Modified update: step size = keylen (instead of 1)
                low = (low + keylen) % sboxlen;
                high = (high + sbox[i % sboxlen]) % sboxlen; // Still non‑standard

                unsigned char b = sbox[low];
                sbox[low] = sbox[high];
                sbox[high] = b;

                mid = (sbox[low] + sbox[high]) % sboxlen;
                if (E) {
                    data[i] = (unsigned char)((data[i] ^ sbox[mid]) - x);
                }
                else {
                    data[i] = (unsigned char)((data[i] - x) ^ sbox[mid]);
                }
            }

            return true;
        }

        /**
         * @brief Convenience RC4 entry that allocates and initializes a temporary S-box.
         * @return True on success.
         */
        bool rc4_crypt(unsigned char* key, int keylen, unsigned char* data, int datalen, int subtract, int E) noexcept {
            if (NULLPTR == key || keylen < 1 || NULLPTR == data || datalen < 1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Rc4CryptInvalidArguments);
                return false;
            }

            unsigned char sbox[RC4_MAXBIT]; // S‑box size 255 (non‑standard)
            rc4_sbox(sbox, sizeof(sbox), key, keylen);

            // Note: uses the version where low stays 0 – deliberate design.
            return rc4_crypt_sbox(key, keylen, sbox, sizeof(sbox), data, datalen, subtract, E);
        }

        /**
         * @brief Constructs a stateful RC4 instance from method and password.
         * @param method RC4 method name.
         * @param password Password used for digest-based key derivation.
         * @param algorithm Digest algorithm identifier.
         * @param ascending Non-zero for ascending S-box initialization.
         * @param subtract Extra additive offset input.
         * @param E Non-zero for encrypt branch behavior.
         */
        RC4::RC4(const ppp::string& method, const ppp::string& password, int algorithm, int ascending, int subtract, int E) noexcept
            : _E(E)
            , _subtract(subtract)
            , _method(method)
            , _password(password) {
            std::shared_ptr<Byte> iv = make_shared_alloc<Byte>(RC4_MAXBIT); // Allocate 255 bytes for the S‑box
            if (NULLPTR != iv) {
                // Derive a key from password using HMAC (algorithm: MD5, SHA1, etc.)
                ppp::string sbox_key = hash_hmac(password.data(), password.size(), (DigestAlgorithmic)algorithm, false);
                if (ascending) {
                    rc4_sbox((unsigned char*)iv.get(), RC4_MAXBIT, (unsigned char*)sbox_key.data(), sbox_key.size());
                }
                else {
                    rc4_sbox_descending((unsigned char*)iv.get(), RC4_MAXBIT, (unsigned char*)sbox_key.data(), sbox_key.size());
                }
                
                _sbox = std::move(iv);
            }
        }

        /**
         * @brief Encrypts input data into an allocated output buffer.
         * @param allocator Buffer allocator.
         * @param data Input data pointer.
         * @param datalen Input size.
         * @param outlen Output size.
         * @return Encrypted data buffer, or null on failure.
         */
        std::shared_ptr<Byte> RC4::Encrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept {
            outlen = -1;
            if ((datalen < 0) || (NULLPTR == data && datalen != 0)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Rc4EncryptInvalidArguments);
                return NULLPTR;
            }

            if (datalen == 0) {
                outlen = 0;
                return NULLPTR;
            }

            if (_password.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Rc4EncryptPasswordEmpty);
                return NULLPTR;
            }

            if (NULLPTR == _sbox) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return NULLPTR;
            }

            std::shared_ptr<Byte> plaintext = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, datalen);
            if (NULLPTR == plaintext) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return NULLPTR;
            }

            return EncryptTo(plaintext.get(), datalen, data, datalen, outlen) ? plaintext : NULLPTR;
        }

        /**
         * @brief Encrypts input data into caller-owned memory.
         */
        bool RC4::EncryptTo(Byte* output, int output_capacity, Byte* data, int datalen, int& outlen) noexcept {
            outlen = -1;
            if (NULLPTR == output || NULLPTR == data || datalen < 1 || output_capacity < datalen) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Rc4EncryptInvalidArguments);
                return false;
            }

            if (_password.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Rc4EncryptPasswordEmpty);
                return false;
            }

            if (NULLPTR == _sbox) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return false;
            }

            if (output != data) {
                memcpy(output, data, datalen);
            }

            // Uses the variant with (low + keylen) % sboxlen – another intentional modification.
            if (!rc4_crypt_sbox_c((unsigned char*)_password.data(), _password.size(),
                (unsigned char*)_sbox.get(), RC4_MAXBIT, (unsigned char*)output, datalen, _subtract, _E)) {
                if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Rc4CryptSboxCFailedWithoutSpecificError);
                }
                return false;
            }

            outlen = datalen;
            return true;
        }

        /**
         * @brief Decrypts input data.
         * @details Uses the same routine as encryption because this stream operation is symmetric.
         */
        std::shared_ptr<Byte> RC4::Decrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept {
            return Encrypt(allocator, data, datalen, outlen);
        }

        bool RC4::DecryptInPlace(Byte* data, int datalen) noexcept {
            int outlen = 0;
            return EncryptTo(data, datalen, data, datalen, outlen);
        }

        /**
         * @brief Checks whether an RC4 method string is supported.
         * @param method Method name.
         * @return True when supported.
         */
        bool RC4::Support(const ppp::string& method) noexcept {
            if (method.empty()) {
                return false;
            }

            if (method == "rc4-md5" ||
                method == "rc4-sha1" ||
                method == "rc4-sha224" ||
                method == "rc4-sha256" ||
                method == "rc4-sha384" ||
                method == "rc4-sha512") {
                return true;
            }

            return false;
        }

        /**
         * @brief Creates an RC4 implementation instance by method name.
         * @param method Method name.
         * @param password Password/key material.
         * @return RC4 instance, or null when method is unsupported.
         */
        std::shared_ptr<RC4> RC4::Create(const ppp::string& method, const ppp::string& password) noexcept {
            if (method.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Rc4CreateMethodEmpty);
                return NULLPTR;
            }

            if (method == "rc4-md5") {
                return make_shared_object<RC4MD5>(method, password);
            }

            if (method == "rc4-sha1") {
                return make_shared_object<RC4SHA1>(method, password);
            }

            if (method == "rc4-sha224") {
                return make_shared_object<RC4SHA224>(method, password);
            }

            if (method == "rc4-sha256") {
                return make_shared_object<RC4SHA256>(method, password);
            }

            if (method == "rc4-sha384") {
                return make_shared_object<RC4SHA384>(method, password);
            }

            if (method == "rc4-sha512") {
                return make_shared_object<RC4SHA512>(method, password);
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::CryptoAlgorithmUnsupported);
            return NULLPTR;
        }
    }
}

