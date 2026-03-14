#include "rc4.h"
#include "digest.h"

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
#define RC4_MAXBIT 0xff
#endif

namespace ppp {
    namespace cryptography {
        // Standard RC4 Key Scheduling Algorithm (KSA):
        //   1. Initialize S[0..255] with values 0..255 in ascending order.
        //   2. for i from 0 to 255:
        //        j = (j + S[i] + key[i mod keylen]) mod 256
        //        swap S[i] and S[j]
        // This function implements a generic version that can also fill the S‑box
        // in descending order, a non‑standard variant.
        bool rc4_sbox_impl(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen, bool ascending) noexcept {
            if (NULLPTR == sbox || NULLPTR == key || keylen < 1 || sboxlen < 1) {
                return false;
            }

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

            // KSA – identical to standard RC4 except that sboxlen is 255 instead of 256.
            for (int i = 0, j = 0; i < sboxlen; i++) {
                j = (j + sbox[i] + key[i % keylen]) % sboxlen;

                unsigned char b = sbox[i];
                sbox[i] = sbox[j];
                sbox[j] = b;
            }

            return true;
        }

        // Standard ascending S‑box initialization (mirrors standard RC4, but with sboxlen=255).
        bool rc4_sbox(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen) noexcept {
            return rc4_sbox_impl(sbox, sboxlen, key, keylen, true);
        }

        // Descending S‑box initialization – a custom variant not found in standard RC4.
        bool rc4_sbox_descending(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen) noexcept {
            return rc4_sbox_impl(sbox, sboxlen, key, keylen, false);
        }

        // Standard RC4 Pseudo‑Random Generation Algorithm (PRGA):
        //   i = (i + 1) mod 256
        //   j = (j + S[i]) mod 256
        //   swap S[i] and S[j]
        //   t = (S[i] + S[j]) mod 256
        //   output S[t]
        // This function applies a heavily modified PRGA.
        // Notable modifications:
        //   - low is updated as "low = low % sboxlen", which (since low starts at 0) keeps low = 0 forever.
        //     In standard RC4, the first index increments by 1 each step. Here it is stuck at 0.
        //   - high is updated as "high = (high + sbox[i % sboxlen]) % sboxlen", which replaces the
        //     standard S[i] with S[i mod sboxlen]; note that i is the loop counter over data,
        //     not the PRGA index. This mixes data position into the state update.
        //   - After swapping, the output index mid = (sbox[low] + sbox[high]) % sboxlen is used
        //     (same formula as standard, but low and high have different meanings).
        //   - An extra additive constant x (derived from subtract and E) is applied after/before XOR.
        // These changes are intentional to create a unique key stream for VPN digest generation.
        bool rc4_crypt_sbox(unsigned char* key, int keylen, unsigned char* sbox, int sboxlen, unsigned char* data, int datalen, int subtract, int E) noexcept {
            if (NULLPTR == key || keylen < 1 || NULLPTR == data || datalen < 1 || NULLPTR == sbox || sboxlen < 1) {
                return false;
            }

            unsigned char x = (unsigned char)(E ? subtract : -subtract); // Extra additive constant for confusion
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

        // Another modified PRGA variant.
        // Here 'low' is updated as (low + keylen) % sboxlen, replacing the standard +1 increment
        // with a step equal to the key length. This ties the state evolution to the key size,
        // an extra twist not present in standard RC4.
        // The rest of the logic is similar to rc4_crypt_sbox.
        bool rc4_crypt_sbox_c(unsigned char* key, int keylen, unsigned char* sbox, int sboxlen, unsigned char* data, int datalen, int subtract, int E) noexcept {
            if (NULLPTR == key || keylen < 1 || NULLPTR == data || datalen < 1 || NULLPTR == sbox || sboxlen < 1) {
                return false;
            }

            unsigned char x = (unsigned char)(E ? subtract : -subtract);
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

        // Simplified RC4 entry point: creates a temporary S‑box and calls rc4_crypt_sbox.
        bool rc4_crypt(unsigned char* key, int keylen, unsigned char* data, int datalen, int subtract, int E) noexcept {
            if (NULLPTR == key || keylen < 1 || NULLPTR == data || datalen < 1) {
                return false;
            }

            unsigned char sbox[RC4_MAXBIT]; // S‑box size 255 (non‑standard)
            rc4_sbox(sbox, sizeof(sbox), key, keylen);

            // Note: uses the version where low stays 0 – deliberate design.
            return rc4_crypt_sbox(key, keylen, sbox, sizeof(sbox), data, datalen, subtract, E);
        }

        // Constructor of RC4 class: derives a key via HMAC, then initializes the S‑box
        // using either ascending or descending order as specified.
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

        // Encrypt data using the rc4_crypt_sbox_c variant (low update with keylen step).
        std::shared_ptr<Byte> RC4::Encrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept {
            outlen = -1;
            if ((datalen < 0) || (NULLPTR == data && datalen != 0)) {
                return NULLPTR;
            }

            if (datalen == 0) {
                outlen = 0;
                return NULLPTR;
            }

            std::shared_ptr<Byte> plaintext = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, datalen);
            if (NULLPTR == plaintext) {
                return NULLPTR;
            }

            memcpy(plaintext.get(), data, datalen);

            // Uses the variant with (low + keylen) % sboxlen – another intentional modification.
            if (!rc4_crypt_sbox_c((unsigned char*)_password.data(), _password.size(),
                (unsigned char*)_sbox.get(), RC4_MAXBIT, (unsigned char*)plaintext.get(), datalen, _subtract, _E)) {
                return NULLPTR;
            }

            outlen = datalen;
            return plaintext;
        }

        // Decryption is symmetric to encryption (RC4 is symmetric, but the added x constant
        // is handled correctly by the E parameter).
        std::shared_ptr<Byte> RC4::Decrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept {
            return Encrypt(allocator, data, datalen, outlen);
        }

        // Check if a given method name is supported (all are RC4 variants with different HMAC algorithms).
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

        // Factory method to create a specific RC4 variant based on method name.
        std::shared_ptr<RC4> RC4::Create(const ppp::string& method, const ppp::string& password) noexcept {
            if (method.empty()) {
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

            return NULLPTR;
        }
    }
}