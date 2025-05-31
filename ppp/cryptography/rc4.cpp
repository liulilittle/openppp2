#include "rc4.h"
#include "digest.h"

#ifndef RC4_MAXBIT
#define RC4_MAXBIT 0xff
#endif

namespace ppp {
    namespace cryptography {
        bool rc4_sbox_impl(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen, bool ascending) noexcept {
            if (NULL == sbox || NULL == key || keylen < 1 || sboxlen < 1) {
                return false;
            }

            for (int i = 0; i < sboxlen; i++) {
                if (ascending) {
                    sbox[i] = (unsigned char)i;
                }
                else {
                    sbox[sboxlen - (i + 1)] = (unsigned char)i;
                }
            }

            for (int i = 0, j = 0; i < sboxlen; i++) {
                j = (j + sbox[i] + key[i % keylen]) % sboxlen;
                unsigned char b = sbox[i];
                sbox[i] = sbox[j];
                sbox[j] = b;
            }

            return true;
        }

        bool rc4_sbox(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen) noexcept {
            return rc4_sbox_impl(sbox, sboxlen, key, keylen, true);
        }

        bool rc4_sbox_descending(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen) noexcept {
            return rc4_sbox_impl(sbox, sboxlen, key, keylen, false);
        }

        bool rc4_crypt_sbox(unsigned char* key, int keylen, unsigned char* sbox, int sboxlen, unsigned char* data, int datalen, int subtract, int E) noexcept {
            if (NULL == key || keylen < 1 || NULL == data || datalen < 1 || NULL == sbox || sboxlen < 1) {
                return false;
            }

            unsigned char x = (unsigned char)(E ? subtract : -subtract);
            for (int i = 0, low = 0, high = 0, mid; i < datalen; i++) {
                low = low % sboxlen;
                high = (high + sbox[i % sboxlen]) % sboxlen;

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

        bool rc4_crypt_sbox_c(unsigned char* key, int keylen, unsigned char* sbox, int sboxlen, unsigned char* data, int datalen, int subtract, int E) noexcept {
            if (NULL == key || keylen < 1 || NULL == data || datalen < 1 || NULL == sbox || sboxlen < 1) {
                return false;
            }

            unsigned char x = (unsigned char)(E ? subtract : -subtract);
            for (int i = 0, low = 0, high = 0, mid; i < datalen; i++) {
                low = (low + keylen) % sboxlen;
                high = (high + sbox[i % sboxlen]) % sboxlen;

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

        bool rc4_crypt(unsigned char* key, int keylen, unsigned char* data, int datalen, int subtract, int E) noexcept {
            if (NULL == key || keylen < 1 || NULL == data || datalen < 1) {
                return false;
            }

            unsigned char sbox[RC4_MAXBIT];
            rc4_sbox(sbox, sizeof(sbox), key, keylen);

            return rc4_crypt_sbox(key, keylen, sbox, sizeof(sbox), data, datalen, subtract, E);
        }

        RC4::RC4(const ppp::string& method, const ppp::string& password, int algorithm, int ascending, int subtract, int E) noexcept
            : _E(E)
            , _subtract(subtract)
            , _method(method)
            , _password(password) {
            std::shared_ptr<Byte> iv = make_shared_alloc<Byte>(RC4_MAXBIT);
            if (NULL != iv) {
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

        std::shared_ptr<Byte> RC4::Encrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept {
            outlen = -1;
            if ((datalen < 0) || (NULL == data && datalen != 0)) {
                return NULL;
            }

            if (datalen == 0) {
                outlen = 0;
                return NULL;
            }

            std::shared_ptr<Byte> plaintext = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, datalen);
            if (NULL == plaintext) {
                return NULL;
            }

            memcpy(plaintext.get(), data, datalen);
            if (!rc4_crypt_sbox_c((unsigned char*)_password.data(), _password.size(),
                (unsigned char*)_sbox.get(), RC4_MAXBIT, (unsigned char*)plaintext.get(), datalen, _subtract, _E)) {
                return NULL;
            }

            outlen = datalen;
            return plaintext;
        }

        std::shared_ptr<Byte> RC4::Decrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept {
            return Encrypt(allocator, data, datalen, outlen);
        }

        bool RC4::Support(const ppp::string& method) noexcept {
            if (method.empty()) {
                return false;
            }

            if (method == "rc4-md5") {
                return true;
            }

            if (method == "rc4-sha1") {
                return true;
            }

            if (method == "rc4-sha224") {
                return true;
            }

            if (method == "rc4-sha256") {
                return true;
            }

            if (method == "rc4-sha386") {
                return true;
            }

            if (method == "rc4-sha512") {
                return true;
            }

            return false;
        }

        std::shared_ptr<RC4> RC4::Create(const ppp::string& method, const ppp::string& password) noexcept {
            if (method.empty()) {
                return NULL;
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

            if (method == "rc4-sha386") {
                return make_shared_object<RC4SHA386>(method, password);
            }

            if (method == "rc4-sha512") {
                return make_shared_object<RC4SHA512>(method, password);
            }

            return NULL;
        }
    }
}