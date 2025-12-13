#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    namespace cryptography {
        enum DigestAlgorithmic {
            DigestAlgorithmic_md5,
            DigestAlgorithmic_sha1,
            DigestAlgorithmic_sha224,
            DigestAlgorithmic_sha256,
            DigestAlgorithmic_sha386,
            DigestAlgorithmic_sha512,
        };

        ppp::string     hash_hmac(const void* data, int size, DigestAlgorithmic agorithm, bool toupper) noexcept;
        ppp::string     hash_hmac(const void* data, int size, DigestAlgorithmic agorithm, bool hex_or_binarys, bool toupper) noexcept;
        bool            hash_hmac(const void* data, int size, ppp::string& digest, DigestAlgorithmic agorithm, bool hex_or_binarys, bool toupper) noexcept;
    }
}