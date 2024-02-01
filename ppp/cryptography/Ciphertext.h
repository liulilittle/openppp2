#pragma once

#include <ppp/cryptography/EVP.h>
#include <ppp/cryptography/rc4.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace cryptography {
        class Ciphertext : public std::enable_shared_from_this<Ciphertext> {
        public:
            Ciphertext(const ppp::string& method, const ppp::string& password) noexcept;

        public:
            std::shared_ptr<Byte>                               Encrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept;
            std::shared_ptr<Byte>                               Decrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept;
            std::shared_ptr<Ciphertext>                         GetReference() noexcept { return this->shared_from_this(); }
            static bool                                         Support(const ppp::string& method) noexcept;

        private:
            std::shared_ptr<RC4>                                rc4_;
            std::shared_ptr<EVP>                                evp_;
        };
    }
}