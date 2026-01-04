#include <ppp/cryptography/Ciphertext.h>

namespace ppp {
    namespace cryptography {
        Ciphertext::Ciphertext(const ppp::string& method, const ppp::string& password) noexcept {
            if (method.size() > 0 && password.size() > 0) {
                if (EVP::Support(method)) {
                    evp_ = make_shared_object<EVP>(method, password);
                }
                elif(RC4::Support(method)) {
                    rc4_ = RC4::Create(method, password);
                }
            }
        }

        std::shared_ptr<Byte> Ciphertext::Encrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept {
            outlen = -1;

            if (NULLPTR != evp_) {
                return evp_->Encrypt(allocator, data, datalen, outlen);
            }

            if (NULLPTR != rc4_) {
                return rc4_->Encrypt(allocator, data, datalen, outlen);
            }

            return NULLPTR;
        }

        std::shared_ptr<Byte> Ciphertext::Decrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept {
            outlen = -1;

            if (NULLPTR != evp_) {
                return evp_->Decrypt(allocator, data, datalen, outlen);
            }

            if (NULLPTR != rc4_) {
                return rc4_->Decrypt(allocator, data, datalen, outlen);
            }

            return NULLPTR;
        }

        bool Ciphertext::Support(const ppp::string& method) noexcept {
            if (method.empty()) {
                return false;
            }

            return EVP::Support(method) || RC4::Support(method);
        }
    }
}