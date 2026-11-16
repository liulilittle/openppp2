#include <ppp/cryptography/Ciphertext.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file Ciphertext.cpp
 * @brief Implements a backend-dispatching cipher wrapper.
 */

namespace ppp {
    namespace cryptography {
        /**
         * @brief Initializes the wrapper with either EVP or RC4 depending on method support.
         * @param method Cipher method name.
         * @param password Password used to initialize the selected backend.
         */
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

        /**
         * @brief Encrypts data through the initialized backend.
         * @param allocator Output allocator.
         * @param data Plaintext bytes.
         * @param datalen Plaintext size.
         * @param outlen Receives encrypted size, or -1 if no backend is available.
         * @return Encrypted bytes on success, or null on failure.
         */
        std::shared_ptr<Byte> Ciphertext::Encrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept {
            outlen = -1;

            if (NULLPTR != evp_) {
                return evp_->Encrypt(allocator, data, datalen, outlen);
            }

            if (NULLPTR != rc4_) {
                return rc4_->Encrypt(allocator, data, datalen, outlen);
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::CryptoAlgorithmUnsupported);
            return NULLPTR;
        }

        /**
         * @brief Encrypts data through the initialized backend into caller-owned memory.
         */
        bool Ciphertext::EncryptTo(Byte* output, int output_capacity, Byte* data, int datalen, int& outlen) noexcept {
            outlen = -1;

            if (NULLPTR != evp_) {
                return evp_->EncryptTo(output, output_capacity, data, datalen, outlen);
            }

            if (NULLPTR != rc4_) {
                return rc4_->EncryptTo(output, output_capacity, data, datalen, outlen);
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::CryptoAlgorithmUnsupported);
            return false;
        }

        /**
         * @brief Decrypts data through the initialized backend.
         * @param allocator Output allocator.
         * @param data Ciphertext bytes.
         * @param datalen Ciphertext size.
         * @param outlen Receives plaintext size, or -1 if no backend is available.
         * @return Decrypted bytes on success, or null on failure.
         */
        std::shared_ptr<Byte> Ciphertext::Decrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept {
            outlen = -1;

            if (NULLPTR != evp_) {
                return evp_->Decrypt(allocator, data, datalen, outlen);
            }

            if (NULLPTR != rc4_) {
                return rc4_->Decrypt(allocator, data, datalen, outlen);
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::CryptoAlgorithmUnsupported);
            return NULLPTR;
        }

        bool Ciphertext::CanDecryptInPlace() const noexcept {
            if (NULLPTR != evp_) {
                return evp_->CanDecryptInPlace();
            }

            return NULLPTR != rc4_;
        }

        /**
         * @brief Decrypts data in place through the initialized backend.
         */
        bool Ciphertext::DecryptInPlace(Byte* data, int datalen) noexcept {
            if (NULLPTR != evp_) {
                return evp_->DecryptInPlace(data, datalen);
            }

            if (NULLPTR != rc4_) {
                return rc4_->DecryptInPlace(data, datalen);
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::CryptoAlgorithmUnsupported);
            return false;
        }

        /**
         * @brief Reports whether a method can be handled by EVP or RC4.
         * @param method Cipher method name.
         * @return True if either backend supports the method.
         */
        bool Ciphertext::Support(const ppp::string& method) noexcept {
            if (method.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::CiphertextSupportMethodEmpty);
                return false;
            }

            return EVP::Support(method) || RC4::Support(method);
        }
    }
}
