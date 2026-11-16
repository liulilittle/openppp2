#include <ppp/cryptography/Ciphertext.h>
#include <ppp/cryptography/EVP.h>

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void Require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

// EncryptTo() writes into caller memory; it must produce exactly the bytes Encrypt()
// returns, because the transmission frame path switched to it without a wire change.
void CheckMethod(const char* method) {
    if (!ppp::cryptography::Ciphertext::Support(method)) {
        std::cout << "skip: " << method << " not supported here" << std::endl;
        return;
    }

    for (int length : { 1, 15, 16, 17, 1400, 65535 }) {
        std::vector<ppp::Byte> plaintext(length);
        for (int i = 0; i < length; i++) {
            plaintext[i] = static_cast<ppp::Byte>(i * 31 + 7);
        }

        // Fresh instances per call so stateful backends start from the same state.
        auto reference = std::make_shared<ppp::cryptography::Ciphertext>(method, "encrypt-to-test");
        auto candidate = std::make_shared<ppp::cryptography::Ciphertext>(method, "encrypt-to-test");

        int expected_length = 0;
        std::shared_ptr<ppp::Byte> expected = reference->Encrypt(nullptr, plaintext.data(), length, expected_length);
        Require(expected != nullptr && expected_length == length, std::string(method) + ": Encrypt failed");

        std::vector<ppp::Byte> output(length + ppp::cryptography::Ciphertext::EncryptToSlack + 8, 0xA5);
        int actual_length = 0;
        Require(candidate->EncryptTo(output.data() + 8, static_cast<int>(output.size()) - 8, plaintext.data(), length, actual_length),
            std::string(method) + ": EncryptTo failed");
        Require(actual_length == expected_length, std::string(method) + ": EncryptTo length differs");
        Require(std::memcmp(output.data() + 8, expected.get(), length) == 0, std::string(method) + ": EncryptTo bytes differ");
        for (int i = 0; i < 8; i++) {
            Require(output[i] == 0xA5, std::string(method) + ": EncryptTo wrote before the output pointer");
        }

        auto decoder = std::make_shared<ppp::cryptography::Ciphertext>(method, "encrypt-to-test");
        int decoded_length = 0;
        std::shared_ptr<ppp::Byte> decoded = decoder->Decrypt(nullptr, output.data() + 8, actual_length, decoded_length);
        Require(decoded != nullptr && decoded_length == length && std::memcmp(decoded.get(), plaintext.data(), length) == 0,
            std::string(method) + ": EncryptTo output does not decrypt");

        // The receive path decrypts the transport layer in place when the backend allows it.
        auto inplace = std::make_shared<ppp::cryptography::Ciphertext>(method, "encrypt-to-test");
        if (inplace->CanDecryptInPlace()) {
            std::vector<ppp::Byte> buffer(output.begin() + 8, output.begin() + 8 + actual_length);
            Require(inplace->DecryptInPlace(buffer.data(), actual_length),
                std::string(method) + ": DecryptInPlace failed");
            Require(std::memcmp(buffer.data(), plaintext.data(), length) == 0,
                std::string(method) + ": DecryptInPlace bytes differ");
        }
    }

    ppp::Byte input[4] = { 1, 2, 3, 4 };
    ppp::Byte small[2] = {};
    int ignored = 0;
    auto cipher = std::make_shared<ppp::cryptography::Ciphertext>(method, "encrypt-to-test");
    Require(!cipher->EncryptTo(small, sizeof(small), input, sizeof(input), ignored),
        std::string(method) + ": EncryptTo accepted an undersized output");

    std::cout << "ok: " << method << std::endl;
}

// The AES-NI kernels must stay byte-compatible with OpenSSL, the fallback a peer
// without AES-NI (or on ARM) uses for the same method name.
void CheckSimdMatchesOpenSsl(const char* method) {
    for (int length : { 1, 16, 63, 64, 65, 1400, 4099 }) {
        std::vector<ppp::Byte> plaintext(length);
        for (int i = 0; i < length; i++) {
            plaintext[i] = static_cast<ppp::Byte>(i * 13 + 5);
        }

        ppp::cryptography::EVP::SetSimdAuto(false);
        auto openssl = std::make_shared<ppp::cryptography::Ciphertext>(method, "simd-compat-test");
        ppp::cryptography::EVP::SetSimdAuto(true);
        auto simd = std::make_shared<ppp::cryptography::Ciphertext>(method, "simd-compat-test");

        int expected_length = 0;
        int actual_length = 0;
        std::shared_ptr<ppp::Byte> expected = openssl->Encrypt(nullptr, plaintext.data(), length, expected_length);
        std::shared_ptr<ppp::Byte> actual = simd->Encrypt(nullptr, plaintext.data(), length, actual_length);
        Require(expected != nullptr && actual != nullptr && expected_length == length && actual_length == length,
            std::string(method) + ": simd/OpenSSL encrypt failed");
        Require(std::memcmp(expected.get(), actual.get(), length) == 0,
            std::string(method) + ": simd ciphertext differs from OpenSSL");

        // Every packet restarts from the fixed IV: reusing one instance (the EVP
        // path keeps its key schedule and only rewinds the IV) must repeat exactly.
        for (int round = 0; round < 3; round++) {
            std::vector<ppp::Byte> again(length + ppp::cryptography::Ciphertext::EncryptToSlack);
            int again_length = 0;
            Require(openssl->EncryptTo(again.data(), static_cast<int>(again.size()), plaintext.data(), length, again_length) &&
                again_length == length && std::memcmp(again.data(), expected.get(), length) == 0,
                std::string(method) + ": reused OpenSSL encrypt context diverged");

            int decoded_length = 0;
            std::shared_ptr<ppp::Byte> decoded = openssl->Decrypt(nullptr, again.data(), length, decoded_length);
            Require(decoded != nullptr && decoded_length == length && std::memcmp(decoded.get(), plaintext.data(), length) == 0,
                std::string(method) + ": reused OpenSSL decrypt context diverged");
        }

        Require(simd->CanDecryptInPlace() && openssl->CanDecryptInPlace(),
            std::string(method) + ": stream mode should support in-place decrypt");
        std::vector<ppp::Byte> a(expected.get(), expected.get() + length);
        std::vector<ppp::Byte> b(a);
        Require(openssl->DecryptInPlace(a.data(), length) && simd->DecryptInPlace(b.data(), length),
            std::string(method) + ": simd/OpenSSL in-place decrypt failed");
        Require(std::memcmp(a.data(), plaintext.data(), length) == 0 && std::memcmp(b.data(), plaintext.data(), length) == 0,
            std::string(method) + ": simd/OpenSSL in-place decrypt differs");
    }

    std::cout << "ok: simd matches OpenSSL for " << method << std::endl;
}

} // namespace

int main() {
    try {
        for (const char* method : { "aes-128-cfb", "aes-256-cfb", "simd-aes-128-cfb", "simd-aes-256-cfb",
                 "aes-128-ctr", "aes-256-gcm", "chacha20", "rc4-md5", "rc4-sha256" }) {
            CheckMethod(method);
        }

        for (const char* method : { "aes-128-cfb", "aes-256-cfb", "aes-128-gcm", "aes-256-gcm", "aes-128-ctr", "chacha20" }) {
            CheckSimdMatchesOpenSsl(method);
        }

        // Block modes hold back their tail block, so they must keep the allocating path.
        auto cbc = std::make_shared<ppp::cryptography::Ciphertext>("aes-256-cbc", "encrypt-to-test");
        Require(!cbc->CanDecryptInPlace(), "aes-256-cbc must not report in-place decrypt");
    }
    catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "PASS: ciphertext_encrypt_to_test" << std::endl;
    return 0;
}
