// Phase 1 探索验证 —— aes-*-cfb(OpenSSL EVP) 与 simd-aes-*(AES-NI) 的密文互操作性。
// 关键点：构造普通 aes-*-cfb 时显式关闭 simd-auto，确保比较的确是 OpenSSL vs AES-NI，
// 而不是被透明升级后误测成 AES-NI vs AES-NI。
#include <ppp/cryptography/EVP.h>

#include <cstdio>
#include <cstring>
#include <vector>

using ppp::Byte;
using ppp::cryptography::EVP;

static std::vector<Byte> payload(int n) {
    std::vector<Byte> v((size_t)n);
    for (int i = 0; i < n; ++i) v[(size_t)i] = (Byte)((i * 131 + 7) & 0xFF);
    return v;
}

static bool cross(const char* enc_method,
                  const char* dec_method,
                  const char* pw,
                  int n,
                  bool expected_enc_hw,
                  bool expected_dec_hw,
                  bool* byte_identical) {
    EVP::SetSimdAuto(false);
    EVP enc{ppp::string(enc_method), ppp::string(pw)};
    EVP dec{ppp::string(dec_method), ppp::string(pw)};
    EVP::SetSimdAuto(true);

    if (enc.IsHardwareAccelerated() != expected_enc_hw) {
        std::printf("  [%s] unexpected encrypt backend: hw=%d expected=%d\n",
                    enc_method, enc.IsHardwareAccelerated() ? 1 : 0, expected_enc_hw ? 1 : 0);
        return false;
    }
    if (dec.IsHardwareAccelerated() != expected_dec_hw) {
        std::printf("  [%s] unexpected decrypt backend: hw=%d expected=%d\n",
                    dec_method, dec.IsHardwareAccelerated() ? 1 : 0, expected_dec_hw ? 1 : 0);
        return false;
    }

    std::vector<Byte> data = payload(n);

    int clen = 0;
    auto ct = enc.Encrypt(nullptr, data.data(), n, clen);
    if (!ct || clen <= 0) {
        std::printf("  [%s->%s] encrypt failed\n", enc_method, dec_method);
        return false;
    }

    int plen = 0;
    auto pt = dec.Decrypt(nullptr, ct.get(), clen, plen);
    bool ok = pt && plen == n && std::memcmp(pt.get(), data.data(), (size_t)n) == 0;

    if (byte_identical) {
        int clen2 = 0;
        auto ct2 = dec.Encrypt(nullptr, data.data(), n, clen2);
        *byte_identical = ct2 && clen2 == clen &&
            std::memcmp(ct.get(), ct2.get(), (size_t)clen) == 0;
    }
    return ok;
}

int main() {
    const char* pw = "interop-test-password";
    int fails = 0;
    struct { const char* openssl; const char* simd; } pairs[] = {
        {"aes-128-cfb", "simd-aes-128-cfb"},
        {"aes-256-cfb", "simd-aes-256-cfb"},
    };

    for (auto& p : pairs) {
        bool ident_ab = false;
        bool ident_ba = false;
        bool ab = cross(p.openssl, p.simd, pw, 512, false, true, &ident_ab);
        bool ba = cross(p.simd, p.openssl, pw, 512, true, false, &ident_ba);
        std::printf("%-16s <-> %-20s : openssl->aesni=%s  aesni->openssl=%s  ciphertext-identical=%s\n",
                    p.openssl, p.simd,
                    ab ? "OK" : "FAIL",
                    ba ? "OK" : "FAIL",
                    (ident_ab && ident_ba) ? "YES" : "NO");
        if (!ab || !ba || !ident_ab || !ident_ba) ++fails;
    }

    std::printf("\nRESULT: %s\n",
                fails == 0 ? "INTEROPERABLE (透明加速可行)" : "NOT interoperable");
    return fails == 0 ? 0 : 1;
}
