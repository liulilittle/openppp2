// H4 TDD 测试 —— EVP 对 aes-*-cfb 的透明 AES-NI 加速 + simd-auto 开关。
// 行为无法从密文区分（aesni 与 openssl 密文位对位相同，见 compat_check），
// 故用 IsHardwareAccelerated() 观察后端选择。
#include <ppp/cryptography/EVP.h>

#include <cstdio>

using ppp::cryptography::EVP;

static int check(const char* what, bool cond) {
    printf("  %-58s : %s\n", what, cond ? "OK" : "FAIL");
    return cond ? 0 : 1;
}

int main() {
    int fails = 0;

    // 1) simd-auto 开启：aes-*-cfb 应透明走 AES-NI
    EVP::SetSimdAuto(true);
    { EVP e("aes-128-cfb", "pw"); fails += check("aes-128-cfb accelerated when simd-auto ON", e.IsHardwareAccelerated()); }
    { EVP e("aes-256-cfb", "pw"); fails += check("aes-256-cfb accelerated when simd-auto ON", e.IsHardwareAccelerated()); }

    // 2) simd-auto 关闭：回退 OpenSSL
    EVP::SetSimdAuto(false);
    { EVP e("aes-128-cfb", "pw"); fails += check("aes-128-cfb uses OpenSSL when simd-auto OFF", !e.IsHardwareAccelerated()); }
    EVP::SetSimdAuto(true);

    // 3) 显式 simd-aes-* 一直加速，不受开关影响（回归）
    { EVP e("simd-aes-128-cfb", "pw"); fails += check("simd-aes-128-cfb always accelerated", e.IsHardwareAccelerated()); }
    // 4) 非 AES 算法不受影响（回归）：rc4 不硬件加速
    { EVP e("rc4", "pw"); fails += check("rc4 not hardware-accelerated", !e.IsHardwareAccelerated()); }

    printf("\n%s (fails=%d)\n", fails == 0 ? "ALL PASS (GREEN)" : "RED", fails);
    return fails == 0 ? 0 : 1;
}
