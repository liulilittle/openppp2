#include <benchmark/benchmark.h>

#include <ppp/cryptography/Ciphertext.h>
#include <ppp/cryptography/EVP.h>
#include <ppp/cryptography/ssea.h>

#include <array>
#include <cstring>
#include <vector>

using ppp::Byte;
using ppp::cryptography::Ciphertext;
using ppp::cryptography::EVP;
using ppp::cryptography::ssea;

namespace {
struct Chain {
    std::shared_ptr<Ciphertext> protocol;
    std::shared_ptr<Ciphertext> transport;

    explicit Chain(const char* method) {
        EVP::SetSimdAuto(false);
        protocol = std::make_shared<Ciphertext>(ppp::string(method), ppp::string("protocol-key"));
        transport = std::make_shared<Ciphertext>(ppp::string(method), ppp::string("transport-key"));
        EVP::SetSimdAuto(true);
    }

    std::shared_ptr<Byte> encrypt(Byte* input, int size, int& output_size) {
        int payload_size = 0;
        auto payload = transport->Encrypt(nullptr, input, size, payload_size);
        if (!payload || payload_size != size) return nullptr;

        const int kf = 0x4f13 ^ 0x5a;
        ssea::masked_xor_random_next(payload.get(), payload.get() + payload_size, kf);
        ssea::shuffle_data(reinterpret_cast<char*>(payload.get()), payload_size, kf);
        std::shared_ptr<Byte> encoded;
        if (ssea::delta_encode(nullptr, payload.get(), payload_size, 0x4f13, encoded) != payload_size) return nullptr;

        std::array<Byte, 3> header{{0x5a, static_cast<Byte>((size - 1) >> 8), static_cast<Byte>((size - 1) & 0xff)}};
        int encrypted_header_size = 0;
        auto encrypted_header = protocol->Encrypt(nullptr, header.data() + 1, 2, encrypted_header_size);
        if (!encrypted_header || encrypted_header_size != 2) return nullptr;
        std::memcpy(header.data() + 1, encrypted_header.get(), 2);
        header[1] ^= static_cast<Byte>(kf);
        header[2] ^= static_cast<Byte>(kf);
        ssea::shuffle_data(reinterpret_cast<char*>(header.data() + 1), 2, kf);
        std::shared_ptr<Byte> encoded_header;
        if (ssea::delta_encode(nullptr, header.data(), static_cast<int>(header.size()), 0x4f13, encoded_header) !=
            static_cast<int>(header.size())) return nullptr;

        output_size = static_cast<int>(header.size()) + payload_size;
        auto output = ppp::threading::BufferswapAllocator::MakeByteArray(nullptr, output_size);
        if (!output) return nullptr;
        std::memcpy(output.get(), encoded_header.get(), header.size());
        std::memcpy(output.get() + header.size(), encoded.get(), payload_size);
        return output;
    }
};

void BM_CryptoChain(benchmark::State& state, const char* method) {
    if (!Ciphertext::Support(ppp::string(method))) {
        state.SkipWithError("cipher method not supported");
        return;
    }
    Chain chain(method);
    std::vector<Byte> payload(static_cast<size_t>(state.range(0)), 0x2a);
    int check_size = 0;
    if (!chain.encrypt(payload.data(), static_cast<int>(payload.size()), check_size) ||
        check_size != static_cast<int>(payload.size()) + 3) {
        state.SkipWithError("full crypto-chain self-check failed");
        return;
    }
    for (auto _ : state) {
        int output_size = 0;
        auto output = chain.encrypt(payload.data(), static_cast<int>(payload.size()), output_size);
        benchmark::DoNotOptimize(output.get());
        benchmark::DoNotOptimize(output_size);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(payload.size()));
    state.counters["allocations"] = 5;
}
} // namespace

#define REGISTER(name, method) \
    BENCHMARK_CAPTURE(BM_CryptoChain, name, method)->Arg(64)->Arg(1400)
REGISTER(openssl, "aes-256-cfb");
REGISTER(simd, "simd-aes-256-cfb");
#undef REGISTER
BENCHMARK_MAIN();
