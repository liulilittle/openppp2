#include <benchmark/benchmark.h>

#include <array>
#include <charconv>
#include <cstring>
#include <string_view>

namespace {
struct Endpoint {
    std::string_view host;
    unsigned short port;
};

size_t encode(const Endpoint& endpoint, unsigned char* output) {
    output[0] = static_cast<unsigned char>(endpoint.host.size());
    std::memcpy(output + 1, endpoint.host.data(), endpoint.host.size());
    char* port = reinterpret_cast<char*>(output + 2 + endpoint.host.size());
    auto result = std::to_chars(port, port + 5, endpoint.port);
    output[1 + endpoint.host.size()] = static_cast<unsigned char>(result.ptr - port);
    return static_cast<size_t>(result.ptr - reinterpret_cast<char*>(output));
}

bool decode(const unsigned char* input, size_t size, Endpoint& endpoint) {
    if (size < 3 || input[0] + 2 > size) return false;
    const size_t host_size = input[0];
    const size_t port_size = input[host_size + 1];
    if (host_size + port_size + 2 != size) return false;
    unsigned short port = 0;
    const char* first = reinterpret_cast<const char*>(input + host_size + 2);
    auto result = std::from_chars(first, first + port_size, port);
    if (result.ec != std::errc{} || result.ptr != first + port_size || port == 0) return false;
    endpoint = {std::string_view(reinterpret_cast<const char*>(input + 1), host_size), port};
    return true;
}

bool roundtrip_ok(std::string_view host) {
    std::array<unsigned char, 300> bytes{};
    Endpoint decoded{};
    const size_t size = encode({host, 65535}, bytes.data());
    return decode(bytes.data(), size, decoded) && decoded.host == host && decoded.port == 65535;
}

void BM_EndpointRoundTrip(benchmark::State& state, std::string_view host) {
    if (!roundtrip_ok(host)) {
        state.SkipWithError("endpoint wire-format roundtrip failed");
        return;
    }
    std::array<unsigned char, 300> bytes{};
    for (auto _ : state) {
        Endpoint decoded{};
        const size_t size = encode({host, 65535}, bytes.data());
        benchmark::DoNotOptimize(decode(bytes.data(), size, decoded));
    }
    state.SetItemsProcessed(state.iterations());
    state.counters["allocations"] = 0;
}
} // namespace

BENCHMARK_CAPTURE(BM_EndpointRoundTrip, ipv4, std::string_view("192.0.2.1"));
BENCHMARK_CAPTURE(BM_EndpointRoundTrip, ipv6, std::string_view("2001:db8::1"));
BENCHMARK_CAPTURE(BM_EndpointRoundTrip, hostname, std::string_view("vpn.example.test"));
BENCHMARK_MAIN();
