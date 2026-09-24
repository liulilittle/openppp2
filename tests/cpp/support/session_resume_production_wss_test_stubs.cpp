#include <ppp/Random.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/cryptography/ssea.h>
#include <ppp/io/File.h>
#include <ppp/net/Ipep.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/threading/Executors.h>

#include <boost/uuid/random_generator.hpp>

#include <chrono>
#include <cstring>
#include <unistd.h>

namespace ppp {

namespace {
thread_local Random test_random;
}

boost::uuids::uuid GuidGenerate() noexcept {
    return boost::uuids::random_generator{}();
}

int RandomNext() noexcept {
    return test_random.Next(0, INT_MAX);
}

int RandomNext(int min_value, int max_value) noexcept {
    return test_random.Next(min_value, max_value);
}

const char* GetDefaultCipherSuites() noexcept {
    return "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
}

const char* GetPlatformCode() noexcept {
    return "X86_64";
}

} // namespace ppp

ppp::string chnroutes2_cacertpath_default() noexcept {
    return {};
}

namespace ppp::auxiliary {

Int128 StringAuxiliary::GuidStringToInt128(const boost::uuids::uuid& guid) noexcept {
    Int128 network_guid = 0;
    std::memcpy(&network_guid, guid.data, sizeof(network_guid));
    return net::Ipep::NetworkToHostOrder(network_guid);
}

} // namespace ppp::auxiliary

namespace ppp::io {

bool File::CanAccess(const char* path, FileAccess) noexcept {
    return path != nullptr && ::access(path, R_OK) == 0;
}

bool File::Exists(const char* path) noexcept {
    return path != nullptr && ::access(path, F_OK) == 0;
}

} // namespace ppp::io

namespace ppp::net {

ppp::string Ipep::ToIpepAddress(const IPEndPoint*) noexcept {
    return {};
}

} // namespace ppp::net

namespace ppp::configurations {

AppConfiguration::AppConfiguration() noexcept {
    tcp.connect.timeout = 5;
    tcp.connect.nexcept = 0;
    websocket.ssl.verify_peer = false;
    key.kf = 154543927;
    key.kh = 12;
    key.kl = 10;
    key.kx = 128;
    key.sb = 0;
    key.masked = false;
    key.plaintext = true;
    key.delta_encode = false;
    key.shuffle_data = false;
    key.simd_auto = true;
    _lcgmods[LCGMOD_TYPE_TRANSMISSION] =
        ppp::cryptography::ssea::lcgmod(key.kf, 64 * 64 * 64, 94 * 94 * 94);
    _lcgmods[LCGMOD_TYPE_STATIC] =
        ppp::cryptography::ssea::lcgmod(key.kf, 1 << 7, 1 << 8);
}

namespace extensions {

bool IsHaveCiphertext(const AppConfiguration&) noexcept {
    return false;
}

} // namespace extensions
} // namespace ppp::configurations

namespace ppp::threading {

void* BufferswapAllocator::Alloc(uint32_t) noexcept {
    return nullptr;
}

bool BufferswapAllocator::Free(const void*) noexcept {
    return false;
}

uint64_t Executors::GetTickCount() noexcept {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

std::shared_ptr<boost::asio::io_context> Executors::GetExecutor() noexcept {
    return nullptr;
}

std::shared_ptr<boost::asio::io_context> Executors::GetScheduler() noexcept {
    return nullptr;
}

} // namespace ppp::threading
