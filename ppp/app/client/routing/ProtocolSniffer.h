#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ppp::app::client::routing {

    enum class ProtocolSnifferStatus {
        NeedMore,
        Complete,
        Unsupported,
        Malformed,
        LimitExceeded,
    };

    enum class ProtocolSnifferSource {
        None,
        TlsSni,
        HttpHost,
    };

    struct ProtocolSnifferResult final {
        ProtocolSnifferStatus status = ProtocolSnifferStatus::NeedMore;
        std::string domain;
        ProtocolSnifferSource source = ProtocolSnifferSource::None;
    };

    class ProtocolSniffer final {
    public:
        static constexpr std::size_t MaxInputSize = 16 * 1024;
        static constexpr std::size_t MaxTlsRecordCount = 8;

        ProtocolSnifferResult Feed(const void* data, std::size_t length);
        const ProtocolSnifferResult& GetResult() const noexcept;

    private:
        ProtocolSnifferResult Parse() const;
        ProtocolSnifferResult ParseTls() const;
        ProtocolSnifferResult ParseHttp() const;

        std::vector<std::uint8_t> input_;
        ProtocolSnifferResult result_;
    };

} // namespace ppp::app::client::routing
