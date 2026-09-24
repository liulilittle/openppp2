#include <ppp/app/client/routing/ProtocolSniffer.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

using ppp::app::client::routing::ProtocolSniffer;
using ppp::app::client::routing::ProtocolSnifferResult;
using ppp::app::client::routing::ProtocolSnifferSource;
using ppp::app::client::routing::ProtocolSnifferStatus;

namespace {

void AppendU16(std::vector<std::uint8_t>& bytes, std::size_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xff));
}

void AppendU24(std::vector<std::uint8_t>& bytes, std::size_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xff));
}

std::vector<std::uint8_t> MakeClientHello(
    std::string_view hostname, bool include_sni = true, bool include_ech = false) {
    std::vector<std::uint8_t> body;
    AppendU16(body, 0x0303);
    body.insert(body.end(), 32, 0x42);
    body.push_back(0);
    AppendU16(body, 2);
    AppendU16(body, 0x1301);
    body.push_back(1);
    body.push_back(0);

    std::vector<std::uint8_t> extensions;
    if (include_sni) {
        std::vector<std::uint8_t> names;
        names.push_back(0);
        AppendU16(names, hostname.size());
        names.insert(names.end(), hostname.begin(), hostname.end());
        AppendU16(extensions, 0);
        AppendU16(extensions, names.size() + 2);
        AppendU16(extensions, names.size());
        extensions.insert(extensions.end(), names.begin(), names.end());
    }
    if (include_ech) {
        AppendU16(extensions, 0xfe0d);
        AppendU16(extensions, 1);
        extensions.push_back(0);
    }
    AppendU16(body, extensions.size());
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<std::uint8_t> handshake;
    handshake.push_back(1);
    AppendU24(handshake, body.size());
    handshake.insert(handshake.end(), body.begin(), body.end());
    return handshake;
}

std::vector<std::uint8_t> MakeTlsRecords(
    const std::vector<std::uint8_t>& handshake,
    std::initializer_list<std::size_t> record_sizes) {
    std::vector<std::uint8_t> records;
    std::size_t offset = 0;
    for (const std::size_t requested : record_sizes) {
        const std::size_t count = std::min(requested, handshake.size() - offset);
        records.push_back(0x16);
        records.push_back(0x03);
        records.push_back(0x03);
        AppendU16(records, count);
        records.insert(records.end(), handshake.begin() + offset,
            handshake.begin() + offset + count);
        offset += count;
    }
    if (offset < handshake.size()) {
        records.push_back(0x16);
        records.push_back(0x03);
        records.push_back(0x03);
        AppendU16(records, handshake.size() - offset);
        records.insert(records.end(), handshake.begin() + offset, handshake.end());
    }
    return records;
}

ProtocolSnifferResult FeedBytes(
    ProtocolSniffer& sniffer, const std::vector<std::uint8_t>& bytes) {
    return sniffer.Feed(bytes.data(), bytes.size());
}

void ExpectStatus(const ProtocolSnifferResult& result, ProtocolSnifferStatus status) {
    assert(result.status == status);
    if (status != ProtocolSnifferStatus::Complete) {
        assert(result.domain.empty());
        assert(result.source == ProtocolSnifferSource::None);
    }
}

void TestTlsFragmentation() {
    const auto records = MakeTlsRecords(MakeClientHello("WWW.Example.COM."), {4096});
    for (std::size_t split = 1; split < records.size(); ++split) {
        ProtocolSniffer sniffer;
        ExpectStatus(sniffer.Feed(records.data(), split), ProtocolSnifferStatus::NeedMore);
        const auto result = sniffer.Feed(records.data() + split, records.size() - split);
        ExpectStatus(result, ProtocolSnifferStatus::Complete);
        assert(result.domain == "www.example.com");
        assert(result.source == ProtocolSnifferSource::TlsSni);
    }
}

void TestTlsAcrossRecords() {
    const auto records = MakeTlsRecords(MakeClientHello("split.example"), {2, 3, 7, 11});
    ProtocolSniffer sniffer;
    const auto result = FeedBytes(sniffer, records);
    ExpectStatus(result, ProtocolSnifferStatus::Complete);
    assert(result.domain == "split.example");
    assert(result.source == ProtocolSnifferSource::TlsSni);
}

void TestTlsWithoutSniAndEchOuter() {
    const std::vector<std::vector<std::uint8_t>> hellos = {
        MakeClientHello("", false, false),
        MakeClientHello("", false, true),
    };
    for (const auto& hello : hellos) {
        ProtocolSniffer sniffer;
        ExpectStatus(FeedBytes(sniffer, MakeTlsRecords(hello, {4096})),
            ProtocolSnifferStatus::Unsupported);
    }
}

void TestTlsMalformedLengthsAndNames() {
    {
        ProtocolSniffer sniffer;
        const std::vector<std::uint8_t> oversized_record = {0x16, 0x03, 0x03, 0x40, 0x01};
        ExpectStatus(FeedBytes(sniffer, oversized_record), ProtocolSnifferStatus::Malformed);
    }
    {
        auto hello = MakeClientHello("example.com");
        hello[1] = 0x01;
        hello[2] = 0x00;
        hello[3] = 0x00;
        ProtocolSniffer sniffer;
        ExpectStatus(FeedBytes(sniffer, MakeTlsRecords(hello, {4096})),
            ProtocolSnifferStatus::Malformed);
    }
    const std::vector<std::string> invalid_names = {
        "-bad.example",
        "bad_.example",
        "bad..example",
        std::string(64, 'a') + ".example",
    };
    for (const auto& name : invalid_names) {
        ProtocolSniffer sniffer;
        ExpectStatus(FeedBytes(sniffer, MakeTlsRecords(MakeClientHello(name), {4096})),
            ProtocolSnifferStatus::Malformed);
    }
}

void TestHttpHost() {
    const std::string request =
        "GET /path HTTP/1.1\r\nUser-Agent: test\r\nHost:\tWWW.Example.COM.:443 \r\n\r\n";
    for (std::size_t split = 1; split < request.size(); ++split) {
        ProtocolSniffer sniffer;
        ExpectStatus(sniffer.Feed(request.data(), split), ProtocolSnifferStatus::NeedMore);
        const auto result = sniffer.Feed(request.data() + split, request.size() - split);
        ExpectStatus(result, ProtocolSnifferStatus::Complete);
        assert(result.domain == "www.example.com");
        assert(result.source == ProtocolSnifferSource::HttpHost);
    }
}

void TestHttpDuplicateInvalidAndIpv6Host() {
    const std::vector<std::string> malformed = {
        "GET / HTTP/1.1\r\nHost: one.example\r\nHost: two.example\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: -bad.example\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: bad_.example\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: example.com:99999\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: [not-ipv6]\r\n\r\n",
        "GET / HTTP/1.1\nHost: example.com\n\n",
        "GET / HTTP/1.1\r\n folded: value\r\nHost: example.com\r\n\r\n",
    };
    for (const auto& request : malformed) {
        ProtocolSniffer sniffer;
        ExpectStatus(sniffer.Feed(request.data(), request.size()),
            ProtocolSnifferStatus::Malformed);
    }

    for (const std::string request : {
        "GET / HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n",
        "GET / HTTP/1.0\r\nUser-Agent: test\r\n\r\n"}) {
        ProtocolSniffer sniffer;
        ExpectStatus(sniffer.Feed(request.data(), request.size()),
            ProtocolSnifferStatus::Unsupported);
    }
}

void TestLimitsAndUnsupported() {
    {
        ProtocolSniffer sniffer;
        std::vector<std::uint8_t> bytes(ProtocolSniffer::MaxInputSize, 'G');
        ExpectStatus(FeedBytes(sniffer, bytes), ProtocolSnifferStatus::LimitExceeded);
    }
    {
        ProtocolSniffer sniffer;
        const std::string prefix = "GET / HTTP/1.1\r\nX: ";
        std::vector<std::uint8_t> bytes(ProtocolSniffer::MaxInputSize, 'a');
        std::copy(prefix.begin(), prefix.end(), bytes.begin());
        ExpectStatus(FeedBytes(sniffer, bytes), ProtocolSnifferStatus::LimitExceeded);
    }
    {
        ProtocolSniffer sniffer;
        const auto records = MakeTlsRecords(MakeClientHello("many.example"),
            {1, 1, 1, 1, 1, 1, 1, 1, 1});
        ExpectStatus(FeedBytes(sniffer, records), ProtocolSnifferStatus::LimitExceeded);
    }
    const std::vector<std::vector<std::uint8_t>> unsupported = {
        {'S', 'S', 'H', '-', '2', '.', '0', '\r', '\n'},
        {0x05, 0x01, 0x00},
        MakeTlsRecords(std::vector<std::uint8_t>{0x02, 0, 0, 0}, {4}),
    };
    for (const auto& bytes : unsupported) {
        ProtocolSniffer sniffer;
        ExpectStatus(FeedBytes(sniffer, bytes), ProtocolSnifferStatus::Unsupported);
    }
}

void TestMalformedCorpus() {
    const std::vector<std::vector<std::uint8_t>> corpus = {
        {0x16, 0x02, 0x00, 0x00, 0x01, 0x00},
        {0x16, 0x03, 0x03, 0x00, 0x00},
        MakeTlsRecords(std::vector<std::uint8_t>{0x01, 0, 0, 1, 0}, {5}),
    };
    for (const auto& bytes : corpus) {
        ProtocolSniffer sniffer;
        ExpectStatus(FeedBytes(sniffer, bytes), ProtocolSnifferStatus::Malformed);
    }

    const std::vector<std::string> http_corpus = {
        "GET  HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET / HTTP/1.1 extra\r\nHost: example.com\r\n\r\n",
        "GET / HTTP/1.1\r\nBad Header: x\r\nHost: example.com\r\n\r\n",
        "GET / HTTP/1.1\r\nHost:\r\n\r\n",
    };
    for (const auto& bytes : http_corpus) {
        ProtocolSniffer sniffer;
        ExpectStatus(sniffer.Feed(bytes.data(), bytes.size()),
            ProtocolSnifferStatus::Malformed);
    }
}

} // namespace

int main() {
    TestTlsFragmentation();
    TestTlsAcrossRecords();
    TestTlsWithoutSniAndEchOuter();
    TestTlsMalformedLengthsAndNames();
    TestHttpHost();
    TestHttpDuplicateInvalidAndIpv6Host();
    TestLimitsAndUnsupported();
    TestMalformedCorpus();
    return 0;
}
