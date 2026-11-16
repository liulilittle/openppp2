#include "DnsFakeIpResponse.h"

#include <common/dnslib/message.h>

namespace {
using ppp::Byte;
using ppp::vector;

bool ValidateEdnsOptions(const std::vector<uint8_t>& data) noexcept {
    std::size_t offset = 0;
    while (offset < data.size()) {
        if (data.size() - offset < 4) return false;
        const uint16_t code = static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
        const std::size_t length = static_cast<std::size_t>((data[offset + 2] << 8) | data[offset + 3]);
        offset += 4;
        if (length > data.size() - offset) return false;
        const auto* value = data.data() + offset;
        switch (code) {
            case 3: // NSID is a zero-length request option.
            case 11: // TCP keepalive request.
                if (length != 0) return false;
                break;
            case 8: { // Client ECS query: scope prefix must be zero.
                if (length < 4) return false;
                const uint16_t family = static_cast<uint16_t>((value[0] << 8) | value[1]);
                const unsigned max_prefix = family == 1 ? 32u : family == 2 ? 128u : 0u;
                const unsigned source_prefix = value[2];
                if (!max_prefix || source_prefix > max_prefix || value[3] != 0 ||
                    length != 4u + (source_prefix + 7u) / 8u) return false;
                const unsigned remainder = source_prefix & 7u;
                if (remainder && length > 4) {
                    const uint8_t unused_mask = static_cast<uint8_t>((1u << (8u - remainder)) - 1u);
                    if ((value[length - 1] & unused_mask) != 0) return false;
                }
                break;
            }
            case 10: // Client cookie, optionally followed by a server cookie.
                if (length != 8 && (length < 16 || length > 40)) return false;
                break;
            case 12: // Padding bytes are required to be zero.
                for (std::size_t i = 0; i < length; ++i) if (value[i] != 0) return false;
                break;
            default:
                return false;
        }
        offset += length;
    }
    return true;
}

ppp::app::client::dns::DnsFakeIpResponse::AQueryStatus DecodeAQueryV2(
    const Byte* packet, int length, ::dns::Message& query) {
    using Status = ppp::app::client::dns::DnsFakeIpResponse::AQueryStatus;
    if (!packet || length < 12 || length > 65535) return Status::Invalid;
    if (query.decode(packet, static_cast<std::size_t>(length)) != ::dns::BufferResult::NoError)
        return Status::Invalid;
    if (query.questions.size() != 1 || query.questions.front().mType != ::dns::RecordType::kA ||
        query.questions.front().mClass != ::dns::RecordClass::kIN || !query.answers.empty() ||
        !query.authorities.empty() || query.mQr || query.mOpCode || query.mAA || query.mTC ||
        query.mRA || query.mRCode || (packet[2] & 0xfe) != 0 || (packet[3] & 0xcf) != 0)
        return Status::Invalid;

    if (query.additions.empty()) return Status::Supported;
    if (query.additions.size() != 1) return Status::Unsupported;
    auto& opt = query.additions.front();
    if (opt.mType != ::dns::RecordType::kOPT || !opt.mName.empty() ||
        static_cast<uint16_t>(opt.mClass) < 512 || (opt.mTtl >> 24) != 0 ||
        ((opt.mTtl >> 16) & 0xff) != 0 || (opt.mTtl & 0x7fff) != 0)
        return Status::Unsupported;
    const auto options = opt.getRData<::dns::RDataOPT>();
    if (!options || !ValidateEdnsOptions(options->mData)) return Status::Unsupported;
    return Status::Supported;
}

vector<Byte> EncodeV2(::dns::Message& message) {
    vector<Byte> response(65535);
    std::size_t encoded_size = 0;
    if (message.encode(response.data(), response.size(), encoded_size) != ::dns::BufferResult::NoError)
        return {};
    response.resize(encoded_size);
    return response;
}
}

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                static int LocateQuestionEnd(const Byte* packet, int length) noexcept {
                    if (NULLPTR == packet || length < 12) {
                        return 0;
                    }

                    int qdcount = (static_cast<int>(packet[4]) << 8) | packet[5];
                    if (qdcount != 1) {
                        return 0;
                    }

                    int pos = 12;
                    while (pos < length) {
                        Byte label = packet[pos];
                        if (label == 0x00) {
                            pos += 1;
                            if (pos + 4 > length) {
                                return 0;
                            }
                            return pos + 4;
                        }
                        if ((label & 0xC0) == 0xC0) {
                            pos += 2;
                            if (pos + 4 > length) {
                                return 0;
                            }
                            return pos + 4;
                        }
                        if (label > 63) {
                            return 0;
                        }
                        pos += 1 + static_cast<int>(label);
                    }
                    return 0;
                }

                static bool IsReverseArpaHostname(const ppp::string& hostname_lower) noexcept {
                    static constexpr char kIpv4Arpa[] = ".in-addr.arpa";
                    static constexpr char kIpv6Arpa[] = ".ip6.arpa";
                    if (hostname_lower.size() >= sizeof(kIpv4Arpa) - 1 &&
                        hostname_lower.compare(
                            hostname_lower.size() - (sizeof(kIpv4Arpa) - 1),
                            sizeof(kIpv4Arpa) - 1,
                            kIpv4Arpa) == 0) {
                        return true;
                    }
                    if (hostname_lower.size() >= sizeof(kIpv6Arpa) - 1 &&
                        hostname_lower.compare(
                            hostname_lower.size() - (sizeof(kIpv6Arpa) - 1),
                            sizeof(kIpv6Arpa) - 1,
                            kIpv6Arpa) == 0) {
                        return true;
                    }
                    return false;
                }

                bool DnsFakeIpResponse::ShouldUseFakeIp(const ppp::string& hostname_lower) noexcept {
                    if (hostname_lower.empty()) {
                        return false;
                    }
                    if (IsReverseArpaHostname(hostname_lower)) {
                        return false;
                    }
                    if (hostname_lower == "localhost") {
                        return false;
                    }
                    if (hostname_lower.size() >= 6 &&
                        hostname_lower.compare(hostname_lower.size() - 6, 6, ".local") == 0) {
                        return false;
                    }
                    if (hostname_lower.size() >= 4 &&
                        hostname_lower.compare(hostname_lower.size() - 4, 4, ".lan") == 0) {
                        return false;
                    }
                    return true;
                }

                DnsFakeIpResponse::AQueryStatus DnsFakeIpResponse::InspectAQueryV2(
                    const Byte* query_packet, int query_length) noexcept {
                    try {
                        ::dns::Message query;
                        return DecodeAQueryV2(query_packet, query_length, query);
                    }
                    catch (...) {
                        return AQueryStatus::Invalid;
                    }
                }

                ppp::vector<Byte> DnsFakeIpResponse::BuildARecordResponseV2(
                    const Byte* query_packet, int query_length, uint32_t fake_ip_host) noexcept {
                    try {
                        ::dns::Message query;
                        if (DecodeAQueryV2(query_packet, query_length, query) != AQueryStatus::Supported)
                            return {};

                        ::dns::Message response;
                        response.mId = query.mId;
                        response.mQr = 1;
                        response.mRD = query.mRD;
                        response.questions = query.questions;

                        response.answers.emplace_back();
                        auto& answer = response.answers.back();
                        answer.mName = query.questions.front().mName;
                        answer.mType = ::dns::RecordType::kA;
                        answer.mClass = ::dns::RecordClass::kIN;
                        answer.mTtl = 60;
                        auto address = std::make_shared<::dns::RDataA>();
                        const Byte address_bytes[] = {
                            static_cast<Byte>((fake_ip_host >> 24) & 0xff),
                            static_cast<Byte>((fake_ip_host >> 16) & 0xff),
                            static_cast<Byte>((fake_ip_host >> 8) & 0xff),
                            static_cast<Byte>(fake_ip_host & 0xff)
                        };
                        address->setAddress(address_bytes);
                        answer.setRData(address);

                        if (!query.additions.empty()) {
                            response.additions.emplace_back();
                            auto& opt = response.additions.back();
                            opt.mType = ::dns::RecordType::kOPT;
                            opt.mClass = query.additions.front().mClass;
                            opt.mTtl = query.additions.front().mTtl & 0x8000u;
                            opt.setRData(std::make_shared<::dns::RDataOPT>());
                        }
                        auto bytes = EncodeV2(response);
                        if (!bytes.empty()) bytes[3] |= static_cast<Byte>(query_packet[3] & 0x10);
                        return bytes;
                    }
                    catch (...) {
                        return {};
                    }
                }

                ppp::vector<Byte> DnsFakeIpResponse::BuildARecordResponse(
                    const Byte* query_packet,
                    int query_length,
                    uint32_t fake_ip_host) noexcept {

                    int qend = LocateQuestionEnd(query_packet, query_length);
                    if (qend == 0) {
                        return {};
                    }

                    ppp::vector<Byte> response(static_cast<std::size_t>(qend) + 16);
                    std::memcpy(response.data(), query_packet, static_cast<std::size_t>(qend));

                    Byte rd = static_cast<Byte>(response[2] & 0x01);
                    response[2] = static_cast<Byte>(0x80 | rd);
                    response[3] = 0x80;

                    response[4] = 0; response[5] = 1;
                    response[6] = 0; response[7] = 1;
                    response[8] = 0; response[9] = 0;
                    response[10] = 0; response[11] = 0;

                    std::size_t offset = static_cast<std::size_t>(qend);
                    response[offset++] = 0xC0;
                    response[offset++] = 0x0C;
                    response[offset++] = 0x00;
                    response[offset++] = 0x01;
                    response[offset++] = 0x00;
                    response[offset++] = 0x01;
                    response[offset++] = 0x00;
                    response[offset++] = 0x00;
                    response[offset++] = 0x00;
                    response[offset++] = 0x3C;
                    response[offset++] = 0x00;
                    response[offset++] = 0x04;
                    response[offset++] = static_cast<Byte>((fake_ip_host >> 24) & 0xFF);
                    response[offset++] = static_cast<Byte>((fake_ip_host >> 16) & 0xFF);
                    response[offset++] = static_cast<Byte>((fake_ip_host >> 8) & 0xFF);
                    response[offset++] = static_cast<Byte>(fake_ip_host & 0xFF);
                    return response;
                }

                uint32_t DnsFakeIpResponse::ParseFirstARecordNetwork(
                    const Byte* response,
                    int response_length) noexcept {

                    if (NULLPTR == response || response_length < 12) {
                        return 0;
                    }

                    uint16_t ancount = (static_cast<uint16_t>(response[6]) << 8) | static_cast<uint16_t>(response[7]);
                    uint16_t qdcount = (static_cast<uint16_t>(response[4]) << 8) | static_cast<uint16_t>(response[5]);

                    std::size_t pos = 12;
                    for (uint16_t qi = 0; qi < qdcount; ++qi) {
                        bool done = false;
                        while (pos < static_cast<std::size_t>(response_length) && !done) {
                            Byte label = response[pos];
                            if (label == 0x00) {
                                pos += 1;
                                done = true;
                            }
                            else if ((label & 0xC0) == 0xC0) {
                                pos += 2;
                                done = true;
                            }
                            else if (label > 63) {
                                return 0;
                            }
                            else {
                                pos += 1 + static_cast<std::size_t>(label);
                            }
                        }
                        if (!done || pos + 4 > static_cast<std::size_t>(response_length)) {
                            return 0;
                        }
                        pos += 4;
                    }

                    for (uint16_t i = 0; i < ancount; ++i) {
                        while (pos < static_cast<std::size_t>(response_length)) {
                            Byte label = response[pos];
                            if (label == 0x00) {
                                pos += 1;
                                break;
                            }
                            if ((label & 0xC0) == 0xC0) {
                                pos += 2;
                                break;
                            }
                            if (label > 63) {
                                return 0;
                            }
                            pos += 1 + static_cast<std::size_t>(label);
                        }

                        if (pos + 10 > static_cast<std::size_t>(response_length)) {
                            return 0;
                        }

                        uint16_t rr_type = (static_cast<uint16_t>(response[pos]) << 8) |
                            static_cast<uint16_t>(response[pos + 1]);
                        uint16_t rdlength = (static_cast<uint16_t>(response[pos + 8]) << 8) |
                            static_cast<uint16_t>(response[pos + 9]);
                        pos += 10;

                        if (pos + rdlength > static_cast<std::size_t>(response_length)) {
                            return 0;
                        }

                        if (rr_type == 1 && rdlength == 4) {
                            uint32_t addr = (static_cast<uint32_t>(response[pos]) << 24) |
                                (static_cast<uint32_t>(response[pos + 1]) << 16) |
                                (static_cast<uint32_t>(response[pos + 2]) << 8) |
                                static_cast<uint32_t>(response[pos + 3]);
                            return addr;
                        }

                        pos += rdlength;
                    }

                    return 0;
                }

            }
        }
    }
}
