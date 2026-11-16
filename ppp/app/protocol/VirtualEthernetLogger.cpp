// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file VirtualEthernetLogger.cpp
 * @brief Implementation of structured virtual Ethernet event logging.
 */

#include <ppp/app/protocol/VirtualEthernetLogger.h>
#include <ppp/DateTime.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/io/File.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/tcp.h>
#include <ppp/net/native/udp.h>
#include <ppp/ipv6/IPv6Packet.h>
#include <ppp/threading/Executors.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/transmissions/IWebsocketTransmission.h>

#if !defined(_WIN32)
#include <common/unix/UnixAfx.h>
#endif

namespace ppp {
    namespace app {
        namespace protocol {
            namespace logger_detail {
                /** @brief Maximum queued lines before oldest entries are dropped. */
                static constexpr std::size_t kMaxPendingLines = 4096;
                /** @brief Maximum active log file size before rotation. */
                static constexpr std::size_t kMaxLogFileBytes = 64ULL * 1024ULL * 1024ULL;
                /** @brief Number of rotated archive days to retain. */
                static constexpr int kMaxArchiveDays = 14;

                /** @brief Builds integer day key in `YYYYMMDD` format. */
                static int LOGGER_DAY_KEY(ppp::DateTime now) noexcept {
                    return now.Year() * 10000 + now.Month() * 100 + now.Day();
                }

                /** @brief Formats timestamp in fixed millisecond precision. */
                static ppp::string LOGGER_NOW_ISO(ppp::DateTime now) noexcept {
                    return now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                }

                /** @brief Converts session GUID to uppercase braced string. */
                static ppp::string LOGGER_GUID(ppp::Int128 guid) noexcept {
                    ppp::string s = "{";
                    ppp::string guid_text = ppp::auxiliary::StringAuxiliary::Int128ToGuidString(guid);
                    s += ToUpper(guid_text);
                    s += "}";
                    return s;
                }

                /** @brief Converts packet direction enum to stable text token. */
                static const char* LOGGER_DIRECTION(ppp::app::protocol::VirtualEthernetLogger::PacketDirection direction) noexcept {
                    using PacketDirection = ppp::app::protocol::VirtualEthernetLogger::PacketDirection;
                    switch (direction) {
                    case PacketDirection::ClientToServer:
                        return "client->server";
                    case PacketDirection::ServerToClient:
                        return "server->client";
                    case PacketDirection::ServerToUplink:
                        return "server->uplink";
                    case PacketDirection::UplinkToServer:
                        return "uplink->server";
                    default:
                        return "unknown";
                    }
                }

                /** @brief Escapes string for JSON value context. */
                static ppp::string LOGGER_JSON_ESCAPE(const ppp::string& in) noexcept {
                    ppp::string out;
                    out.reserve(in.size() + 16);
                    for (char ch : in) {
                        switch (ch) {
                        case '\\':
                            out += "\\\\";
                            break;
                        case '"':
                            out += "\\\"";
                            break;
                        case '\r':
                            out += "\\r";
                            break;
                        case '\n':
                            out += "\\n";
                            break;
                        case '\t':
                            out += "\\t";
                            break;
                        default:
                            out += ch;
                            break;
                        }
                    }
                    return out;
                }

                /** @brief Converts packet prefix bytes into uppercase hex sample. */
                static ppp::string LOGGER_JSON_HEX(const void* data, int length) noexcept {
                    static const char kHex[] = "0123456789ABCDEF";

                    if (NULLPTR == data || length <= 0) {
                        return ppp::string();
                    }

                    int bounded = std::min<int>(length, 96);
                    const unsigned char* p = reinterpret_cast<const unsigned char*>(data);
                    ppp::string out;
                    out.reserve(static_cast<std::size_t>(bounded) * 2);
                    for (int i = 0; i < bounded; ++i) {
                        unsigned char b = p[i];
                        out.push_back(kHex[(b >> 4) & 0x0f]);
                        out.push_back(kHex[b & 0x0f]);
                    }
                    return out;
                }

                /** @brief Maps L3/L4 protocol number to display token. */
                static ppp::string LOGGER_PROTOCOL_NAME(int protocol) noexcept {
                    switch (protocol) {
                    case ppp::net::native::ip_hdr::IP_PROTO_TCP:
                        return "tcp";
                    case ppp::net::native::ip_hdr::IP_PROTO_UDP:
                        return "udp";
                    case ppp::net::native::ip_hdr::IP_PROTO_ICMP:
                        return "icmp";
                    case IPPROTO_ICMPV6:
                        return "icmpv6";
                    default:
                        return "other";
                    }
                }

                static const char* LOGGER_TRANSPORT_NAME(int protocol) noexcept {
                    switch (protocol) {
                    case ppp::net::native::ip_hdr::IP_PROTO_TCP:
                        return "TCP";
                    case ppp::net::native::ip_hdr::IP_PROTO_UDP:
                        return "UDP";
                    case ppp::net::native::ip_hdr::IP_PROTO_ICMP:
                    case IPPROTO_ICMPV6:
                        return "ICMP";
                    default:
                        return "OTHER";
                    }
                }

                static ppp::string LOGGER_IP_STRING(const boost::asio::ip::address& ip) noexcept {
                    std::string ip_std = ip.to_string();
                    return ppp::string(ip_std.data(), ip_std.size());
                }

                /** @brief Formats endpoint using IPv4/IPv6-safe notation. */
                static ppp::string LOGGER_ENDPOINT(const boost::asio::ip::address& ip, int port) noexcept {
                    std::string ip_std = ip.to_string();
                    ppp::string ip_string(ip_std.data(), ip_std.size());
                    if (ip.is_v4()) {
                        return ip_string + ":" + stl::to_string<ppp::string>(port);
                    }

                    if (ip.is_v6()) {
                        return "[" + ip_string + "]:" + stl::to_string<ppp::string>(port);
                    }

                    return ppp::string();
                }

                /** @brief Formats TCP endpoint into string. */
                static ppp::string LOGGER_ENDPOINT(const boost::asio::ip::tcp::endpoint& ep) noexcept {
                    return LOGGER_ENDPOINT(ep.address(), ep.port());
                }

                /** @brief Formats UDP endpoint into string. */
                static ppp::string LOGGER_ENDPOINT(const boost::asio::ip::udp::endpoint& ep) noexcept {
                    return LOGGER_ENDPOINT(ep.address(), ep.port());
                }

                /** @brief Extracts optional X-Forwarded-For and transport family. */
                static ppp::string GetXForwardedFor(const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, ppp::string* protocol) noexcept {
                    if (ppp::transmissions::IWebsocketTransmission* ws = dynamic_cast<ppp::transmissions::IWebsocketTransmission*>(transmission.get()); ws) {
                        if (auto p = ws->GetSocket(); p) {
                            if (protocol) {
                                (*protocol) = "ws";
                            }

                            return p->XForwardedFor;
                        }
                    }

                    if (ppp::transmissions::ISslWebsocketTransmission* wss = dynamic_cast<ppp::transmissions::ISslWebsocketTransmission*>(transmission.get()); wss) {
                        if (auto p = wss->GetSocket(); p) {
                            if (protocol) {
                                (*protocol) = "wss";
                            }

                            return p->XForwardedFor;
                        }
                    }

                    if (protocol) {
                        (*protocol) = "tcp";
                    }

                    return ppp::string();
                }

                /** @brief Builds source endpoint text including transport and proxy hints. */
                static ppp::string GetRemoteEndPoint(const std::shared_ptr<ppp::transmissions::ITransmission>& transmission) noexcept {
                    ppp::string log = ppp::net::IPEndPoint::ToEndPoint(transmission->GetRemoteEndPoint()).ToString();
                    ppp::string protocol;
                    ppp::string x_forwarded_for = GetXForwardedFor(transmission, &protocol);
                    if (x_forwarded_for.empty()) {
                        log += "/" + protocol;
                    }
                    else {
                        log += "/" + protocol + " Claimed-Client-IP(untrusted):" + x_forwarded_for;
                    }
                    return log;
                }

                /** @brief Removes file path if it exists. */
                static bool LOGGER_DELETE_FILE(const ppp::string& path) noexcept {
                    if (path.empty()) {
                        return false;
                    }

                    return ::remove(path.data()) == 0;
                }

                /** @brief Parses `YYYYMMDD` day key from rotated archive file name. */
                static int LOGGER_PARSE_DAYKEY_FROM_NAME(const ppp::string& base_name, const ppp::string& file_name) noexcept {
                    if (base_name.empty() || file_name.size() <= base_name.size() + 9) {
                        return -1;
                    }

                    if (file_name.find(base_name + ".") != 0) {
                        return -1;
                    }

                    std::size_t pos = base_name.size() + 1;
                    if (pos + 8 > file_name.size()) {
                        return -1;
                    }

                    int value = 0;
                    for (std::size_t i = 0; i < 8; ++i) {
                        char ch = file_name[pos + i];
                        if (ch < '0' || ch > '9') {
                            return -1;
                        }

                        value = value * 10 + (ch - '0');
                    }

                    if (pos + 8 >= file_name.size() || file_name[pos + 8] != '.') {
                        return -1;
                    }

                    return value;
                }

                /** @brief Returns file name without extension. */
                static ppp::string LOGGER_BASE_NAME(const ppp::string& file_name) noexcept {
                    std::size_t dot = file_name.find_last_of('.');
                    if (dot == ppp::string::npos || dot == 0) {
                        return file_name;
                    }

                    return file_name.substr(0, dot);
                }

                /** @brief Returns file extension without dot. */
                static ppp::string LOGGER_EXTENSION(const ppp::string& file_name) noexcept {
                    std::size_t dot = file_name.find_last_of('.');
                    if (dot == ppp::string::npos || dot + 1 >= file_name.size()) {
                        return ppp::string();
                    }

                    return file_name.substr(dot + 1);
                }
            }
        }
    }
}

namespace ppp {
    namespace app {
        namespace protocol {
            using namespace logger_detail;

            /** @brief Constructs logger and prepares active log file. */
            VirtualEthernetLogger::VirtualEthernetLogger(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& log_path) noexcept
                : log_context_(context) {
                if (NULLPTR == context || log_path.empty()) {
                    return;
                }

                ppp::string rewritten = ppp::io::File::RewritePath(log_path.data());
                ppp::string full_path = ppp::io::File::GetFullPath(rewritten.data());
                if (full_path.empty()) {
                    return;
                }

                log_path_ = std::move(full_path);
                log_directory_ = ppp::io::File::GetParentPath(log_path_.data());
                log_file_name_ = ppp::io::File::GetFileName(log_path_.data());
                if (log_directory_.empty() || log_file_name_.empty()) {
                    return;
                }

                if (!ppp::io::File::CreateDirectories(log_directory_.data())) {
                    return;
                }

                log_strand_ = ppp::make_shared_object<boost::asio::strand<boost::asio::io_context::executor_type>>(boost::asio::make_strand(*context));
                if (NULLPTR == log_strand_) {
                    return;
                }

                OpenLogFile();
            }

            /** @brief Flushes and closes logger resources. */
            VirtualEthernetLogger::~VirtualEthernetLogger() noexcept {
                Finalize();
            }

            /** @brief Opens active log file and initializes size/day metadata. */
            bool VirtualEthernetLogger::OpenLogFile() noexcept {
                if (log_path_.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
                }

                FILE* f = fopen(log_path_.data(), "ab+");
                if (NULLPTR == f) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileOpenFailed);
                }

                if (fseek(f, 0, SEEK_END) != 0) {
                    fclose(f);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileStatFailed);
                }

                long size = ftell(f);
                if (size < 0) {
                    size = 0;
                }

                log_file_ = f;
                log_file_size_ = static_cast<std::size_t>(size);
                log_file_day_key_ = LOGGER_DAY_KEY(ppp::threading::Executors::Now());
                return true;
            }

            /** @brief Returns whether logger can currently write entries. */
            bool VirtualEthernetLogger::Valid() noexcept {
                return NULLPTR != log_file_ && NULLPTR != log_context_ && !log_path_.empty();
            }

            /** @brief Schedules asynchronous finalization on logger context. */
            void VirtualEthernetLogger::Dispose() noexcept {
                std::shared_ptr<VirtualEthernetLogger> self = GetReference();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                if (NULLPTR == context) {
                    Finalize();
                    return;
                }

                auto strand = log_strand_;
                if (strand) {
                    boost::asio::post(*strand,
                        [self, this]() noexcept {
                            Finalize();
                        });
                }
                else {
                    boost::asio::post(*context,
                        [self, this]() noexcept {
                            Finalize();
                        });
                }
            }

            /** @brief Performs synchronous flush/close and resets state. */
            void VirtualEthernetLogger::Finalize() noexcept {
                FlushPending();

                FILE* f = std::exchange(log_file_, NULLPTR);
                if (NULLPTR != f) {
                    fflush(f);
                    fclose(f);
                }

                flush_scheduled_ = false;
                pending_lines_.clear();
                log_file_size_ = 0;
                log_file_day_key_ = -1;
            }

            /** @brief Ensures active file exists and rotates if day/size threshold is reached. */
            bool VirtualEthernetLogger::EnsureLogFile(std::size_t incoming_bytes) noexcept {
                if (NULLPTR == log_file_) {
                    if (!OpenLogFile()) {
                        return false;
                    }
                }

                int now_day = LOGGER_DAY_KEY(ppp::threading::Executors::Now());
                bool need_rotate_by_day = log_file_day_key_ > 0 && now_day != log_file_day_key_;
                bool need_rotate_by_size = (log_file_size_ + incoming_bytes) > kMaxLogFileBytes;
                if (need_rotate_by_day || need_rotate_by_size) {
                    RotateLogFile(now_day);
                }

                if (NULLPTR == log_file_) {
                    return OpenLogFile();
                }

                return true;
            }

            /** @brief Rotates active file to dated archive and opens a new one. */
            void VirtualEthernetLogger::RotateLogFile(int day_key) noexcept {
                FILE* f = std::exchange(log_file_, NULLPTR);
                if (NULLPTR != f) {
                    fflush(f);
                    fclose(f);
                }

                ppp::string base_name = LOGGER_BASE_NAME(log_file_name_);
                ppp::string extension = LOGGER_EXTENSION(log_file_name_);
                if (extension.empty()) {
                    extension = "log";
                }

                ppp::DateTime now = ppp::threading::Executors::Now();
                if (day_key <= 0) {
                    day_key = LOGGER_DAY_KEY(now);
                }

                char suffix[64];
                snprintf(suffix, sizeof(suffix), ".%08d.%s", day_key, extension.data());

                ppp::string archive_path = log_directory_ + ppp::io::File::GetSeparator() + base_name + suffix;
                LOGGER_DELETE_FILE(archive_path);
                ::rename(log_path_.data(), archive_path.data());

                log_file_size_ = 0;
                log_file_day_key_ = day_key;
                OpenLogFile();
                CleanupArchives();
            }

            /** @brief Removes oldest archive files beyond retention policy. */
            void VirtualEthernetLogger::CleanupArchives() noexcept {
                ppp::vector<ppp::string> files;
                if (!ppp::io::File::GetAllFileNames(log_directory_.data(), false, files)) {
                    return;
                }

                ppp::string base_name = LOGGER_BASE_NAME(log_file_name_);
                ppp::vector<std::pair<int, ppp::string>> archives;
                archives.reserve(files.size());

                for (const ppp::string& path : files) {
                    ppp::string file_name = ppp::io::File::GetFileName(path.data());
                    int day_key = LOGGER_PARSE_DAYKEY_FROM_NAME(base_name, file_name);
                    if (day_key > 0) {
                        archives.emplace_back(day_key, path);
                    }
                }

                if (archives.size() <= static_cast<std::size_t>(kMaxArchiveDays)) {
                    return;
                }

                std::sort(archives.begin(), archives.end(),
                    [](const std::pair<int, ppp::string>& a, const std::pair<int, ppp::string>& b) noexcept {
                        return a.first < b.first;
                    });

                std::size_t remove_count = archives.size() - static_cast<std::size_t>(kMaxArchiveDays);
                for (std::size_t i = 0; i < remove_count; ++i) {
                    LOGGER_DELETE_FILE(archives[i].second);
                }
            }

            /** @brief Adds a line to pending queue with bound on memory growth. */
            bool VirtualEthernetLogger::EnqueueLine(ppp::string line) noexcept {
                if (line.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VEthernetLoggerEnqueueLineEmpty);
                }

                if (line.size() > 8192) {
                    line.resize(8192);
                    line.append("\n");
                }

                if (pending_lines_.size() >= kMaxPendingLines) {
                    pending_lines_.pop_front();
                }

                pending_lines_.emplace_back(std::move(line));
                return true;
            }

            /** @brief Flushes pending lines to disk in FIFO order. */
            void VirtualEthernetLogger::FlushPending() noexcept {
                if (pending_lines_.empty()) {
                    return;
                }

                for (ppp::string& line : pending_lines_) {
                    if (!EnsureLogFile(line.size())) {
                        continue;
                    }

                    if (NULLPTR == log_file_) {
                        continue;
                    }

                    std::size_t n = fwrite(line.data(), 1, line.size(), log_file_);
                    if (n == line.size()) {
                        log_file_size_ += n;
                    }
                }

                if (NULLPTR != log_file_) {
                    fflush(log_file_);
                }

                pending_lines_.clear();
            }

            /** @brief Copies caller buffer and dispatches asynchronous write. */
            bool VirtualEthernetLogger::Write(const void* s, int length, const ppp::function<void(bool)>& cb) noexcept {
                if (NULLPTR == s || length < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VEthernetLoggerWriteNullInputBuffer);
                    if (cb) {
                        cb(false);
                    }
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = BufferAllocator;
                std::shared_ptr<Byte> buffer = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, length);
                if (NULLPTR == buffer) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VEthernetLoggerWriteBufferAllocFailed);
                    if (cb) {
                        cb(false);
                    }
                    return false;
                }

                memcpy(buffer.get(), s, length);
                return Write(buffer, length, cb);
            }

            /** @brief Enqueues owned line and flushes in logger strand/context. */
            bool VirtualEthernetLogger::Write(const std::shared_ptr<Byte>& s, int length, const ppp::function<void(bool)>& cb) noexcept {
                if (NULLPTR == s || length < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VEthernetLoggerWriteNullSharedBuffer);
                    if (cb) {
                        cb(false);
                    }
                    return false;
                }

                ppp::string line(reinterpret_cast<const char*>(s.get()), length);
                std::shared_ptr<VirtualEthernetLogger> self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = log_context_;
                if (NULLPTR == context) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                    if (cb) {
                        cb(false);
                    }
                    return false;
                }

                auto strand = log_strand_;
                auto invoke = 
                    [self, this, line = std::move(line), cb]() noexcept {
                        bool ok = EnqueueLine(std::move(line));
                        if (ok) {
                            FlushPending();
                        }
                    
                        if (cb) {
                            cb(ok);
                        }
                    };

                if (strand) {
                    boost::asio::post(*strand, std::move(invoke));
                }
                else {
                    boost::asio::post(*context, std::move(invoke));
                }

                return true;
            }

            /**
             * @brief Logs one packet event with lightweight protocol parsing.
             * @details The parser extracts protocol, endpoints and payload size best-effort,
             * then writes one JSON line with a packet byte sample.
             */
            bool VirtualEthernetLogger::Packet(Int128 guid, const void* packet, int packet_length, PacketDirection direction) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VEthernetLoggerPacketInvalidArguments);
                }

                ppp::DateTime now = ppp::threading::Executors::Now();
                ppp::string timestamp = LOGGER_NOW_ISO(now);
                ppp::string protocol = "unknown";
                ppp::string src;
                ppp::string dst;
                ppp::string src_ip;
                ppp::string dst_ip;

                int transport_protocol_number = -1;
                int source_port = 0;
                int destination_port = 0;

                int payload_bytes = 0;
                bool checksum_ok = true;
                bool ipv6_packet = false;

                int packet_size = packet_length;
                const Byte* bytes = reinterpret_cast<const Byte*>(packet);
                ppp::net::native::ip_hdr* v4 = ppp::net::native::ip_hdr::Parse(packet, packet_size);
                if (NULLPTR != v4) {
                    ipv6_packet = false;
                    transport_protocol_number = ppp::net::native::ip_hdr::IPH_PROTO(v4);
                    protocol = LOGGER_PROTOCOL_NAME(transport_protocol_number);
                    boost::asio::ip::address src_address = ppp::net::Ipep::ToAddress(v4->src);
                    boost::asio::ip::address dst_address = ppp::net::Ipep::ToAddress(v4->dest);
                    src_ip = LOGGER_IP_STRING(src_address);
                    dst_ip = LOGGER_IP_STRING(dst_address);
                    int hdr_len = ppp::net::native::ip_hdr::IPH_HL(v4) * 4;
                    if (hdr_len < 20) {
                        hdr_len = 20;
                    }

                    int l4_len = packet_length - hdr_len;
                    if (l4_len < 0) {
                        l4_len = 0;
                    }

                    if (transport_protocol_number == ppp::net::native::ip_hdr::IP_PROTO_TCP) {
                        ppp::net::native::tcp_hdr* tcp = ppp::net::native::tcp_hdr::Parse(v4, packet, packet_length);
                        if (tcp) {
                            source_port = ntohs(tcp->src);
                            destination_port = ntohs(tcp->dest);
                            int tcp_hdr_len = ppp::net::native::tcp_hdr::TCPH_HDRLEN_BYTES(tcp);
                            if (tcp_hdr_len < 20) {
                                tcp_hdr_len = 20;
                            }
                            payload_bytes = std::max<int>(0, l4_len - tcp_hdr_len);
                        }
                    }
                    elif(transport_protocol_number == ppp::net::native::ip_hdr::IP_PROTO_UDP) {
                        ppp::net::native::udp_hdr* udp = ppp::net::native::udp_hdr::Parse(v4, packet, packet_length);
                        if (udp) {
                            source_port = ntohs(udp->src);
                            destination_port = ntohs(udp->dest);
                            payload_bytes = std::max<int>(0, l4_len - static_cast<int>(sizeof(ppp::net::native::udp_hdr)));
                        }
                    }
                    else {
                        payload_bytes = l4_len;
                    }

                    src = LOGGER_ENDPOINT(src_address, source_port);
                    dst = LOGGER_ENDPOINT(dst_address, destination_port);
                }
                else {
                    boost::asio::ip::address_v6 src_v6;
                    boost::asio::ip::address_v6 dst_v6;
                    Byte next_header = 0;
                    int body_length = 0;
                    if (ppp::ipv6::TryParsePacket(const_cast<Byte*>(bytes), packet_length, src_v6, dst_v6, &next_header, &body_length)) {
                        ipv6_packet = true;
                        transport_protocol_number = next_header;
                        protocol = LOGGER_PROTOCOL_NAME(next_header);
                        boost::asio::ip::address src_address(src_v6);
                        boost::asio::ip::address dst_address(dst_v6);
                        src_ip = LOGGER_IP_STRING(src_address);
                        dst_ip = LOGGER_IP_STRING(dst_address);

                        bool ipv6_l4_parsed = false;
                        if (body_length > 0 && packet_length >= ppp::ipv6::IPv6_HEADER_MIN_SIZE) {
                            const Byte* l4 = bytes + ppp::ipv6::IPv6_HEADER_MIN_SIZE;
                            int l4_len = std::min<int>(body_length, packet_length - ppp::ipv6::IPv6_HEADER_MIN_SIZE);
                            if (l4_len >= 0) {
                                if (next_header == ppp::net::native::ip_hdr::IP_PROTO_TCP && l4_len >= static_cast<int>(sizeof(ppp::net::native::tcp_hdr))) {
                                    const ppp::net::native::tcp_hdr* tcp = reinterpret_cast<const ppp::net::native::tcp_hdr*>(l4);
                                    source_port = ntohs(tcp->src);
                                    destination_port = ntohs(tcp->dest);
                                    int tcp_hdr_len = ppp::net::native::tcp_hdr::TCPH_HDRLEN_BYTES(const_cast<ppp::net::native::tcp_hdr*>(tcp));
                                    if (tcp_hdr_len < 20 || tcp_hdr_len > l4_len) {
                                        tcp_hdr_len = 20;
                                    }
                                    payload_bytes = std::max<int>(0, l4_len - tcp_hdr_len);
                                    ipv6_l4_parsed = true;
                                }
                                elif(next_header == ppp::net::native::ip_hdr::IP_PROTO_UDP && l4_len >= static_cast<int>(sizeof(ppp::net::native::udp_hdr))) {
                                    const ppp::net::native::udp_hdr* udp = reinterpret_cast<const ppp::net::native::udp_hdr*>(l4);
                                    source_port = ntohs(udp->src);
                                    destination_port = ntohs(udp->dest);
                                    payload_bytes = std::max<int>(0, l4_len - static_cast<int>(sizeof(ppp::net::native::udp_hdr)));
                                    ipv6_l4_parsed = true;
                                }
                                else {
                                    payload_bytes = std::max<int>(0, l4_len);
                                    ipv6_l4_parsed = true;
                                }
                            }
                        }

                        src = LOGGER_ENDPOINT(src_address, source_port);
                        dst = LOGGER_ENDPOINT(dst_address, destination_port);
                        if (!ipv6_l4_parsed) {
                            payload_bytes = std::max<int>(0, body_length);
                        }
                    }
                }

                const char* direction_text = LOGGER_DIRECTION(direction);
                const char* transport_name = LOGGER_TRANSPORT_NAME(transport_protocol_number);

                ppp::string line;
                line.reserve(512);
                line += "{";
                line += "\"ts\":\"" + LOGGER_JSON_ESCAPE(timestamp) + "\"";
                line += ",\"event\":\"packet\"";
                line += ",\"session\":\"" + LOGGER_JSON_ESCAPE(LOGGER_GUID(guid)) + "\"";
                line += ",\"direction\":\"" + ppp::string(direction_text) + "\"";
                line += ",\"protocol\":\"" + LOGGER_JSON_ESCAPE(protocol) + "\"";
                line += ",\"src\":\"" + LOGGER_JSON_ESCAPE(src) + "\"";
                line += ",\"dst\":\"" + LOGGER_JSON_ESCAPE(dst) + "\"";
                line += ",\"bytes\":" + stl::to_string<ppp::string>(packet_length);
                line += ",\"payload_bytes\":" + stl::to_string<ppp::string>(payload_bytes);
                line += ",\"ipv6\":" + ppp::string(ipv6_packet ? "true" : "false");
                line += ",\"checksum_ok\":" + ppp::string(checksum_ok ? "true" : "false");
                line += ",\"sample_hex\":\"" + LOGGER_JSON_ESCAPE(LOGGER_JSON_HEX(packet, packet_length)) + "\"";
                line += ",\"src_ip\":\"" + LOGGER_JSON_ESCAPE(src_ip) + "\"";
                line += ",\"dst_ip\":\"" + LOGGER_JSON_ESCAPE(dst_ip) + "\"";
                line += ",\"transport\":\"" + ppp::string(transport_name) + "\"";
                line += ",\"src_port\":" + stl::to_string<ppp::string>(source_port);
                line += ",\"dst_port\":" + stl::to_string<ppp::string>(destination_port);
                line += ",\"packet_length\":" + stl::to_string<ppp::string>(packet_length);
                line += ",\"packet_direction\":\"" + ppp::string(direction_text) + "\"";
                line += "}\n";

                return Write(line.data(), static_cast<int>(line.size()), NULLPTR);
            }

            /** @brief Logs ARP-like assignment event from raw IPv4 values. */
            bool VirtualEthernetLogger::Arp(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, uint32_t ip, uint32_t mask) noexcept {
                return this->Arp(guid, transmission, ppp::net::Ipep::ToAddress(ip), ppp::net::Ipep::ToAddress(mask));
            }

            /** @brief Logs ARP-like assignment event with address objects. */
            bool VirtualEthernetLogger::Arp(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::address& ip, const boost::asio::ip::address& mask) noexcept {
                ppp::DateTime now = ppp::threading::Executors::Now();
                std::string ip_std = ip.to_string();
                std::string mask_std = mask.to_string();
                ppp::string ip_string(ip_std.data(), ip_std.size());
                ppp::string mask_string(mask_std.data(), mask_std.size());
                ppp::string line;
                line += "{";
                line += "\"ts\":\"" + LOGGER_JSON_ESCAPE(LOGGER_NOW_ISO(now)) + "\"";
                line += ",\"event\":\"arp\"";
                line += ",\"session\":\"" + LOGGER_JSON_ESCAPE(LOGGER_GUID(guid)) + "\"";
                line += ",\"source\":\"" + LOGGER_JSON_ESCAPE(GetRemoteEndPoint(transmission)) + "\"";
                line += ",\"ip\":\"" + LOGGER_JSON_ESCAPE(ip_string) + "\"";
                line += ",\"gateway\":\"" + LOGGER_JSON_ESCAPE(mask_string) + "\"";
                line += "}\n";
                return this->Write(line.data(), static_cast<int>(line.size()), NULLPTR);
            }

            /** @brief Logs connect event including NAT endpoint and destination endpoint. */
            bool VirtualEthernetLogger::Connect(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::tcp::endpoint& natEP, const boost::asio::ip::tcp::endpoint& dstEP, const ppp::string& hostDomain) noexcept {
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                ppp::DateTime now = ppp::threading::Executors::Now();
                ppp::string line;
                line += "{";
                line += "\"ts\":\"" + LOGGER_JSON_ESCAPE(LOGGER_NOW_ISO(now)) + "\"";
                line += ",\"event\":\"connect\"";
                line += ",\"session\":\"" + LOGGER_JSON_ESCAPE(LOGGER_GUID(guid)) + "\"";
                line += ",\"source\":\"" + LOGGER_JSON_ESCAPE(GetRemoteEndPoint(transmission)) + "\"";
                line += ",\"nat\":\"" + LOGGER_JSON_ESCAPE(LOGGER_ENDPOINT(natEP)) + "\"";
                line += ",\"destination\":\"" + LOGGER_JSON_ESCAPE(LOGGER_ENDPOINT(dstEP)) + "\"";
                line += ",\"domain\":\"" + LOGGER_JSON_ESCAPE(hostDomain) + "\"";
                line += "}\n";
                return this->Write(line.data(), static_cast<int>(line.size()), NULLPTR);
            }

            /**
             * @brief Logs an obfuscation-flag mismatch detected post-handshake.
             *
             * Emits a single JSON line of the form:
             * `{"ts":..., "event":"obfuscation-mismatch", "source":"ip:port", "details":"..."}`
             *
             * Companion record to `transmission.handshake.flag_mismatch` in the
             * telemetry pipeline; together they ensure that both the structured
             * server event log AND the metric/text telemetry log surface the
             * same diagnostic, regardless of which one the operator monitors.
             */
            bool VirtualEthernetLogger::Mismatch(const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const ppp::string& details) noexcept {
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                ppp::DateTime now = ppp::threading::Executors::Now();
                ppp::string line;
                line += "{";
                line += "\"ts\":\"" + LOGGER_JSON_ESCAPE(LOGGER_NOW_ISO(now)) + "\"";
                line += ",\"event\":\"obfuscation-mismatch\"";
                line += ",\"source\":\"" + LOGGER_JSON_ESCAPE(GetRemoteEndPoint(transmission)) + "\"";
                line += ",\"details\":\"" + LOGGER_JSON_ESCAPE(details) + "\"";
                line += "}\n";

                return this->Write(line.data(), static_cast<int>(line.size()), NULLPTR);
            }

            /** @brief Logs VPN session establishment event. */
            bool VirtualEthernetLogger::Vpn(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission) noexcept {
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                ppp::DateTime now = ppp::threading::Executors::Now();
                ppp::string line;
                line += "{";
                line += "\"ts\":\"" + LOGGER_JSON_ESCAPE(LOGGER_NOW_ISO(now)) + "\"";
                line += ",\"event\":\"vpn\"";
                line += ",\"session\":\"" + LOGGER_JSON_ESCAPE(LOGGER_GUID(guid)) + "\"";
                line += ",\"source\":\"" + LOGGER_JSON_ESCAPE(GetRemoteEndPoint(transmission)) + "\"";
                line += "}\n";

                return this->Write(line.data(), static_cast<int>(line.size()), NULLPTR);
            }

            /** @brief Logs DNS-related domain event. */
            bool VirtualEthernetLogger::Dns(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const ppp::string& hostDomain) noexcept {
                ppp::DateTime now = ppp::threading::Executors::Now();
                ppp::string line;
                line += "{";
                line += "\"ts\":\"" + LOGGER_JSON_ESCAPE(LOGGER_NOW_ISO(now)) + "\"";
                line += ",\"event\":\"dns\"";
                line += ",\"session\":\"" + LOGGER_JSON_ESCAPE(LOGGER_GUID(guid)) + "\"";
                line += ",\"source\":\"" + LOGGER_JSON_ESCAPE(GetRemoteEndPoint(transmission)) + "\"";
                line += ",\"domain\":\"" + LOGGER_JSON_ESCAPE(hostDomain) + "\"";
                line += "}\n";

                return this->Write(line.data(), static_cast<int>(line.size()), NULLPTR);
            }

            /** @brief Logs UDP port mapping event. */
            bool VirtualEthernetLogger::Port(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::udp::endpoint& inEP, const boost::asio::ip::udp::endpoint& natEP) noexcept {
                ppp::DateTime now = ppp::threading::Executors::Now();
                ppp::string line;
                line += "{";
                line += "\"ts\":\"" + LOGGER_JSON_ESCAPE(LOGGER_NOW_ISO(now)) + "\"";
                line += ",\"event\":\"port\"";
                line += ",\"session\":\"" + LOGGER_JSON_ESCAPE(LOGGER_GUID(guid)) + "\"";
                line += ",\"source\":\"" + LOGGER_JSON_ESCAPE(GetRemoteEndPoint(transmission)) + "\"";
                line += ",\"in\":\"" + LOGGER_JSON_ESCAPE(LOGGER_ENDPOINT(inEP)) + "\"";
                line += ",\"nat\":\"" + LOGGER_JSON_ESCAPE(LOGGER_ENDPOINT(natEP)) + "\"";
                line += "}\n";

                return this->Write(line.data(), static_cast<int>(line.size()), NULLPTR);
            }

            /** @brief Logs mapping connect event between public and remote endpoints. */
            bool VirtualEthernetLogger::MPConnect(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::tcp::endpoint& publicEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
                ppp::DateTime now = ppp::threading::Executors::Now();
                ppp::string line;
                line += "{";
                line += "\"ts\":\"" + LOGGER_JSON_ESCAPE(LOGGER_NOW_ISO(now)) + "\"";
                line += ",\"event\":\"mapping-connect\"";
                line += ",\"session\":\"" + LOGGER_JSON_ESCAPE(LOGGER_GUID(guid)) + "\"";
                line += ",\"source\":\"" + LOGGER_JSON_ESCAPE(GetRemoteEndPoint(transmission)) + "\"";
                line += ",\"public\":\"" + LOGGER_JSON_ESCAPE(LOGGER_ENDPOINT(publicEP)) + "\"";
                line += ",\"remote\":\"" + LOGGER_JSON_ESCAPE(LOGGER_ENDPOINT(remoteEP)) + "\"";
                line += "}\n";

                return this->Write(line.data(), static_cast<int>(line.size()), NULLPTR);
            }

            /** @brief Logs mapping entry registration with transport type. */
            bool VirtualEthernetLogger::MPEntry(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::tcp::endpoint& publicEP, bool protocol_tcp_or_udp) noexcept {
                ppp::DateTime now = ppp::threading::Executors::Now();
                ppp::string line;
                line += "{";
                line += "\"ts\":\"" + LOGGER_JSON_ESCAPE(LOGGER_NOW_ISO(now)) + "\"";
                line += ",\"event\":\"mapping-entry\"";
                line += ",\"session\":\"" + LOGGER_JSON_ESCAPE(LOGGER_GUID(guid)) + "\"";
                line += ",\"source\":\"" + LOGGER_JSON_ESCAPE(GetRemoteEndPoint(transmission)) + "\"";
                line += ",\"public\":\"" + LOGGER_JSON_ESCAPE(LOGGER_ENDPOINT(publicEP)) + "\"";
                line += ",\"transport\":\"" + ppp::string(protocol_tcp_or_udp ? "tcp" : "udp") + "\"";
                line += "}\n";

                return this->Write(line.data(), static_cast<int>(line.size()), NULLPTR);
            }
        }
    }
}
