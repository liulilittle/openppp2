#include <ppp/diagnostics/Telemetry.h>

#include <ppp/stdafx.h>

#include <mutex>
#include <condition_variable>
#include <queue>
#include <thread>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <chrono>
#include <cinttypes>
#include <algorithm>
#include <random>
#include <string>
#include <functional>
#include <thread>
#include <vector>
#include <memory>
#include <sstream>
#include <ctime>
#include <unordered_map>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
#include <windows.h>
#include <io.h>
#pragma comment(lib, "ws2_32.lib")
using socklen_t = int;
using ssize_t = int;
#else
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#define closesocket close
#define INVALID_SOCKET (-1)
using SOCKET = int;
#endif

namespace ppp {
    namespace telemetry {

        std::atomic<int>  g_min_level{0};
        std::atomic<bool> g_enabled{false};
        std::atomic<bool> g_enabled_count{false};
        std::atomic<bool> g_enabled_span{false};
        std::atomic<bool> g_console_log{true};
        std::atomic<bool> g_console_metric{true};
        std::atomic<bool> g_console_span{true};
        std::atomic<ConsoleSinkFn> g_console_sink{nullptr};
        std::atomic<HttpPostFn>    g_http_post_sink{nullptr};
        std::atomic<void*>         g_http_post_user_data{nullptr};
        std::string       g_endpoint;
        std::string       g_log_file;
        std::mutex        g_resource_attributes_mutex;
        std::unordered_map<std::string, std::string> g_resource_attributes;

        namespace {
            struct TraceContext final {
                uint64_t trace_id_hi = 0;
                uint64_t trace_id_lo = 0;
                uint64_t span_id = 0;
            };

            static thread_local std::vector<TraceContext> g_trace_stack;

            uint64_t NextRandom64() noexcept {
                static std::mt19937_64 rng{std::random_device{}()};
                static std::mutex rng_mutex;
                std::lock_guard<std::mutex> lock(rng_mutex);
                return rng();
            }

            uint64_t NowUnixNano() noexcept {
                return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
            }

            uint64_t CurrentThreadId() noexcept {
                return (uint64_t)std::hash<std::thread::id>{}(std::this_thread::get_id());
            }

            bool TryGetCurrentTraceContext(TraceContext& out) noexcept {
                if (g_trace_stack.empty()) {
                    return false;
                }
                out = g_trace_stack.back();
                return true;
            }

            std::vector<std::pair<std::string, std::string>> CopyResourceAttributes() noexcept {
                std::vector<std::pair<std::string, std::string>> attrs;
                std::lock_guard<std::mutex> lock(g_resource_attributes_mutex);
                attrs.reserve(g_resource_attributes.size());
                for (const auto& item : g_resource_attributes) {
                    if (!item.first.empty() && !item.second.empty()) {
                        attrs.emplace_back(item.first, item.second);
                    }
                }
                std::sort(attrs.begin(), attrs.end(), [](const auto& lhs, const auto& rhs) {
                    return lhs.first < rhs.first;
                });
                return attrs;
            }

            const char* ServiceVersion() noexcept {
                return PPP_APPLICATION_VERSION;
            }

            const char* PlatformName() noexcept {
#if defined(_WIN32)
                return "windows";
#elif defined(__APPLE__)
#if defined(_IPHONE) || defined(IPHONE) || defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
                return "ios";
#else
                return "macos";
#endif
#elif defined(__ANDROID__)
                return "android";
#elif defined(__linux__)
                return "linux";
#else
                return "unknown";
#endif
            }

            uint64_t ProcessId() noexcept {
#if defined(_WIN32)
                return (uint64_t)GetCurrentProcessId();
#else
                return (uint64_t)getpid();
#endif
            }

            bool IsStderrTerminal() noexcept {
#if defined(_WIN32)
                return _isatty(_fileno(stderr)) != 0;
#else
                return isatty(fileno(stderr)) != 0;
#endif
            }

            std::string Hex64(uint64_t value) {
                std::ostringstream oss;
                oss << std::hex << std::nouppercase;
                oss.width(16);
                oss.fill('0');
                oss << value;
                return oss.str();
            }

            std::string ShortHex64(uint64_t value) {
                std::string full = Hex64(value);
                return full.size() > 8 ? full.substr(0, 8) : full;
            }

            std::string FormatWallClock(uint64_t unix_ns) {
                const std::time_t seconds = (std::time_t)(unix_ns / 1000000000ULL);
                const uint64_t micros = (unix_ns / 1000ULL) % 1000000ULL;
                std::tm tmv{};
#if defined(_WIN32)
                localtime_s(&tmv, &seconds);
#else
                localtime_r(&seconds, &tmv);
#endif
                char buf[64];
                std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%06llu",
                    tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                    tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
                    (unsigned long long)micros);
                return buf;
            }

            const char* LevelColor(Level level) noexcept {
                switch (level) {
                    case Level::kInfo:  return "\x1b[32m";
                    case Level::kVerb:  return "\x1b[36m";
                    case Level::kDebug: return "\x1b[33m";
                    case Level::kTrace: return "\x1b[35m";
                }
                return "\x1b[0m";
            }

            const char* ResetColor() noexcept {
                return "\x1b[0m";
            }
        }

        void SetMinLevel(int level) noexcept {
            g_min_level.store(std::max(0, std::min(level, 3)), std::memory_order_relaxed);
        }

        void SetEnabled(bool enabled) noexcept {
            g_enabled.store(enabled, std::memory_order_relaxed);
        }

        void SetCountEnabled(bool enabled) noexcept {
            g_enabled_count.store(enabled, std::memory_order_relaxed);
        }

        void SetSpanEnabled(bool enabled) noexcept {
            g_enabled_span.store(enabled, std::memory_order_relaxed);
        }

        void SetConsoleLogEnabled(bool enabled) noexcept {
            g_console_log.store(enabled, std::memory_order_relaxed);
        }

        void SetConsoleMetricEnabled(bool enabled) noexcept {
            g_console_metric.store(enabled, std::memory_order_relaxed);
        }

        void SetConsoleSpanEnabled(bool enabled) noexcept {
            g_console_span.store(enabled, std::memory_order_relaxed);
        }

        bool IsConsoleLogEnabled() noexcept {
            return g_console_log.load(std::memory_order_relaxed);
        }

        bool IsConsoleMetricEnabled() noexcept {
            return g_console_metric.load(std::memory_order_relaxed);
        }

        bool IsConsoleSpanEnabled() noexcept {
            return g_console_span.load(std::memory_order_relaxed);
        }

        void SetConsoleSink(ConsoleSinkFn fn) noexcept {
            g_console_sink.store(fn, std::memory_order_release);
        }

        void SetHttpPostSink(HttpPostFn fn, void* user_data) noexcept {
            g_http_post_sink.store(fn, std::memory_order_release);
            g_http_post_user_data.store(user_data, std::memory_order_release);
        }

        ConsoleSinkFn GetConsoleSink() noexcept {
            return g_console_sink.load(std::memory_order_acquire);
        }

        int GetMinLevel() noexcept {
            return g_min_level.load(std::memory_order_relaxed);
        }

        void SetResourceAttribute(const char* key, const char* value) noexcept {
            if (key == nullptr || value == nullptr || key[0] == '\0') {
                return;
            }
            std::lock_guard<std::mutex> lock(g_resource_attributes_mutex);
            g_resource_attributes[key] = value;
        }

        void ClearResourceAttributes() noexcept {
            std::lock_guard<std::mutex> lock(g_resource_attributes_mutex);
            g_resource_attributes.clear();
        }

        namespace {
            struct LogEvent {
                uint64_t                               timestamp_ns;
                uint64_t                               thread_id;
                uint64_t                               trace_id_hi;
                uint64_t                               trace_id_lo;
                uint64_t                               span_id;
                bool                                  has_trace_context;
                Level                                 level;
                std::string                           component;
                std::string                           message;
                std::vector<std::pair<std::string, std::string>> attributes;
            };

            struct CounterEvent {
                uint64_t                               timestamp_ns;
                uint64_t                               thread_id;
                uint64_t                               trace_id_hi;
                uint64_t                               trace_id_lo;
                uint64_t                               span_id;
                bool                                  has_trace_context;
                std::string                           metric;
                int64_t                               delta;
            };

            struct SpanEvent {
                uint64_t                               start_time_ns;
                uint64_t                               end_time_ns;
                uint64_t                               thread_id;
                std::string                           name;
                std::string                           session_id;
                uint64_t                               trace_id_hi;
                uint64_t                               trace_id_lo;
                uint64_t                               span_id;
                uint64_t                               parent_span_id;
            };

            struct GaugeEvent {
                uint64_t                               timestamp_ns;
                uint64_t                               thread_id;
                uint64_t                               trace_id_hi;
                uint64_t                               trace_id_lo;
                uint64_t                               span_id;
                bool                                  has_trace_context;
                std::string                           metric;
                int64_t                               value;
            };

            struct HistogramEvent {
                uint64_t                               timestamp_ns;
                uint64_t                               thread_id;
                uint64_t                               trace_id_hi;
                uint64_t                               trace_id_lo;
                uint64_t                               span_id;
                bool                                  has_trace_context;
                std::string                           metric;
                int64_t                               value;
            };

            class FileSink {
            public:
                void Open(const std::string& path) {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (file_) { std::fclose(file_); file_ = nullptr; }
                    if (!path.empty()) {
                        file_ = std::fopen(path.c_str(), "a");
                        if (file_) std::setbuf(file_, nullptr);
                    }
                    path_ = path;
                }
                void Write(const char* line) noexcept {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (file_) {
                        std::fputs(line, file_);
                        std::fflush(file_);
                    }
                }
                void Close() noexcept {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (file_) { std::fclose(file_); file_ = nullptr; }
                    path_.clear();
                }
                ~FileSink() { Close(); }
            private:
                std::mutex  mutex_;
                std::FILE*  file_ = nullptr;
                std::string path_;
            };

            class HttpOtlpExporter final {
            public:
                void SetEndpoint(const std::string& url) {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (url.empty()) {
                        scheme_.clear();
                        endpoint_.clear();
                        host_.clear();
                        port_.clear();
                        base_path_.clear();
                        logs_path_.clear();
                        metrics_path_.clear();
                        traces_path_.clear();
                        return;
                    }

                    endpoint_ = url;
                    scheme_ = "http";
                    if (url.rfind("https://", 0) == 0) {
                        scheme_ = "https";
                    }

                    ParseUrl(url, scheme_, host_, port_, base_path_);
                    logs_path_ = BuildSignalPath(base_path_, "logs");
                    metrics_path_ = BuildSignalPath(base_path_, "metrics");
                    traces_path_ = BuildSignalPath(base_path_, "traces");
                }

                void ExportLogs(const std::vector<LogEvent>& events) noexcept {
                    if (events.empty() || host_.empty()) return;
                    PostHttp(logs_path_, BuildLogJson(events));
                }

                void ExportCounters(const std::vector<CounterEvent>& events) noexcept {
                    if (events.empty() || host_.empty()) return;
                    PostHttp(metrics_path_, BuildCounterJson(events));
                }

                void ExportSpans(const std::vector<SpanEvent>& events) noexcept {
                    if (events.empty() || host_.empty()) return;
                    PostHttp(traces_path_, BuildSpanJson(events));
                }

                void ExportGauges(const std::vector<GaugeEvent>& events) noexcept {
                    if (events.empty() || host_.empty()) return;
                    PostHttp(metrics_path_, BuildGaugeJson(events));
                }

                void ExportHistograms(const std::vector<HistogramEvent>& events) noexcept {
                    if (events.empty() || host_.empty()) return;
                    PostHttp(metrics_path_, BuildHistogramJson(events));
                }

            private:
                static std::string TrimTrailingSlash(std::string value) {
                    while (!value.empty() && value.back() == '/') {
                        value.pop_back();
                    }
                    return value;
                }

                static std::string BuildSignalPath(const std::string& base_path, const char* signal) {
                    const std::string suffix = std::string("/v1/") + signal;
                    if (base_path.empty()) {
                        return suffix;
                    }

                    if (base_path.find("/v1/") != std::string::npos) {
                        const std::string logs_suffix = "/v1/logs";
                        const std::string metrics_suffix = "/v1/metrics";
                        const std::string traces_suffix = "/v1/traces";
                        if (base_path.size() >= logs_suffix.size()
                            && base_path.compare(base_path.size() - logs_suffix.size(), logs_suffix.size(), logs_suffix) == 0) {
                            return TrimTrailingSlash(base_path.substr(0, base_path.size() - logs_suffix.size())) + suffix;
                        }
                        if (base_path.size() >= metrics_suffix.size()
                            && base_path.compare(base_path.size() - metrics_suffix.size(), metrics_suffix.size(), metrics_suffix) == 0) {
                            return TrimTrailingSlash(base_path.substr(0, base_path.size() - metrics_suffix.size())) + suffix;
                        }
                        if (base_path.size() >= traces_suffix.size()
                            && base_path.compare(base_path.size() - traces_suffix.size(), traces_suffix.size(), traces_suffix) == 0) {
                            return TrimTrailingSlash(base_path.substr(0, base_path.size() - traces_suffix.size())) + suffix;
                        }
                    }

                    return TrimTrailingSlash(base_path) + suffix;
                }

                std::string BuildFullUrl(const std::string& path) const {
                    if (host_.empty() || path.empty()) {
                        return {};
                    }
                    // Omit scheme-default ports so HTTPS stays on 443, not OTLP 4318.
                    if ((scheme_ == "https" && port_ == "443") || (scheme_ == "http" && port_ == "80")) {
                        return scheme_ + "://" + host_ + path;
                    }
                    return scheme_ + "://" + host_ + ":" + port_ + path;
                }

                void PostHttp(const std::string& path, const std::string& body) noexcept {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (host_.empty() || path.empty()) {
                        return;
                    }

                    const std::string full_url = BuildFullUrl(path);
                    HttpPostFn sink = g_http_post_sink.load(std::memory_order_acquire);
                    void* user_data = g_http_post_user_data.load(std::memory_order_acquire);
                    if (sink != nullptr) {
                        sink(full_url.c_str(), body.data(), body.size(), user_data);
                        return;
                    }

                    if (scheme_ == "https") {
                        return;
                    }

                    struct addrinfo hints{}, *result = nullptr;
                    hints.ai_family = AF_UNSPEC;
                    hints.ai_socktype = SOCK_STREAM;
                    if (getaddrinfo(host_.c_str(), port_.c_str(), &hints, &result) != 0) return;

                    SOCKET sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
                    if (sock == INVALID_SOCKET) { freeaddrinfo(result); return; }

                    struct timeval tv{1, 0};
                    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
                    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

                    if (connect(sock, result->ai_addr, (socklen_t)result->ai_addrlen) != 0) {
                        closesocket(sock); freeaddrinfo(result); return;
                    }
                    freeaddrinfo(result);

                    std::string request;
                    request += "POST " + path + " HTTP/1.0\r\n";
                    request += "Host: " + host_ + "\r\n";
                    request += "Content-Type: application/json\r\n";
                    request += "Content-Length: " + std::to_string(body.size()) + "\r\n";
                    request += "Connection: close\r\n";
                    request += "\r\n";
                    request += body;

                    send(sock, request.data(), (int)request.size(), 0);
                    char discard[256];
                    recv(sock, discard, sizeof(discard) - 1, 0);
                    closesocket(sock);
                }

                static void ParseUrl(const std::string& url, const std::string& scheme, std::string& host, std::string& port, std::string& path) {
                    const char* p = url.c_str();
                    if (strncmp(p, "http://", 7) == 0) p += 7;
                    else if (strncmp(p, "https://", 8) == 0) p += 8;

                    const char* slash = strchr(p, '/');
                    if (slash) { path.assign(slash); host.assign(p, slash - p); }
                    else       { path.clear(); host = p; }

                    // For IPv6 literals, only strip a port after the closing bracket.
                    const char* colon = nullptr;
                    if (!host.empty() && host.front() == '[') {
                        const auto bracket = host.find(']');
                        if (bracket != std::string::npos && bracket + 1 < host.size() && host[bracket + 1] == ':') {
                            colon = host.c_str() + bracket + 1;
                        }
                    }
                    else {
                        colon = strrchr(host.c_str(), ':');
                    }

                    if (colon) {
                        port.assign(colon + 1);
                        host.resize(static_cast<size_t>(colon - host.c_str()));
                    }
                    else if (scheme == "https") {
                        // Public HTTPS endpoints use 443 rather than the OTLP HTTP default.
                        port = "443";
                    }
                    else {
                        port = "4318";
                    }
                }

                static std::string BuildAttributeJson(const std::vector<std::pair<std::string, std::string>>& attributes) noexcept {
                    std::string json;
                    for (size_t i = 0; i < attributes.size(); ++i) {
                        if (i > 0) json += ",";
                        json += "{\"key\":\"" + JsonEscape(attributes[i].first) + "\",\"value\":{\"stringValue\":\"" + JsonEscape(attributes[i].second) + "\"}}";
                    }
                    return json;
                }

                static std::string BuildResourceJson() noexcept {
                    std::string json = "{\"attributes\":[";
                    json += "{\"key\":\"service.name\",\"value\":{\"stringValue\":\"openppp2\"}},";
                    json += "{\"key\":\"service.version\",\"value\":{\"stringValue\":\"" + JsonEscape(ServiceVersion()) + "\"}},";
                    json += "{\"key\":\"platform\",\"value\":{\"stringValue\":\"" + JsonEscape(PlatformName()) + "\"}},";
                    json += "{\"key\":\"process.pid\",\"value\":{\"intValue\":\"" + std::to_string(ProcessId()) + "\"}}";
                    const auto extra_attrs = CopyResourceAttributes();
                    for (const auto& attr : extra_attrs) {
                        json += ",{\"key\":\"" + JsonEscape(attr.first) + "\",\"value\":{\"stringValue\":\"" + JsonEscape(attr.second) + "\"}}";
                    }
                    json += "]}";
                    return json;
                }

                static std::string BuildLogJson(const std::vector<LogEvent>& events) noexcept {
                    std::string json = "{\"resourceLogs\":[{\"resource\":" + BuildResourceJson() + ",\"scopeLogs\":[{\"scope\":{},\"logRecords\":[";
                    for (size_t i = 0; i < events.size(); ++i) {
                        if (i > 0) json += ",";
                        json += "{\"timeUnixNano\":\"" + std::to_string(events[i].timestamp_ns) + "\",";
                        if (events[i].has_trace_context) {
                            json += "\"traceId\":\"" + Hex64(events[i].trace_id_hi) + Hex64(events[i].trace_id_lo) + "\",";
                            json += "\"spanId\":\"" + Hex64(events[i].span_id) + "\",";
                        }
                        json += "\"severityText\":\"" + LevelName(events[i].level) + "\",";
                        json += "\"body\":{\"stringValue\":\"" + JsonEscape(events[i].message) + "\"},";
                        json += "\"attributes\":[";
                        json += "{\"key\":\"component\",\"value\":{\"stringValue\":\"" + JsonEscape(events[i].component) + "\"}},";
                        json += "{\"key\":\"log.level\",\"value\":{\"stringValue\":\"" + LevelName(events[i].level) + "\"}},";
                        json += "{\"key\":\"thread.id\",\"value\":{\"stringValue\":\"" + std::to_string(events[i].thread_id) + "\"}}";
                        if (!events[i].attributes.empty()) {
                            json += "," + BuildAttributeJson(events[i].attributes);
                        }
                        json += "]}";
                    }
                    json += "]}]}]}";
                    return json;
                }

                static std::string BuildCounterJson(const std::vector<CounterEvent>& events) noexcept {
                    std::string json = "{\"resourceMetrics\":[{\"resource\":" + BuildResourceJson() + ",\"scopeMetrics\":[{\"scope\":{},\"metrics\":[";
                    for (size_t i = 0; i < events.size(); ++i) {
                        if (i > 0) json += ",";
                        json += "{\"name\":\"" + JsonEscape(events[i].metric) + "\",";
                        json += "\"sum\":{\"dataPoints\":[{\"timeUnixNano\":\"" + std::to_string(events[i].timestamp_ns) + "\",";
                        json += "\"attributes\":[{\"key\":\"thread.id\",\"value\":{\"stringValue\":\"" + std::to_string(events[i].thread_id) + "\"}}";
                        if (events[i].has_trace_context) {
                            json += ",{\"key\":\"trace.id\",\"value\":{\"stringValue\":\"" + Hex64(events[i].trace_id_hi) + Hex64(events[i].trace_id_lo) + "\"}}";
                            json += ",{\"key\":\"span.id\",\"value\":{\"stringValue\":\"" + Hex64(events[i].span_id) + "\"}}";
                        }
                        json += "],";
                        json += "\"asInt\":\"" + std::to_string(events[i].delta) + "\"}],\"aggregationTemporality\":2,\"isMonotonic\":true}}";
                    }
                    json += "]}]}]}";
                    return json;
                }

                static std::string BuildSpanJson(const std::vector<SpanEvent>& events) noexcept {
                    std::string json = "{\"resourceSpans\":[{\"resource\":" + BuildResourceJson() + ",\"scopeSpans\":[{\"scope\":{},\"spans\":[";
                    for (size_t i = 0; i < events.size(); ++i) {
                        if (i > 0) json += ",";
                        json += "{\"traceId\":\"" + Hex64(events[i].trace_id_hi) + Hex64(events[i].trace_id_lo) + "\",";
                        json += "\"spanId\":\"" + Hex64(events[i].span_id) + "\",";
                        if (events[i].parent_span_id != 0) {
                            json += "\"parentSpanId\":\"" + Hex64(events[i].parent_span_id) + "\",";
                        }
                        json += "\"name\":\"" + JsonEscape(events[i].name) + "\",";
                        json += "\"startTimeUnixNano\":\"" + std::to_string(events[i].start_time_ns) + "\",";
                        json += "\"endTimeUnixNano\":\"" + std::to_string(events[i].end_time_ns) + "\",";
                        json += "\"attributes\":[{\"key\":\"thread.id\",\"value\":{\"stringValue\":\"" + std::to_string(events[i].thread_id) + "\"}}";
                        if (!events[i].session_id.empty()) {
                            json += ",{\"key\":\"session.id\",\"value\":{\"stringValue\":\"" + JsonEscape(events[i].session_id) + "\"}}";
                        }
                        json += "]}";
                    }
                    json += "]}]}]}";
                    return json;
                }

                static std::string BuildGaugeJson(const std::vector<GaugeEvent>& events) noexcept {
                    std::string json = "{\"resourceMetrics\":[{\"resource\":" + BuildResourceJson() + ",\"scopeMetrics\":[{\"scope\":{},\"metrics\":[";
                    for (size_t i = 0; i < events.size(); ++i) {
                        if (i > 0) json += ",";
                        json += "{\"name\":\"" + JsonEscape(events[i].metric) + "\",";
                        json += "\"gauge\":{\"dataPoints\":[{\"timeUnixNano\":\"" + std::to_string(events[i].timestamp_ns) + "\",";
                        json += "\"attributes\":[{\"key\":\"thread.id\",\"value\":{\"stringValue\":\"" + std::to_string(events[i].thread_id) + "\"}}";
                        if (events[i].has_trace_context) {
                            json += ",{\"key\":\"trace.id\",\"value\":{\"stringValue\":\"" + Hex64(events[i].trace_id_hi) + Hex64(events[i].trace_id_lo) + "\"}}";
                            json += ",{\"key\":\"span.id\",\"value\":{\"stringValue\":\"" + Hex64(events[i].span_id) + "\"}}";
                        }
                        json += "],";
                        json += "\"asInt\":\"" + std::to_string(events[i].value) + "\"}]}}";
                    }
                    json += "]}]}]}";
                    return json;
                }

                static std::string BuildHistogramJson(const std::vector<HistogramEvent>& events) noexcept {
                    std::string json = "{\"resourceMetrics\":[{\"resource\":" + BuildResourceJson() + ",\"scopeMetrics\":[{\"scope\":{},\"metrics\":[";
                    for (size_t i = 0; i < events.size(); ++i) {
                        if (i > 0) json += ",";
                        json += "{\"name\":\"" + JsonEscape(events[i].metric) + "\",";
                        json += "\"histogram\":{\"dataPoints\":[{";
                        json += "\"timeUnixNano\":\"" + std::to_string(events[i].timestamp_ns) + "\",";
                        json += "\"attributes\":[{\"key\":\"thread.id\",\"value\":{\"stringValue\":\"" + std::to_string(events[i].thread_id) + "\"}}";
                        if (events[i].has_trace_context) {
                            json += ",{\"key\":\"trace.id\",\"value\":{\"stringValue\":\"" + Hex64(events[i].trace_id_hi) + Hex64(events[i].trace_id_lo) + "\"}}";
                            json += ",{\"key\":\"span.id\",\"value\":{\"stringValue\":\"" + Hex64(events[i].span_id) + "\"}}";
                        }
                        json += "],";
                        json += "\"count\":\"1\",";
                        json += "\"sum\":\"" + std::to_string(events[i].value) + "\",";
                        json += "\"bucketCounts\":[\"0\",\"0\",\"0\",\"0\",\"0\",\"1\"],";
                        json += "\"explicitBounds\":[\"1\",\"10\",\"100\",\"1000\",\"10000\"]";
                        json += "}],\"aggregationTemporality\":2}}";
                    }
                    json += "]}]}]}";
                    return json;
                }

                static std::string LevelName(Level level) noexcept {
                    switch (level) {
                        case Level::kInfo:  return "INFO";
                        case Level::kVerb:  return "VERB";
                        case Level::kDebug: return "DEBUG";
                        case Level::kTrace: return "TRACE";
                    }
                    return "INFO";
                }

                static std::string JsonEscape(const std::string& s) noexcept {
                    std::string r; r.reserve(s.size() + 8);
                    for (char c : s) {
                        switch (c) {
                            case '"':  r += "\\\""; break;
                            case '\\': r += "\\\\"; break;
                            case '\n': r += "\\n";  break;
                            case '\r': r += "\\r";  break;
                            case '\t': r += "\\t";  break;
                            default:   r += c;      break;
                        }
                    }
                    return r;
                }

                std::mutex  mutex_;
                std::string endpoint_;
                std::string scheme_;
                std::string host_;
                std::string port_;
                std::string base_path_;
                std::string logs_path_;
                std::string metrics_path_;
                std::string traces_path_;
            };

            class TelemetryBackend final {
            public:
                TelemetryBackend() { worker_ = std::thread(&TelemetryBackend::Run, this); }
                ~TelemetryBackend() { Stop(); }

                void EnqueueLog(Level level, const char* component, const char* message, const Attribute* attrs = nullptr, size_t attr_count = 0) {
                    if (!running_.load()) return;
                    TraceContext ctx{};
                    const bool has_ctx = TryGetCurrentTraceContext(ctx);
                    std::vector<std::pair<std::string, std::string>> copied_attrs;
                    copied_attrs.reserve(attr_count);
                    for (size_t i = 0; i < attr_count; ++i) {
                        const Attribute& attr = attrs[i];
                        if (!attr.key || !attr.value) {
                            continue;
                        }
                        copied_attrs.emplace_back(attr.key, attr.value);
                    }
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (!running_.load()) return;
                    if (log_queue_.size() >= kMaxQueueSize) { dropped_logs_++; return; }
                    log_queue_.push({NowUnixNano(), CurrentThreadId(), ctx.trace_id_hi, ctx.trace_id_lo, ctx.span_id, has_ctx, level, component, message, std::move(copied_attrs)});
                    cv_.notify_one();
                }

                void EnqueueCount(const char* metric, int64_t delta) {
                    if (!running_.load()) return;
                    TraceContext ctx{};
                    const bool has_ctx = TryGetCurrentTraceContext(ctx);
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (!running_.load()) return;
                    if (counter_queue_.size() >= kMaxQueueSize) { dropped_counters_++; return; }
                    counter_queue_.push({NowUnixNano(), CurrentThreadId(), ctx.trace_id_hi, ctx.trace_id_lo, ctx.span_id, has_ctx, metric, delta});
                    cv_.notify_one();
                }

                void EnqueueSpan(const char* name, const char* session_id) {
                    if (!running_.load()) return;
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (!running_.load()) return;
                    if (span_queue_.size() >= kMaxQueueSize) { dropped_spans_++; return; }
                    span_queue_.push({NowUnixNano(), NowUnixNano(), CurrentThreadId(), name, session_id, 0, 0, 0, 0});
                    cv_.notify_one();
                }

                void EnqueueGauge(const char* metric, int64_t value) {
                    if (!running_.load()) return;
                    TraceContext ctx{};
                    const bool has_ctx = TryGetCurrentTraceContext(ctx);
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (!running_.load()) return;
                    if (gauge_queue_.size() >= kMaxQueueSize) { dropped_gauges_++; return; }
                    gauge_queue_.push({NowUnixNano(), CurrentThreadId(), ctx.trace_id_hi, ctx.trace_id_lo, ctx.span_id, has_ctx, metric, value});
                    cv_.notify_one();
                }

                void EnqueueHistogram(const char* metric, int64_t value) {
                    if (!running_.load()) return;
                    TraceContext ctx{};
                    const bool has_ctx = TryGetCurrentTraceContext(ctx);
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (!running_.load()) return;
                    if (histogram_queue_.size() >= kMaxQueueSize) { dropped_histograms_++; return; }
                    histogram_queue_.push({NowUnixNano(), CurrentThreadId(), ctx.trace_id_hi, ctx.trace_id_lo, ctx.span_id, has_ctx, metric, value});
                    cv_.notify_one();
                }

                void EnqueueCompletedSpan(uint64_t start_time_ns, uint64_t end_time_ns, const char* name,
                    const char* session_id, uint64_t trace_id_hi, uint64_t trace_id_lo, uint64_t span_id, uint64_t parent_span_id) {
                    if (!running_.load()) return;
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (!running_.load()) return;
                    if (span_queue_.size() >= kMaxQueueSize) { dropped_spans_++; return; }
                    span_queue_.push({start_time_ns, end_time_ns, CurrentThreadId(), name ? name : "", session_id ? session_id : "", trace_id_hi, trace_id_lo, span_id, parent_span_id});
                    cv_.notify_one();
                }

                void SetOtlpEndpoint(const std::string& url) {
                    std::lock_guard<std::mutex> lock(mutex_);
                    SetOtlpEndpointLocked(url);
                }

                void SetLogFile(const std::string& path) {
                    file_sink_.Open(path);
                }

                void RefreshConfig() {
                    std::lock_guard<std::mutex> lock(mutex_);
                    SetOtlpEndpointLocked(g_endpoint);
                    file_sink_.Open(g_log_file);
                }

                void Flush(int timeout_ms) {
                    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
                    while (std::chrono::steady_clock::now() < deadline) {
                        std::unique_lock<std::mutex> lock(mutex_);
                        if (log_queue_.empty() && counter_queue_.empty() && span_queue_.empty() && gauge_queue_.empty() && histogram_queue_.empty()) {
                            return;
                        }
                        lock.unlock();
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    }
                }

            private:
#if defined(IPHONE)
                static constexpr size_t kMaxQueueSize = 256;
                static constexpr size_t kBatchSize    = 32;
#else
                static constexpr size_t kMaxQueueSize = 4096;
                static constexpr size_t kBatchSize    = 256;
#endif

                void SetOtlpEndpointLocked(const std::string& url) {
                    use_otlp_ = !url.empty();
                    exporter_.SetEndpoint(url);
                }

                void Run() noexcept {
                    for (;;) {
                        std::unique_lock<std::mutex> lock(mutex_);
#if defined(IPHONE)
                        cv_.wait_for(lock, std::chrono::milliseconds(500),
#else
                        cv_.wait_for(lock, std::chrono::milliseconds(100),
#endif
                            [this] { return HasPendingLocked() || !running_.load(); });

                        if (!running_.load() && !HasPendingLocked()) {
                            break;
                        }

                        if (use_otlp_) {
                            DispatchOtlp(lock);
                        } else {
                            DispatchLocal(lock);
                        }
                    }
                }

                bool HasPendingLocked() const noexcept {
                    return !log_queue_.empty() || !counter_queue_.empty() || !span_queue_.empty() || !gauge_queue_.empty() || !histogram_queue_.empty();
                }

                void DispatchOtlp(std::unique_lock<std::mutex>& lock) {
                    std::vector<LogEvent>    log_batch;
                    std::vector<CounterEvent> counter_batch;
                    std::vector<SpanEvent>    span_batch;
                    std::vector<GaugeEvent>   gauge_batch;
                    std::vector<HistogramEvent> histogram_batch;

                    while (!log_queue_.empty() && log_batch.size() < kBatchSize) {
                        log_batch.push_back(std::move(log_queue_.front()));
                        log_queue_.pop();
                    }
                    while (!counter_queue_.empty() && counter_batch.size() < kBatchSize) {
                        counter_batch.push_back(std::move(counter_queue_.front()));
                        counter_queue_.pop();
                    }
                    while (!span_queue_.empty() && span_batch.size() < kBatchSize) {
                        span_batch.push_back(std::move(span_queue_.front()));
                        span_queue_.pop();
                    }
                    while (!gauge_queue_.empty() && gauge_batch.size() < kBatchSize) {
                        gauge_batch.push_back(std::move(gauge_queue_.front()));
                        gauge_queue_.pop();
                    }
                    while (!histogram_queue_.empty() && histogram_batch.size() < kBatchSize) {
                        histogram_batch.push_back(std::move(histogram_queue_.front()));
                        histogram_queue_.pop();
                    }

                    lock.unlock();
                    for (const LogEvent& ev : log_batch) {
                        if (static_cast<int>(ev.level) <= g_min_level.load(std::memory_order_relaxed)) {
                            PrintLog(ev);
                        }
                    }
                    for (const CounterEvent& ev : counter_batch) {
                        PrintCounter(ev);
                    }
                    for (const SpanEvent& ev : span_batch) {
                        PrintSpan(ev);
                    }
                    for (const GaugeEvent& ev : gauge_batch) {
                        PrintGauge(ev);
                    }
                    for (const HistogramEvent& ev : histogram_batch) {
                        PrintHistogram(ev);
                    }
                    if (!log_batch.empty())    exporter_.ExportLogs(log_batch);
                    if (!counter_batch.empty()) exporter_.ExportCounters(counter_batch);
                    if (!span_batch.empty())    exporter_.ExportSpans(span_batch);
                    if (!gauge_batch.empty())   exporter_.ExportGauges(gauge_batch);
                    if (!histogram_batch.empty()) exporter_.ExportHistograms(histogram_batch);
                    lock.lock();
                }

                void DispatchLocal(std::unique_lock<std::mutex>& lock) {
                    ProcessLogs(lock);
                    ProcessCounters(lock);
                    ProcessSpans(lock);
                    ProcessGauges(lock);
                    ProcessHistograms(lock);
                }

                void ProcessLogs(std::unique_lock<std::mutex>& lock) {
                    while (!log_queue_.empty()) {
                        LogEvent ev = std::move(log_queue_.front());
                        log_queue_.pop();
                        lock.unlock();
                        if (static_cast<int>(ev.level) <= g_min_level.load(std::memory_order_relaxed)) {
                            PrintLog(ev);
                        }
                        lock.lock();
                    }
                }

                void ProcessCounters(std::unique_lock<std::mutex>& lock) {
                    while (!counter_queue_.empty()) {
                        CounterEvent ev = std::move(counter_queue_.front());
                        counter_queue_.pop();
                        lock.unlock();
                        PrintCounter(ev);
                        lock.lock();
                    }
                }

                void ProcessSpans(std::unique_lock<std::mutex>& lock) {
                    while (!span_queue_.empty()) {
                        SpanEvent ev = std::move(span_queue_.front());
                        span_queue_.pop();
                        lock.unlock();
                        PrintSpan(ev);
                        lock.lock();
                    }
                }

                void ProcessGauges(std::unique_lock<std::mutex>& lock) {
                    while (!gauge_queue_.empty()) {
                        GaugeEvent ev = std::move(gauge_queue_.front());
                        gauge_queue_.pop();
                        lock.unlock();
                        PrintGauge(ev);
                        lock.lock();
                    }
                }

                void ProcessHistograms(std::unique_lock<std::mutex>& lock) {
                    while (!histogram_queue_.empty()) {
                        HistogramEvent ev = std::move(histogram_queue_.front());
                        histogram_queue_.pop();
                        lock.unlock();
                        PrintHistogram(ev);
                        lock.lock();
                    }
                }

                void PrintLog(const LogEvent& ev) noexcept {
                    if (!g_console_log.load(std::memory_order_relaxed)) {
                        return;
                    }
                    const char* level_str = "INFO";
                    switch (ev.level) {
                        case Level::kVerb:  level_str = "VERB";  break;
                        case Level::kDebug: level_str = "DEBUG"; break;
                        case Level::kTrace: level_str = "TRACE"; break;
                        default: break;
                    }
                    const bool tty = IsStderrTerminal();
                    std::string line;
                    line += "[" + FormatWallClock(ev.timestamp_ns) + "] ";
                    if (tty) line += LevelColor(ev.level);
                    line += level_str;
                    if (tty) line += ResetColor();
                    line += " [";
                    line += ev.component;
                    line += "]";
                    if (ev.has_trace_context) {
                        line += " trace=" + ShortHex64(ev.trace_id_hi) + ShortHex64(ev.trace_id_lo);
                        line += " span=" + ShortHex64(ev.span_id);
                    }
                    line += " tid=" + std::to_string(ev.thread_id);
                    line += " :: ";
                    line += ev.message;
                    if (!ev.attributes.empty()) {
                        line += " attrs={";
                        for (size_t i = 0; i < ev.attributes.size(); ++i) {
                            if (i > 0) line += ", ";
                            line += ev.attributes[i].first;
                            line += "=";
                            line += ev.attributes[i].second;
                        }
                        line += "}";
                    }
                    line += "\n";
                    ConsoleSinkFn sink = g_console_sink.load(std::memory_order_acquire);
                    if (sink) {
                        sink(line.c_str());
                    } else {
                        std::fputs(line.c_str(), stderr);
                    }
                    file_sink_.Write(line.c_str());
                }

                void PrintCounter(const CounterEvent& ev) noexcept {
                    if (!g_console_metric.load(std::memory_order_relaxed)) {
                        return;
                    }
                    std::string line;
                    line += "[" + FormatWallClock(ev.timestamp_ns) + "] COUNT [" + ev.metric + "]";
                    if (ev.has_trace_context) {
                        line += " trace=" + ShortHex64(ev.trace_id_hi) + ShortHex64(ev.trace_id_lo);
                        line += " span=" + ShortHex64(ev.span_id);
                    }
                    line += " tid=" + std::to_string(ev.thread_id);
                    line += " delta=" + std::to_string(ev.delta) + "\n";
                    ConsoleSinkFn sink = g_console_sink.load(std::memory_order_acquire);
                    if (sink) {
                        sink(line.c_str());
                    } else {
                        std::fputs(line.c_str(), stderr);
                    }
                    file_sink_.Write(line.c_str());
                }

                void PrintSpan(const SpanEvent& ev) noexcept {
                    if (!g_console_span.load(std::memory_order_relaxed)) {
                        return;
                    }
                    std::string line;
                    line += "[" + FormatWallClock(ev.end_time_ns) + "] SPAN [" + ev.name + "]";
                    line += " trace=" + ShortHex64(ev.trace_id_hi) + ShortHex64(ev.trace_id_lo);
                    line += " span=" + ShortHex64(ev.span_id);
                    if (ev.parent_span_id != 0) {
                        line += " parent=" + ShortHex64(ev.parent_span_id);
                    }
                    if (!ev.session_id.empty()) {
                        line += " session=" + ev.session_id;
                    }
                    line += " dur=" + std::to_string((ev.end_time_ns - ev.start_time_ns) / 1000ULL) + "us\n";
                    ConsoleSinkFn sink = g_console_sink.load(std::memory_order_acquire);
                    if (sink) {
                        sink(line.c_str());
                    } else {
                        std::fputs(line.c_str(), stderr);
                    }
                    file_sink_.Write(line.c_str());
                }

                void PrintGauge(const GaugeEvent& ev) noexcept {
                    if (!g_console_metric.load(std::memory_order_relaxed)) {
                        return;
                    }
                    std::string line;
                    line += "[" + FormatWallClock(ev.timestamp_ns) + "] GAUGE [" + ev.metric + "]";
                    if (ev.has_trace_context) {
                        line += " trace=" + ShortHex64(ev.trace_id_hi) + ShortHex64(ev.trace_id_lo);
                        line += " span=" + ShortHex64(ev.span_id);
                    }
                    line += " tid=" + std::to_string(ev.thread_id);
                    line += " value=" + std::to_string(ev.value) + "\n";
                    ConsoleSinkFn sink = g_console_sink.load(std::memory_order_acquire);
                    if (sink) {
                        sink(line.c_str());
                    } else {
                        std::fputs(line.c_str(), stderr);
                    }
                    file_sink_.Write(line.c_str());
                }

                void PrintHistogram(const HistogramEvent& ev) noexcept {
                    if (!g_console_metric.load(std::memory_order_relaxed)) {
                        return;
                    }
                    std::string line;
                    line += "[" + FormatWallClock(ev.timestamp_ns) + "] HIST [" + ev.metric + "]";
                    if (ev.has_trace_context) {
                        line += " trace=" + ShortHex64(ev.trace_id_hi) + ShortHex64(ev.trace_id_lo);
                        line += " span=" + ShortHex64(ev.span_id);
                    }
                    line += " v=" + std::to_string(ev.value) + "\n";
                    ConsoleSinkFn sink = g_console_sink.load(std::memory_order_acquire);
                    if (sink) {
                        sink(line.c_str());
                    } else {
                        std::fputs(line.c_str(), stderr);
                    }
                    file_sink_.Write(line.c_str());
                }

            public:
                void Stop() noexcept {
                    {
                        std::lock_guard<std::mutex> lock(mutex_);
                        running_.store(false);
                    }
                    cv_.notify_all();
                    if (worker_.joinable()) worker_.join();
                    file_sink_.Close();
                }

            private:
                std::mutex                    mutex_;
                std::condition_variable       cv_;
                std::queue<LogEvent>          log_queue_;
                std::queue<CounterEvent>      counter_queue_;
                std::queue<SpanEvent>         span_queue_;
                std::queue<GaugeEvent>        gauge_queue_;
                std::queue<HistogramEvent>    histogram_queue_;
                std::thread                   worker_;
                std::atomic<bool>             running_{true};
                uint64_t                      dropped_logs_     = 0;
                uint64_t                      dropped_counters_ = 0;
                uint64_t                      dropped_spans_    = 0;
                uint64_t                      dropped_gauges_   = 0;
                uint64_t                      dropped_histograms_ = 0;
                bool                          use_otlp_         = false;
                HttpOtlpExporter              exporter_;
                FileSink                      file_sink_;
            };

            TelemetryBackend& GetBackend() noexcept {
                static TelemetryBackend* backend = new TelemetryBackend();
                return *backend;
            }
        }

        void Configure(const char* endpoint) noexcept {
            if (endpoint && endpoint[0]) {
                g_endpoint = endpoint;
            } else {
                g_endpoint.clear();
            }
            GetBackend().RefreshConfig();
        }

        void SetLogFile(const char* path) noexcept {
            if (path && path[0]) {
                g_log_file = path;
            } else {
                g_log_file.clear();
            }
            GetBackend().RefreshConfig();
        }

        void Log(Level level, const char* component, const char* fmt, ...) noexcept {
            if (!g_enabled.load(std::memory_order_relaxed)) return;
            if (static_cast<int>(level) > g_min_level.load(std::memory_order_relaxed)) return;
            char buffer[1024];
            va_list args;
            va_start(args, fmt);
            std::vsnprintf(buffer, sizeof(buffer), fmt, args);
            va_end(args);
            buffer[sizeof(buffer) - 1] = '\0';
            GetBackend().EnqueueLog(level, component ? component : "", buffer);
        }

        void LogWithAttributes(Level level, const char* component, const Attribute* attrs, size_t attr_count, const char* fmt, ...) noexcept {
            if (!g_enabled.load(std::memory_order_relaxed)) return;
            if (static_cast<int>(level) > g_min_level.load(std::memory_order_relaxed)) return;
            char buffer[1024];
            va_list args;
            va_start(args, fmt);
            std::vsnprintf(buffer, sizeof(buffer), fmt, args);
            va_end(args);
            buffer[sizeof(buffer) - 1] = '\0';
            GetBackend().EnqueueLog(level, component ? component : "", buffer, attrs, attr_count);
        }

        void Count(const char* metric, int64_t delta) noexcept {
            if (!g_enabled.load(std::memory_order_relaxed)) return;
            if (!g_enabled_count.load(std::memory_order_relaxed)) return;
            GetBackend().EnqueueCount(metric ? metric : "", delta);
        }

        void Gauge(const char* metric, int64_t value) noexcept {
            if (!g_enabled.load(std::memory_order_relaxed)) return;
            if (!g_enabled_count.load(std::memory_order_relaxed)) return;
            GetBackend().EnqueueGauge(metric ? metric : "", value);
        }

        void Histogram(const char* metric, int64_t value) noexcept {
            if (!g_enabled.load(std::memory_order_relaxed)) return;
            if (!g_enabled_count.load(std::memory_order_relaxed)) return;
            GetBackend().EnqueueHistogram(metric ? metric : "", value);
        }

        void TraceSpan(const char* name, const char* session_id) noexcept {
            if (!g_enabled.load(std::memory_order_relaxed)) return;
            if (!g_enabled_span.load(std::memory_order_relaxed)) return;
            uint64_t trace_id_hi = 0;
            uint64_t trace_id_lo = 0;
            uint64_t parent_span_id = 0;

            if (!g_trace_stack.empty()) {
                trace_id_hi = g_trace_stack.back().trace_id_hi;
                trace_id_lo = g_trace_stack.back().trace_id_lo;
                parent_span_id = g_trace_stack.back().span_id;
            } else {
                trace_id_hi = NextRandom64();
                trace_id_lo = NextRandom64();
            }

            const uint64_t now = NowUnixNano();
            GetBackend().EnqueueCompletedSpan(now, now, name ? name : "", session_id ? session_id : "", trace_id_hi, trace_id_lo, NextRandom64(), parent_span_id);
        }

        SpanScope::SpanScope(const char* name, const char* session_id) noexcept
            : name_(name), session_id_(session_id), start_time_ns_(0), trace_id_hi_(0), trace_id_lo_(0), span_id_(0), parent_span_id_(0), active_(false) {
            if (!g_enabled.load(std::memory_order_relaxed) || !g_enabled_span.load(std::memory_order_relaxed)) {
                return;
            }

            start_time_ns_ = NowUnixNano();
            span_id_ = NextRandom64();

            if (!g_trace_stack.empty()) {
                trace_id_hi_ = g_trace_stack.back().trace_id_hi;
                trace_id_lo_ = g_trace_stack.back().trace_id_lo;
                parent_span_id_ = g_trace_stack.back().span_id;
            } else {
                trace_id_hi_ = NextRandom64();
                trace_id_lo_ = NextRandom64();
            }

            g_trace_stack.push_back({trace_id_hi_, trace_id_lo_, span_id_});
            active_ = true;
        }

        SpanScope::SpanScope(SpanScope&& other) noexcept
            : name_(other.name_), session_id_(other.session_id_), start_time_ns_(other.start_time_ns_), trace_id_hi_(other.trace_id_hi_), trace_id_lo_(other.trace_id_lo_), span_id_(other.span_id_), parent_span_id_(other.parent_span_id_), active_(other.active_) {
            other.active_ = false;
        }

        SpanScope::~SpanScope() noexcept {
            if (!active_) {
                return;
            }

            const uint64_t end_time_ns = NowUnixNano();
            GetBackend().EnqueueCompletedSpan(start_time_ns_, end_time_ns,
                name_ ? name_ : "", session_id_ ? session_id_ : "",
                trace_id_hi_, trace_id_lo_, span_id_, parent_span_id_);

            if (!g_trace_stack.empty() && g_trace_stack.back().span_id == span_id_) {
                g_trace_stack.pop_back();
            }
        }

        void Flush(int timeout_ms) noexcept {
            GetBackend().Flush(timeout_ms);
        }

        void Shutdown() noexcept {
            g_enabled.store(false, std::memory_order_relaxed);
            g_enabled_count.store(false, std::memory_order_relaxed);
            g_enabled_span.store(false, std::memory_order_relaxed);
            GetBackend().Stop();
        }

    }
}
