#pragma once

/**
 * @file Telemetry.h
 * @brief Always-compiled telemetry facade for observability.
 *
 * @details All telemetry code is unconditionally compiled.  Runtime behavior
 *          is controlled by the g_enabled flag which defaults to false.
 *          The JSON config field "telemetry": { "enabled": true } activates
 *          the backend at application startup.
 *
 *          This facade never allocates, never throws, and never blocks on
 *          the hot path when telemetry is disabled at runtime.
 *
 *          Callers that only need Log/Count/Gauge/Histogram should include
 *          TelemetryFwd.h instead to avoid pulling in SpanScope and config API.
 */

#include <ppp/diagnostics/TelemetryFwd.h>

#include <cstdarg>

namespace ppp {
    namespace telemetry {

        struct Attribute final {
            const char* key;
            const char* value;
        };

        /**
         * @brief RAII trace span scope.
         *
         * @details When telemetry tracing is enabled, constructing this object
         *          starts a span and destroying it emits the completed span with
         *          start/end timestamps and generated trace/span identifiers.
         */
        class SpanScope final {
        public:
            SpanScope(const char* name, const char* session_id = nullptr) noexcept;
            ~SpanScope() noexcept;
            SpanScope(SpanScope&& other) noexcept;
            SpanScope& operator=(SpanScope&& other) noexcept = delete;
            SpanScope(const SpanScope&) = delete;
            SpanScope& operator=(const SpanScope&) = delete;

        private:
            const char*                                                   name_           = nullptr;
            const char*                                                   session_id_     = nullptr;
            uint64_t                                                      start_time_ns_  = 0;
            uint64_t                                                      trace_id_hi_    = 0;
            uint64_t                                                      trace_id_lo_    = 0;
            uint64_t                                                      span_id_        = 0;
            uint64_t                                                      parent_span_id_ = 0;
            bool                                                          active_         = false;
        };

        void LogWithAttributes(Level level, const char* component, const Attribute* attrs, size_t attr_count, const char* fmt, ...) noexcept;
        void TraceSpan(const char* name, const char* session_id) noexcept;
        void SetEnabled(bool enabled) noexcept;
        void SetCountEnabled(bool enabled) noexcept;
        void SetSpanEnabled(bool enabled) noexcept;
        void SetConsoleLogEnabled(bool enabled) noexcept;
        void SetConsoleMetricEnabled(bool enabled) noexcept;
        void SetConsoleSpanEnabled(bool enabled) noexcept;
        bool IsConsoleLogEnabled() noexcept;
        bool IsConsoleMetricEnabled() noexcept;
        bool IsConsoleSpanEnabled() noexcept;
        int  GetMinLevel() noexcept;
        void SetMinLevel(int level) noexcept;
        void Configure(const char* endpoint) noexcept;
        void SetLogFile(const char* path) noexcept;
        void SetResourceAttribute(const char* key, const char* value) noexcept;
        void ClearResourceAttributes() noexcept;
        void Flush(int timeout_ms = 3000) noexcept;
        void Shutdown() noexcept;

        /**
         * @brief Callback type for intercepting console telemetry output.
         *
         * When a sink is installed, all telemetry lines that would normally be
         * written to stderr are instead delivered to this callback.  The file
         * sink is still written regardless.
         *
         * @param line  Fully-formatted telemetry line (including ANSI escapes
         *              and a trailing newline when the backend is attached to
         *              a terminal).
         */
        using ConsoleSinkFn = void(*)(const char* line);

        /**
         * @brief Installs a callback that intercepts console telemetry output.
         *
         * When @p fn is non-null, all Print* methods in the backend call
         * @p fn instead of writing to stderr.  Pass nullptr to restore the
         * default stderr behavior.
         *
         * @param fn  Callback function pointer, or nullptr to disable.
         */
        void SetConsoleSink(ConsoleSinkFn fn) noexcept;

        /**
         * @brief Platform HTTP POST hook for OTLP export.
         *
         * When installed, HttpOtlpExporter delivers fully-qualified OTLP URLs
         * (including https://) to this callback instead of using raw sockets.
         * Return true when the collector accepted the payload.
         */
        using HttpPostFn = bool(*)(const char* url, const void* body, size_t body_len, void* user_data) noexcept;

        void SetHttpPostSink(HttpPostFn fn, void* user_data) noexcept;

        /**
         * @brief Returns the currently installed console sink callback.
         * @return The active sink, or nullptr when stderr is the output target.
         */
        ConsoleSinkFn GetConsoleSink() noexcept;

    }
}
