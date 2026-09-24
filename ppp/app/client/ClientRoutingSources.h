#pragma once

#include <ppp/io/File.h>

namespace ppp {
    namespace app {
        namespace client {

            enum class ClientRoutingSourceKind {
                Inline,
                File,
            };

            struct ClientRoutingSource final {
                ClientRoutingSourceKind kind = ClientRoutingSourceKind::Inline;
                ppp::string value;

                bool IsFile() const noexcept {
                    return kind == ClientRoutingSourceKind::File;
                }

                bool IsInline() const noexcept {
                    return !IsFile();
                }
            };

            namespace detail {
                inline bool HasClientRoutingFileScheme(const ppp::string& value) noexcept {
                    return value.size() >= 7 &&
                        ToLower<ppp::string>(value.substr(0, 7)) == "file://";
                }

                inline ppp::string ExistingClientRoutingFilePath(const ppp::string& value) noexcept {
                    if (value.empty()) {
                        return "";
                    }

                    ppp::string rewritten = ppp::io::File::RewritePath(value.data());
                    if (rewritten.empty()) {
                        return "";
                    }

                    ppp::string fullpath = ppp::io::File::GetFullPath(rewritten.data());
                    if (!fullpath.empty() && ppp::io::File::Exists(fullpath.data())) {
                        return fullpath;
                    }

                    if (ppp::io::File::Exists(rewritten.data())) {
                        return rewritten;
                    }

                    return "";
                }
            }

            /**
             * @brief Trims and classifies one canonical routing source.
             *
             * Existing files are returned as file sources. All other values
             * remain inline text, including missing file:// targets.
             */
            inline ClientRoutingSource ParseClientRoutingSource(const ppp::string& raw) noexcept {
                ClientRoutingSource source;
                ppp::string value = LTrim(RTrim(raw));
                if (detail::HasClientRoutingFileScheme(value)) {
                    value = LTrim(RTrim(value.substr(7)));
                }

                if (ppp::string path = detail::ExistingClientRoutingFilePath(value); !path.empty()) {
                    source.kind = ClientRoutingSourceKind::File;
                    source.value = std::move(path);
                }
                else {
                    source.value = std::move(value);
                }
                return source;
            }

            inline ppp::vector<ClientRoutingSource> ParseClientRoutingSources(
                const ppp::vector<ppp::string>& raw_sources) noexcept {
                ppp::vector<ClientRoutingSource> sources;
                sources.reserve(raw_sources.size());
                for (const ppp::string& raw : raw_sources) {
                    ClientRoutingSource source = ParseClientRoutingSource(raw);
                    if (!source.value.empty()) {
                        sources.emplace_back(std::move(source));
                    }
                }
                return sources;
            }

            /**
             * @brief Combines inline sources without materializing a file.
             */
            inline ppp::string MergeClientRoutingInlineText(
                const ppp::vector<ClientRoutingSource>& sources) noexcept {
                ppp::string text;
                for (const ClientRoutingSource& source : sources) {
                    if (!source.IsInline() || source.value.empty()) {
                        continue;
                    }
                    if (!text.empty()) {
                        text.push_back('\n');
                    }
                    text.append(source.value);
                }
                return text;
            }

            inline ppp::string MergeClientRoutingInlineText(
                const ppp::vector<ppp::string>& raw_sources) noexcept {
                return MergeClientRoutingInlineText(ParseClientRoutingSources(raw_sources));
            }

        }
    }
}
