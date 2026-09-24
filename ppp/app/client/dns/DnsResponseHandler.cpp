#include "DnsResponseHandler.h"

#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/net/packet/IPFrame.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                void DnsResponseHandler::HandleWithPorts(
                    const DnsResponseHandlerPorts& ports,
                    const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                    const boost::asio::ip::udp::endpoint& sourceEP,
                    const boost::asio::ip::udp::endpoint& destEP,
                    ppp::vector<Byte> response) noexcept {

                    try {
                        if (!response.empty()) {
                            try {
                                if (ports.enable_dns_cache && ports.write_cache) {
                                    ports.write_cache(
                                        response.data(),
                                        static_cast<int>(response.size()));
                                }
                            }
                            catch (...) { /* cache failure is non-fatal */ }

                            if (static_cast<bool>(ports.datagram_output)) {
                                bool injected = ports.datagram_output(
                                    sourceEP, destEP,
                                    nullptr,
                                    response.data(),
                                    static_cast<int>(response.size()),
                                    false);
                                if (injected) {
                                    ppp::telemetry::Count("dns.redirect.success", 1);
                                    return;
                                }

                                ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "dns",
                                    "redirect inject failed; tunnel fallback dst=%s:%d bytes=%d",
                                    destEP.address().to_string().data(),
                                    (int)destEP.port(),
                                    (int)response.size());
                            }
                        }

                        if (static_cast<bool>(ports.tunnel_send) && NULLPTR != messages &&
                            NULLPTR != messages->Buffer.get() && messages->Length > 0) {
                            ppp::telemetry::Count("dns.redirect.fallback", 1);
                            ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "dns",
                                "tunnel fallback dst=%s:%d bytes=%d",
                                destEP.address().to_string().data(),
                                (int)destEP.port(),
                                (int)messages->Length);
                            ports.tunnel_send(sourceEP, destEP,
                                messages->Buffer.get(), messages->Length);
                        }
                        else {
                            ppp::telemetry::Count("dns.redirect.dropped", 1);
                        }
                    }
                    catch (const std::exception&) {
                        ppp::telemetry::Count("dns.redirect.exception", 1);
                    }
                    catch (...) {
                        ppp::telemetry::Count("dns.redirect.exception", 1);
                    }
                }

            }
        }
    }
}
