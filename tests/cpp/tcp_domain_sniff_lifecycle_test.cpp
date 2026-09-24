#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace {
    std::string ReadAll(const std::string& path) {
        std::ifstream stream(path);
        std::ostringstream contents;
        contents << stream.rdbuf();
        return contents.str();
    }

    void Require(bool condition, const char* message) {
        if (!condition) {
            std::cerr << message << std::endl;
            std::exit(1);
        }
    }

    std::string FunctionBody(const std::string& source, const std::string& signature) {
        const std::size_t begin = source.find(signature);
        Require(begin != std::string::npos, "required function is missing");
        const std::size_t next = source.find("\n            /**", begin + signature.size());
        return source.substr(begin, next == std::string::npos ? next : next - begin);
    }
}

int main(int argc, char* argv[]) {
    const std::string root = argc > 1 ? argv[1] : ".";
    const std::string stack = ReadAll(
        root + "/ppp/app/client/VEthernetNetworkTcpipStack.cpp");
    const std::string connection = ReadAll(
        root + "/ppp/app/client/VEthernetNetworkTcpipConnection.cpp");
    const std::string rules = ReadAll(
        root + "/ppp/app/client/routing/HumanRoutingRules.h");

    const std::size_t ios_guard = stack.find(
        "#if !defined(_IPHONE) && !defined(IPHONE)");
    const std::size_t enabled = stack.find(
        "configuration_->routing.tcp_domain_sniff", ios_guard);
    const std::size_t ipv4 = stack.find("remoteEP.address().is_v4()", enabled);
    const std::size_t real = stack.find("!destination.is_fake_ip", ipv4);
    const std::size_t snapshot = stack.find(
        "GetHumanRoutingRulesSnapshot()", real);
    const std::size_t has_rules = stack.find("HasDomainRules()", snapshot);
    const std::size_t ios_end = stack.find("#endif", has_rules);
    Require(ios_guard != std::string::npos && enabled != std::string::npos &&
        ipv4 != std::string::npos && real != std::string::npos &&
        snapshot != std::string::npos && has_rules != std::string::npos &&
        ios_end != std::string::npos,
        "candidate gate must require enabled, real IPv4, non-fake, domain rules, and exclude iOS");
    Require(enabled < ipv4 && ipv4 < real && real < snapshot && snapshot < has_rules,
        "disabled/fake/non-IPv4 paths must short-circuit before taking a rules snapshot");
    Require(rules.find("bool HasDomainRules() const noexcept") != std::string::npos,
        "domain-rule presence helper is missing");

    const std::string sniff = FunctionBody(connection,
        "bool VEthernetNetworkTcpipConnection::SniffDomainRouting(");
    Require(sniff.find("kSniffTimeoutMilliseconds = 250") != std::string::npos,
        "sniff timeout must remain 250ms");
    Require(sniff.find("ProtocolSniffer::MaxInputSize") != std::string::npos,
        "sniff buffer must use the parser's 16KiB limit");
    Require(sniff.find("socket_base::message_peek") != std::string::npos,
        "sniff receive must be non-consuming");
    Require(sniff.find("socket->non_blocking(true, ec)") != std::string::npos &&
        sniff.find("socket->non_blocking(was_non_blocking, restore_ec)") != std::string::npos,
        "sniff must temporarily enable and then restore non-blocking mode");
    Require(sniff.find("peeked == peek_buffer.size()") != std::string::npos &&
        sniff.find("ProtocolSnifferStatus::LimitExceeded") != std::string::npos,
        "an undecided full peek buffer must fail as limit-exceeded without polling to timeout");
    Require(sniff.find("return !restore_ec && !IsDisposed();") != std::string::npos,
        "failure to restore socket blocking mode must fail closed");
    Require(sniff.find("peek_buffer.data() + fed_size, peeked - fed_size") !=
            std::string::npos,
        "incremental parser must receive only newly peeked bytes");
    Require(sniff.find("outcome = \"unsupported\"") != std::string::npos &&
        sniff.find("outcome = \"timeout\"") != std::string::npos &&
        sniff.find("outcome = \"no_match\"") != std::string::npos,
        "unsupported, timeout, and no-match outcomes must preserve IP fallback");
    Require(sniff.find("if (match.matched)") != std::string::npos &&
        sniff.find("routing::TcpRoutingSelector::Select(selector_input)") !=
            std::string::npos &&
        sniff.find("routing_mode_ = selected_mode") != std::string::npos,
        "an explicit domain match must refine the per-flow fallback mode");
    Require(sniff.find("result.domain") != std::string::npos &&
        sniff.find("source=%s outcome=%s action=%s") != std::string::npos,
        "sniff telemetry contract is missing");
    Require(sniff.find("domain=%") == std::string::npos &&
        sniff.find("payload=%") == std::string::npos,
        "sniff telemetry must not log domain or payload");

    const std::string begin_accept = FunctionBody(connection,
        "bool VEthernetNetworkTcpipConnection::BeginAccept() noexcept");
    const std::size_t candidate = begin_accept.find("if (domain_sniff_candidate_)");
    const std::size_t candidate_ack = begin_accept.find("return AckAccept();", candidate);
    const std::size_t legacy_connect = begin_accept.find("ConnectToPeer(y)", candidate_ack);
    const std::size_t legacy_ack = begin_accept.find("AckAccept()", legacy_connect);
    Require(candidate != std::string::npos && candidate_ack != std::string::npos,
        "sniff candidates must acknowledge before an accepted socket exists");
    Require(legacy_connect != std::string::npos && legacy_ack != std::string::npos &&
        legacy_connect < legacy_ack,
        "non-candidate path must connect before acknowledging exactly as before");

    const std::string establish = FunctionBody(connection,
        "bool VEthernetNetworkTcpipConnection::Establish() noexcept");
    const std::size_t sniff_first = establish.find("SniffDomainRouting(y)");
    const std::size_t connect_second = establish.find("ConnectToPeer(y)", sniff_first);
    const std::size_t forward_last = establish.find("Loopback(y)", connect_second);
    Require(sniff_first != std::string::npos && connect_second != std::string::npos &&
        forward_last != std::string::npos && sniff_first < connect_second &&
        connect_second < forward_last,
        "candidate lifecycle must sniff, then connect, then forward");
    Require(connection.find("return TapTcpClient::EndAccept(socket, natEP);") !=
            std::string::npos,
        "accepted socket must still pass through the base EndAccept lifecycle");

    return 0;
}
