#include <ppp/net/asio/SharedBufferReceive.h>

#include <boost/asio.hpp>

#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void Require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

using udp = boost::asio::ip::udp;

constexpr int kDatagramsPerSocket = 64;
constexpr std::size_t kBufferSize = 65536;

std::string Payload(char tag, int index) {
    // Different lengths per socket so a stale length also shows up as a mismatch.
    std::string payload(static_cast<std::size_t>(tag == 'A' ? 300 : 900), tag);
    std::string prefix = std::string(1, tag) + "-" + std::to_string(index) + ":";
    std::memcpy(&payload[0], prefix.data(), prefix.size());
    return payload;
}

struct Receiver final : std::enable_shared_from_this<Receiver> {
    Receiver(boost::asio::io_context& context, char tag, unsigned char* buffer, bool shared_helper)
        : socket(context, udp::endpoint(boost::asio::ip::address_v4::loopback(), 0))
        , tag(tag)
        , buffer(buffer)
        , shared_helper(shared_helper) {
    }

    void Arm() {
        auto self = shared_from_this();
        auto handler = [self](const boost::system::error_code& ec, std::size_t size) noexcept {
            self->OnReceive(ec, size);
        };

        if (shared_helper) {
            ppp::net::asio::AsyncReceiveFromSharedBuffer(socket, buffer, kBufferSize, source, std::move(handler));
        }
        else {
            socket.async_receive_from(boost::asio::buffer(buffer, kBufferSize), source, std::move(handler));
        }
    }

    void OnReceive(const boost::system::error_code& ec, std::size_t size) noexcept {
        if (ec) {
            error = ec;
            return;
        }

        std::string expected = Payload(tag, received);
        if (size != expected.size() || std::memcmp(buffer, expected.data(), size) != 0) {
            mismatches++;
        }

        if (++received < kDatagramsPerSocket) {
            Arm();
        }
    }

    udp::socket socket;
    udp::endpoint source;
    char tag;
    unsigned char* buffer;
    bool shared_helper;
    int received = 0;
    int mismatches = 0;
    boost::system::error_code error;
};

// Two sockets on one io_context share one receive buffer, as datagram ports sharing
// Executors::GetCachedBuffer() do. Datagrams are queued on both sockets before the
// receives start, so every read can complete immediately.
int RunInterleaved(bool shared_helper) {
    boost::asio::io_context context;
    std::vector<unsigned char> buffer(kBufferSize);

    auto a = std::make_shared<Receiver>(context, 'A', buffer.data(), shared_helper);
    auto b = std::make_shared<Receiver>(context, 'B', buffer.data(), shared_helper);

    udp::socket sender(context, udp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
    for (int i = 0; i < kDatagramsPerSocket; i++) {
        for (const std::shared_ptr<Receiver>& receiver : { a, b }) {
            std::string payload = Payload(receiver->tag, i);
            sender.send_to(boost::asio::buffer(payload), receiver->socket.local_endpoint());
        }
    }

    a->Arm();
    b->Arm();
    context.run_for(std::chrono::seconds(10));

    Require(!a->error && !b->error, "unexpected receive error");
    Require(a->received == kDatagramsPerSocket, "socket A did not receive every datagram");
    Require(b->received == kDatagramsPerSocket, "socket B did not receive every datagram");
    return a->mismatches + b->mismatches;
}

void SharedBufferReceiveKeepsEachDatagramIntact() {
    Require(RunInterleaved(true) == 0, "shared-buffer receive delivered another socket's bytes");
}

void PlainAsyncReceiveIsReportedForReference() {
    // Not asserted: whether the race shows depends on the Asio backend. On epoll the
    // speculative read in async_receive_from reproduces it deterministically.
    std::cout << "info: plain async_receive_from mismatches with a shared buffer: "
              << RunInterleaved(false) << std::endl;
}

void CloseWhileWaitingReportsAbort() {
    boost::asio::io_context context;
    std::vector<unsigned char> buffer(kBufferSize);
    udp::socket socket(context, udp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
    udp::endpoint source;

    bool called = false;
    boost::system::error_code result;
    std::size_t transferred = 1;
    ppp::net::asio::AsyncReceiveFromSharedBuffer(socket, buffer.data(), buffer.size(), source,
        [&](const boost::system::error_code& ec, std::size_t size) noexcept {
            called = true;
            result = ec;
            transferred = size;
        });

    boost::asio::post(context, [&]() noexcept { socket.close(); });
    context.run_for(std::chrono::seconds(5));

    Require(called, "handler was not called after close");
    Require(result == boost::asio::error::operation_aborted, "close did not report operation_aborted");
    Require(transferred == 0, "aborted receive reported bytes");
}

} // namespace

int main() {
    try {
        SharedBufferReceiveKeepsEachDatagramIntact();
        PlainAsyncReceiveIsReportedForReference();
        CloseWhileWaitingReportsAbort();
    }
    catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "PASS: shared_buffer_receive_test" << std::endl;
    return 0;
}
