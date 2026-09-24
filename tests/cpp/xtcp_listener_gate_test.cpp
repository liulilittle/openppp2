#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>

namespace {
int failures = 0;

#define CHECK(condition)                                                     \
    do {                                                                     \
        if (!(condition)) {                                                  \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                         #condition);                                        \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

xtcp::core::Endpoint Endpoint(UInt32 address, UInt16 port) {
    xtcp::core::Endpoint endpoint;
    endpoint.family = 4;
    endpoint.addr[0] = address;
    endpoint.port = port;
    return endpoint;
}

void Pump(xtcp::ndi::ManualBackend& client_backend,
          xtcp::ndi::ManualBackend& server_backend,
          xtcp::XtcpStack& client,
          xtcp::XtcpStack& server) {
    Byte packet[65536];
    while (0 != client_backend.TxPending()) {
        const UInt32 length = client_backend.PollTx(packet);
        if (0 != length) {
            server_backend.Inject(packet, length, 0x0800);
        }
    }
    while (0 != server_backend.TxPending()) {
        const UInt32 length = server_backend.PollTx(packet);
        if (0 != length) {
            client_backend.Inject(packet, length, 0x0800);
        }
    }
    client.PollAckTimers();
    server.PollAckTimers();
}

void TestListenStopListenGate() {
    xtcp::ndi::ManualBackend backend;
    xtcp::XtcpStack stack(&backend);
    const xtcp::core::Endpoint listener = Endpoint(0x0A000002, 9443);

    CHECK(stack.Listen(listener));
    CHECK(!stack.Listen(listener));
    CHECK(stack.StopListen(listener));
    CHECK(!stack.StopListen(listener));
    CHECK(stack.Listen(listener));
    CHECK(stack.StopListen(listener));
}

void TestAcceptRejectGate() {
    xtcp::ndi::ManualBackend client_backend;
    xtcp::ndi::ManualBackend server_backend;
    xtcp::XtcpStack client(&client_backend);
    xtcp::XtcpStack server(&server_backend);
    const xtcp::core::Endpoint listener = Endpoint(0x0A000012, 9554);
    const xtcp::core::Endpoint local = Endpoint(0x0A000011, 40001);
    UInt32 rejected = 0;

    CHECK(server.Listen(listener));
    server.SetAcceptHandler([&rejected](UInt64,
                                        const xtcp::core::Endpoint&,
                                        const xtcp::core::Endpoint&) {
        ++rejected;
        return false;
    });

    const UInt64 connection = client.Connect(local, listener);
    CHECK(0 != connection);
    for (UInt32 i = 0; i < 100 && 0 == rejected; ++i) {
        Pump(client_backend, server_backend, client, server);
    }

    CHECK(1 == rejected);
    CHECK(0 == server.ConnectionCount());
    CHECK(xtcp::core::TcpState::kClosed == client.ConnectionState(connection));
}

void TestAcceptGate() {
    xtcp::ndi::ManualBackend client_backend;
    xtcp::ndi::ManualBackend server_backend;
    xtcp::XtcpStack client(&client_backend);
    xtcp::XtcpStack server(&server_backend);
    const xtcp::core::Endpoint listener = Endpoint(0x0A000022, 9665);
    const xtcp::core::Endpoint local = Endpoint(0x0A000021, 40002);
    UInt64 accepted_connection = 0;

    CHECK(server.Listen(listener));
    server.SetAcceptHandler([&accepted_connection](
                                UInt64 connection,
                                const xtcp::core::Endpoint&,
                                const xtcp::core::Endpoint&) {
        accepted_connection = connection;
        return true;
    });

    const UInt64 client_connection = client.Connect(local, listener);
    CHECK(0 != client_connection);
    for (UInt32 i = 0; i < 200; ++i) {
        if (0 != accepted_connection &&
            xtcp::core::TcpState::kEstablished ==
                client.ConnectionState(client_connection) &&
            xtcp::core::TcpState::kEstablished ==
                server.ConnectionState(accepted_connection)) {
            break;
        }
        Pump(client_backend, server_backend, client, server);
    }

    CHECK(0 != accepted_connection);
    CHECK(xtcp::core::TcpState::kEstablished ==
          client.ConnectionState(client_connection));
    CHECK(xtcp::core::TcpState::kEstablished ==
          server.ConnectionState(accepted_connection));
    CHECK(1 == client.ConnectionCount());
    CHECK(1 == server.ConnectionCount());
}
}  // namespace

int main() {
    xtcp::buf::InitPools();
    TestListenStopListenGate();
    TestAcceptRejectGate();
    TestAcceptGate();
    xtcp::buf::ShutdownPools();

    if (0 != failures) {
        std::fprintf(stderr, "xtcp_listener_gate_test: %d failure(s)\n", failures);
        return 1;
    }
    std::puts("xtcp_listener_gate_test: passed");
    return 0;
}
