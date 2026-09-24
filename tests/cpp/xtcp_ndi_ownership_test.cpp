#include <xtcp/ndi.h>

#include <array>
#include <cstdio>
#include <utility>

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

class OwnershipBackend final : public xtcp::ndi::Backend {
public:
    explicit OwnershipBackend(UInt32 accept_limit) noexcept
        : accept_limit_(accept_limit) {}

    bool Tx(xtcp::ndi::Packet&& packet) noexcept override {
        ++attempts_;
        if (accepted_count_ >= accept_limit_) {
            return false;
        }
        accepted_[accepted_count_] = std::move(packet.owned);
        ++accepted_count_;
        return true;
    }

    void SetRxHandler(xtcp::ndi::RxHandler handler) noexcept override {
        rx_handler_ = std::move(handler);
    }

    xtcp::ndi::BackendCaps Caps() const noexcept override {
        return xtcp::ndi::kCapNone;
    }

    UInt32 AcceptedCount() const noexcept { return accepted_count_; }
    UInt32 Attempts() const noexcept { return attempts_; }
    const xtcp::buf::BufRef& Accepted(UInt32 index) const noexcept {
        return accepted_[index];
    }

private:
    UInt32 accept_limit_ = 0;
    UInt32 accepted_count_ = 0;
    UInt32 attempts_ = 0;
    std::array<xtcp::buf::BufRef, 8> accepted_;
    xtcp::ndi::RxHandler rx_handler_;
};

xtcp::ndi::Packet MakePacket(Byte marker) {
    xtcp::ndi::Packet packet;
    packet.owned = xtcp::buf::BufRef::Acquire(64);
    CHECK(!packet.owned.IsEmpty());
    if (packet.owned.IsEmpty()) {
        return packet;
    }
    packet.owned.Data()[0] = marker;
    packet.owned.SetLen(1);
    packet.data = packet.owned.Data();
    packet.len = packet.owned.Len();
    packet.eth_type = 0x0800;
    return packet;
}

void TestRejectedTxRetainsOwnership() {
    OwnershipBackend backend(0);
    xtcp::ndi::Packet packet = MakePacket(0x11);
    Byte* original = packet.owned.Data();

    CHECK(!backend.Tx(std::move(packet)));
    CHECK(1 == backend.Attempts());
    CHECK(0 == backend.AcceptedCount());
    CHECK(!packet.owned.IsEmpty());
    CHECK(original == packet.owned.Data());
    CHECK(0x11 == packet.owned.Data()[0]);
}

void TestAcceptedTxConsumesOwnership() {
    OwnershipBackend backend(1);
    xtcp::ndi::Packet packet = MakePacket(0x22);

    CHECK(backend.Tx(std::move(packet)));
    CHECK(packet.owned.IsEmpty());
    CHECK(1 == backend.AcceptedCount());
    CHECK(!backend.Accepted(0).IsEmpty());
    CHECK(0x22 == backend.Accepted(0).Data()[0]);
}

void TestBatchConsumesAcceptedPrefixOnly() {
    OwnershipBackend backend(2);
    std::array<xtcp::ndi::Packet, 4> packets = {
        MakePacket(0x30), MakePacket(0x31), MakePacket(0x32), MakePacket(0x33)};

    const UInt32 accepted = backend.TxBatch(packets.data(), packets.size());
    CHECK(2 == accepted);
    CHECK(3 == backend.Attempts());
    CHECK(packets[0].owned.IsEmpty());
    CHECK(packets[1].owned.IsEmpty());
    CHECK(!packets[2].owned.IsEmpty());
    CHECK(!packets[3].owned.IsEmpty());
    CHECK(0x30 == backend.Accepted(0).Data()[0]);
    CHECK(0x31 == backend.Accepted(1).Data()[0]);
    CHECK(0x32 == packets[2].owned.Data()[0]);
    CHECK(0x33 == packets[3].owned.Data()[0]);
}
}  // namespace

int main() {
    xtcp::buf::InitPools();
    TestRejectedTxRetainsOwnership();
    TestAcceptedTxConsumesOwnership();
    TestBatchConsumesAcceptedPrefixOnly();
    xtcp::buf::ShutdownPools();

    if (0 != failures) {
        std::fprintf(stderr, "xtcp_ndi_ownership_test: %d failure(s)\n", failures);
        return 1;
    }
    std::puts("xtcp_ndi_ownership_test: passed");
    return 0;
}
