#include <ppp/tap/TunWriteError.h>

#include <iostream>

namespace {

int failures = 0;

void Expect(int error, ppp::tap::TunWriteErrorKind expected, const char* name) {
    if (ppp::tap::ClassifyTunWriteErrno(error) != expected) {
        std::cerr << "FAIL: unexpected classification for " << name << std::endl;
        failures++;
    }
}

} // namespace

int main() {
    using ppp::tap::TunWriteErrorKind;

    Expect(EINTR, TunWriteErrorKind::Retry, "EINTR");

    // Per-packet or transient errors must not close the adapter.
    Expect(EAGAIN, TunWriteErrorKind::DropPacket, "EAGAIN");
    Expect(EWOULDBLOCK, TunWriteErrorKind::DropPacket, "EWOULDBLOCK");
    Expect(ENOBUFS, TunWriteErrorKind::DropPacket, "ENOBUFS");
    Expect(ENOMEM, TunWriteErrorKind::DropPacket, "ENOMEM");
    Expect(EINVAL, TunWriteErrorKind::DropPacket, "EINVAL");
    Expect(EMSGSIZE, TunWriteErrorKind::DropPacket, "EMSGSIZE");

    // Descriptor-level errors stay fatal.
    Expect(EBADF, TunWriteErrorKind::Fatal, "EBADF");
    Expect(EIO, TunWriteErrorKind::Fatal, "EIO");
    Expect(EPIPE, TunWriteErrorKind::Fatal, "EPIPE");
    Expect(ENODEV, TunWriteErrorKind::Fatal, "ENODEV");
    Expect(0, TunWriteErrorKind::Fatal, "0");

    if (failures != 0) {
        return 1;
    }

    std::cout << "PASS: tun_write_error_test" << std::endl;
    return 0;
}
