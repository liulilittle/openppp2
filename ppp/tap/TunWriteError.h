#pragma once

/**
 * @file TunWriteError.h
 * @brief Classifies errno values returned by writes to a TUN/TAP file descriptor.
 */

#include <cerrno>

namespace ppp {
    namespace tap {
        /** @brief What a failed TUN write means for the device. */
        enum class TunWriteErrorKind {
            Retry,          ///< Interrupted before any byte was written; write again.
            DropPacket,     ///< This packet cannot be delivered now; the device stays usable.
            Fatal,          ///< The descriptor or device is gone; stop using it.
        };

        /**
         * @brief Maps a write() errno to the action the caller should take.
         *
         * Only errors that describe the descriptor itself are fatal. Errors that describe
         * one packet (a malformed or oversized frame) or momentary pressure (no buffer
         * space) drop that packet, because closing the adapter for them takes the whole
         * tunnel down on input a remote peer can produce.
         */
        inline TunWriteErrorKind ClassifyTunWriteErrno(int error) noexcept {
            switch (error) {
            case EINTR:
                return TunWriteErrorKind::Retry;
            case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
            case ENOBUFS:
            case ENOMEM:
            case EINVAL:
            case EMSGSIZE:
                return TunWriteErrorKind::DropPacket;
            default:
                return TunWriteErrorKind::Fatal;
            }
        }
    }
}
