#pragma once

/**
 * @file P2PDefs.h
 * @brief P2P networking constants, enumerations, and magic values.
 *
 * Defines the wire-protocol magic number, flag bit layout, channel
 * states, default timer values, and buffer pool sizing used across
 * all P2P subsystems.
 *
 * @license GPL-3.0
 */

#include <ppp/stdafx.h>
#include <ppp/Int128.h>

namespace ppp {
    namespace p2p {
        /** @brief Wire magic bytes: ASCII "P2P1" = 0x50325031. */
        static constexpr uint32_t   P2P_MAGIC                   = 0x50325031u;

        /**
         * @brief Tier 1 (control) header size in bytes (before auth tag).
         *
         * Wire layout:
         *   [0]     Flags (1B)
         *   [1..3]  Magic (3B, 0x503250 — first 3 bytes of P2P_MAGIC)
         *   [4..19] Session ID (16B)
         *   [20..27] Nonce (8B, big-endian)
         *   [28..31] Sequence (4B, big-endian)
         *   [32..47] Token (16B)
         * Total = 1 + 3 + 16 + 8 + 4 + 16 = 48 bytes.
         */
        static constexpr int        TIER1_HEADER_SIZE           = 48;
        /** @brief Tier 2 (data) header size in bytes (before auth tag). */
        static constexpr int        TIER2_HEADER_SIZE           = 16;
        /** @brief Auth tag size in bytes (Poly1305 or GCM tag). */
        static constexpr int        AUTH_TAG_SIZE               = 16;
        /** @brief Maximum coalesced Ethernet frame count per UDP datagram. */
        static constexpr int        MAX_COALESCED_FRAMES        = 16;
        /** @brief Maximum Ethernet frame size (standard MTU + headers). */
        static constexpr int        MAX_ETHERNET_FRAME_SIZE     = 1514;
        /** @brief Maximum P2P packet size (header + payload + tag). */
        static constexpr int        P2P_MAX_PACKET_SIZE         = 2048;
        /** @brief Standard P2P buffer size. */
        static constexpr int        P2P_BUFFER_SIZE             = 2048;
        /** @brief Default buffer pool count per channel. */
        static constexpr int        DEFAULT_BUFFER_POOL_COUNT   = 64;
        /** @brief Session ID size (16 bytes = UUID). */
        static constexpr int        SESSION_ID_SIZE             = 16;
        /** @brief Token size (HMAC-SHA256 truncated to 16 bytes). */
        static constexpr int        TOKEN_SIZE                  = 16;
        /** @brief Nonce size (8 bytes). */
        static constexpr int        NONCE_SIZE                  = 8;
        /** @brief Session key size (256 bits). */
        static constexpr int        SESSION_KEY_SIZE            = 32;
        /** @brief Replay window bitmap size in bytes (1024 bits). */
        static constexpr int        REPLAY_BITMAP_SIZE          = 128;
        /** @brief Replay window covers this many sequence numbers. */
        static constexpr int        REPLAY_WINDOW_SIZE          = REPLAY_BITMAP_SIZE * 8;
        /** @brief Socket protector firmware mark for Linux SO_MARK. */
        static constexpr uint32_t   SOCKET_MARK_P2P             = 0x5032u;
        /** @brief Cached session/channel reconnect TTL in seconds. */
        static constexpr int        ZERO_RTT_CACHE_TTL_SECONDS  = 300;
        /** @brief Hot socket pool size per peer. */
        static constexpr int        HOT_SOCKET_POOL_SIZE        = 2;
        /** @brief Maximum offer token size in bytes. */
        static constexpr int        MAX_OFFER_TOKEN_SIZE        = 256;

        /**
         * @brief Flag bit positions in the 1-byte flags field.
         */
        enum P2PFlags : uint8_t {
            P2P_FLAG_HEARTBEAT_REQ  = 1u << 0,  ///< Request heartbeat acknowledgment.
            P2P_FLAG_HEARTBEAT_ACK  = 1u << 1,  ///< Acknowledge heartbeat.
            P2P_FLAG_TIER           = 1u << 2,  ///< 0 = Tier 2 minimal, 1 = Tier 1 full control.
            P2P_FLAG_COALESCED      = 1u << 3,  ///< Payload contains multiple length-prefixed frames.
            P2P_FLAG_PROBE_REQ      = 1u << 4,  ///< Tier-1 probe request.
            P2P_FLAG_PROBE_ACK      = 1u << 5,  ///< Tier-1 probe acknowledgment.
        };

        /**
         * @brief P2P channel lifecycle states.
         *
         * Transitions:
         *   Relay -> Probing -> Direct -> Suspect -> Relay
         */
        enum class P2PChannelState : uint8_t {
            Relay       = 0,    ///< Using server relay (default/fallback).
            Probing     = 1,    ///< Sending probes to candidates.
            Direct      = 2,    ///< Direct path established.
            Suspect     = 3,    ///< Heartbeat missed; probing to verify.
        };

        inline constexpr bool CanProcessAuthenticatedP2PTier2(
                P2PChannelState state) noexcept {
            return state == P2PChannelState::Direct ||
                   state == P2PChannelState::Suspect;
        }

        inline constexpr bool CanForwardP2PPayload(
                P2PChannelState state) noexcept {
            return state == P2PChannelState::Direct;
        }

        /**
         * @brief Platform-adaptive cipher algorithm selection.
         */
        enum class P2PCipher : uint8_t {
            ChaCha20Poly1305    = 0,    ///< Default on ARM/mobile; safe fallback.
            AES256GCM           = 1,    ///< Preferred on x86 with AES-NI.
        };

        /**
         * @brief NAT type classification inferred from relay traffic patterns.
         */
        enum class P2PNatType : uint8_t {
            Unknown         = 0,    ///< Not yet classified.
            FullCone        = 1,    ///< Consistent external IP:port.
            RestrictedCone  = 2,    ///< IP consistent, port varies by destination IP.
            PortRestricted  = 3,    ///< IP consistent, port varies by dest IP:port.
            Symmetric       = 4,    ///< External IP:port changes per destination.
            UdpBlocked      = 5,    ///< No UDP relay traffic observed.
        };

        /**
         * @brief P2P configuration defaults.
         */
        struct P2PConfig {
            int     max_probes          = 2;        ///< Max probe rounds before fallback.
            int     probe_timeout_ms    = 2000;     ///< Per-round probe timeout (ms).
            int     heartbeat_interval_ms = 1000;   ///< Heartbeat send interval (ms).
            int     heartbeat_miss_max  = 2;        ///< Missed heartbeats before Suspect.
            int     suspect_timeout_ms  = 2000;     ///< Suspect recovery timeout (ms).
            int     migration_grace_ms  = 5000;     ///< NAT rebind grace period (ms).
            int     buffer_pool_count   = DEFAULT_BUFFER_POOL_COUNT;
            P2PCipher preferred_cipher  = P2PCipher::ChaCha20Poly1305;
        };

        /**
         * @brief Checks whether the TIER flag indicates a Tier 1 control header.
         */
        inline bool IsTier1(uint8_t flags) noexcept {
            return (flags & P2P_FLAG_TIER) != 0;
        }

        /**
         * @brief Checks whether the COALESCED flag is set.
         */
        inline bool IsCoalesced(uint8_t flags) noexcept {
            return (flags & P2P_FLAG_COALESCED) != 0;
        }

        /**
         * @brief Checks whether the HEARTBEAT_REQ flag is set.
         */
        inline bool IsHeartbeatReq(uint8_t flags) noexcept {
            return (flags & P2P_FLAG_HEARTBEAT_REQ) != 0;
        }

        /**
         * @brief Checks whether the HEARTBEAT_ACK flag is set.
         */
        inline bool IsHeartbeatAck(uint8_t flags) noexcept {
            return (flags & P2P_FLAG_HEARTBEAT_ACK) != 0;
        }

        /**
         * @brief Checks whether the PROBE_REQ flag is set.
         */
        inline bool IsProbeReq(uint8_t flags) noexcept {
            return (flags & P2P_FLAG_PROBE_REQ) != 0;
        }

        /**
         * @brief Checks whether the PROBE_ACK flag is set.
         */
        inline bool IsProbeAck(uint8_t flags) noexcept {
            return (flags & P2P_FLAG_PROBE_ACK) != 0;
        }

        /**
         * @brief Serializes a uint64 nonce to big-endian 8-byte representation.
         *
         * @param[in]  nonce  Host-byte-order nonce value.
         * @param[out] out    8-byte output buffer.
         */
        inline void NonceToBytes(uint64_t nonce, uint8_t out[NONCE_SIZE]) noexcept {
            for (int i = 0; i < NONCE_SIZE; ++i) {
                out[i] = static_cast<uint8_t>((nonce >> ((7 - i) * 8)) & 0xFF);
            }
        }

        /**
         * @brief Deserializes a big-endian 8-byte nonce to uint64.
         *
         * @param[in] buf 8-byte big-endian nonce.
         * @return Host-byte-order nonce value.
         */
        inline uint64_t BytesToNonce(const uint8_t buf[NONCE_SIZE]) noexcept {
            uint64_t n = 0;
            for (int i = 0; i < NONCE_SIZE; ++i) {
                n = (n << 8) | buf[i];
            }
            return n;
        }

        /**
         * @brief Serializes an Int128 to a 16-byte big-endian buffer.
         */
        inline void Int128ToBytes(const Int128& id, uint8_t out[SESSION_ID_SIZE]) noexcept {
            // Int128 is stored as two uint64 values. Serialize in big-endian.
            uint64_t hi = static_cast<uint64_t>(id >> 64);
            uint64_t lo = static_cast<uint64_t>(id);
            for (int i = 0; i < 8; ++i) {
                out[i] = static_cast<uint8_t>((hi >> ((7 - i) * 8)) & 0xFF);
            }
            for (int i = 0; i < 8; ++i) {
                out[8 + i] = static_cast<uint8_t>((lo >> ((7 - i) * 8)) & 0xFF);
            }
        }

        /**
         * @brief Compares two 16-byte session IDs in constant time.
         *
         * @return true if equal.
         */
        inline bool SessionIdEqual(const uint8_t a[SESSION_ID_SIZE],
                                   const uint8_t b[SESSION_ID_SIZE]) noexcept {
            uint8_t diff = 0;
            for (int i = 0; i < SESSION_ID_SIZE; ++i) {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }
    }
}
