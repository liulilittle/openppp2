#include <ppp/transmissions/ITransmission.h>
#include <ppp/transmissions/NoisePskAuthenticatedCarrierBinding.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/diagnostics/DatapathPerfJson.h>

/**
 * @file ITransmission.cpp
 * @brief Implements encrypted packet framing, handshake, and transmission I/O helpers.
 */

// Cryptographic and I/O utilities.
#include <ppp/cryptography/ssea.h>
#include <ppp/io/Stream.h>
#include <ppp/io/MemoryStream.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/checksum.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/threading/Thread.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <chrono>

namespace ppp {
    namespace transmissions {

        using ppp::telemetry::Level;

        // -----------------------------------------------------------------------------
        // Local type aliases for code brevity.
        // -----------------------------------------------------------------------------
        typedef ITransmission::AppConfigurationPtr AppConfigurationPtr;
        typedef ITransmission::CiphertextPtr CiphertextPtr;
        typedef ppp::net::Socket Socket;
        typedef ppp::threading::Thread Thread;
        typedef ppp::cryptography::ssea ssea;
        typedef ppp::io::Stream Stream;
        typedef ppp::io::MemoryStream MemoryStream;
        typedef ITransmission::YieldContext YieldContext;
        typedef ppp::threading::BufferswapAllocator BufferswapAllocator;

        // -----------------------------------------------------------------------------
        // Header size constants used in packet obfuscation.
        // -----------------------------------------------------------------------------
        static constexpr int EVP_HEADER_TSS = 2;                  // Encrypted length field size (2 bytes)
        static constexpr int EVP_HEADER_MSS = EVP_HEADER_TSS + 1; // 3 bytes: total header after first key byte
        static constexpr int EVP_HEADER_XSS = EVP_HEADER_MSS + 1; // 4 bytes: simple header (random key + filler + swapped length)

        // Maximum base94-encoded frame payload size.
        //
        // ssea::base94_encode() encodes input byte-by-byte: a byte whose (value - kf)
        // is >= 93 expands to 2 output characters, otherwise 1.  In the worst case every
        // byte expands, so the encoded size is up to 2x the binary input.  A binary
        // payload bounded by PPP_BUFFER_SIZE can therefore produce up to 2*PPP_BUFFER_SIZE
        // encoded bytes.  The receive-side frame-length check must allow this full
        // expansion; the decoded output is still bounded by PPP_BUFFER_SIZE in the
        // binary decrypt path.  (NOTE: this is NOT 11/9 — that ratio belongs to the
        // unrelated block-based BASE94_INPUT/OUTPUT_BLOCK_SIZE codec, not this byte codec.)
        static constexpr int EVP_BASE94_MAX_FRAME = (PPP_BUFFER_SIZE * 2) + 64;

        // Forward declaration of the full packet read helper (used by ReadBinary).
        static std::shared_ptr<Byte> Transmission_Packet_Read(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            const CiphertextPtr&                        EVP_protocol,
            const CiphertextPtr&                        EVP_transport,
            int&                                        outlen,
            ITransmission*                              transmission,
            YieldContext&                               y,
            bool                                        safest) noexcept;

        // -----------------------------------------------------------------------------
        // ITransmissionBridge – encapsulates all low‑level I/O and encryption logic.
        // -----------------------------------------------------------------------------
        /**
         * @brief Internal bridge for unified read/write, encoding, and decoding workflows.
         */
        class ITransmissionBridge final {
        public:
            /**
             * @brief Reads raw bytes from the transport implementation.
             * @param transmission Active transmission instance.
             * @param y Coroutine yield context.
             * @param length Number of bytes to read.
             * @return Raw bytes on success; null on failure.
             */
            static std::shared_ptr<Byte> ReadBytes(ITransmission* transmission, YieldContext& y, int length) noexcept {
                return transmission->DoReadBytes(y, length);
            }

            /**
             * @brief Reads a binary packet and decrypts it when ciphers are configured.
             * @param transmission Active transmission instance.
             * @param y Coroutine yield context.
             * @param outlen Output plaintext length.
             * @return Decrypted payload on success; null on failure.
             */
            static std::shared_ptr<Byte> ReadBinary(ITransmission* transmission, YieldContext& y, int& outlen) noexcept {
                bool safest = !transmission->handshaked_.load(std::memory_order_acquire);
                CiphertextPtr EVP_protocol = std::atomic_load(&transmission->protocol_);
                CiphertextPtr EVP_transport = std::atomic_load(&transmission->transport_);
                AppConfigurationPtr configuration = transmission->configuration_;
                const auto& allocator = transmission->BufferAllocator;

                if (EVP_protocol && EVP_transport) {
                    return Transmission_Packet_Read(configuration, allocator,
                        EVP_protocol, EVP_transport, outlen,
                        transmission, y, safest);
                }
                else {
                    return Transmission_Packet_Read(configuration, allocator,
                        NULLPTR, NULLPTR, outlen,
                        transmission, y, safest);
                }
            }

            /**
             * @brief Encrypts binary payload using packet-level framing.
             */
            static std::shared_ptr<Byte> EncryptBinary(ITransmission* transmission, Byte* data, int datalen, int& outlen) noexcept;

            /**
             * @brief Decrypts binary payload produced by packet-level framing.
             */
            static std::shared_ptr<Byte> DecryptBinary(ITransmission* transmission, Byte* data, int datalen, int& outlen) noexcept;

            /**
             * @brief Encrypts payload and conditionally applies base94 envelope.
             */
            static std::shared_ptr<Byte> Encrypt(ITransmission* transmission, Byte* data, int datalen, int& outlen) noexcept {
                std::shared_ptr<Byte> packet = EncryptBinary(transmission, data, datalen, outlen);
                if (NULLPTR != packet) {
                    AppConfigurationPtr& cfg = transmission->configuration_;
                    // Base94 needed before handshake or when plaintext mode is forced.
                    if (!transmission->handshaked_.load(std::memory_order_acquire) || cfg->key.plaintext) {
                        packet = base94_encode(transmission, cfg, transmission->BufferAllocator,
                            packet.get(), outlen, cfg->key.kf, outlen);
                    }
                }

                if (NULLPTR != packet) {
                    return packet;
                }
                else {
                    outlen = 0;
                    return packet;   // NULLPTR
                }
            }

            /**
             * @brief Decodes optional base94 envelope and decrypts payload.
             */
            static std::shared_ptr<Byte> Decrypt(ITransmission* transmission, Byte* data, int datalen, int& outlen) noexcept {
                std::shared_ptr<Byte> packet;
                AppConfigurationPtr& cfg = transmission->configuration_;
                if (!transmission->handshaked_.load(std::memory_order_acquire) || cfg->key.plaintext) {
                    // Base94 decode first, then binary decrypt.
                    packet = base94_decode(cfg, transmission->BufferAllocator,
                        data, datalen, cfg->key.kf, outlen);

                    // Guard: if base94 decoding failed, do not pass null to DecryptBinary.
                    if (NULLPTR == packet || outlen < 1) {
                        return ppp::diagnostics::SetLastError(
                            ppp::diagnostics::ErrorCode::ProtocolDecodeFailed, packet);
                    }

                    packet = DecryptBinary(transmission, packet.get(), outlen, outlen);
                }
                else {
                    // Direct binary decryption (post‑handshake).
                    packet = DecryptBinary(transmission, data, datalen, outlen);
                }

                if (NULLPTR != packet) {
                    return packet;
                }
                else {
                    outlen = 0;
                    return packet;
                }
            }

            /**
             * @brief Reads one message using pre/post-handshake decode strategy.
             */
            static std::shared_ptr<Byte> Read(ITransmission* transmission, YieldContext& y, int& outlen) noexcept {
                outlen = 0;
                const bool handshaked = transmission->handshaked_.load(std::memory_order_acquire);
                if (transmission->disposed_.load(std::memory_order_acquire)) {
                    return NULLPTR;
                }

                std::shared_ptr<Byte> packet;
                AppConfigurationPtr& cfg = transmission->configuration_;
                if (!handshaked || cfg->key.plaintext) {
                    packet = base94_decode(transmission, y, outlen);
                    if (NULLPTR == packet || outlen < 1) {
                        outlen = 0;
                        return NULLPTR;
                    }
                    packet = DecryptBinary(transmission, packet.get(), outlen, outlen);
                }
                else {
                    packet = ReadBinary(transmission, y, outlen);
                }

                if (NULLPTR != packet) {
                    return packet;
                }
                else {
                    outlen = 0;
                    return NULLPTR;
                }
            }

            // -------------------------------------------------------------------------
            // Write overloads – coroutine‑aware and callback‑based.
            // Optimization restrictions work around compiler bugs (must stay ≤ O1).
            // -------------------------------------------------------------------------
#if defined(_WIN32)
#pragma optimize("", off)
#pragma optimize("gsyb2", on) /* Enable optimizations similar to /O1 on Windows */
// Windows-specific optimization pragmas to work around known compiler bugs with coroutine state in the Write function.
#else
// TRANSMISSIONO1 macro controls optimization; for GCC < 7.5, force O1 to avoid bugs; otherwise O0
#if defined(__clang__)
#pragma clang optimize off
#else
#pragma GCC push_options
#if defined(TRANSMISSION_O1) || (__GNUC__ < 7) || (__GNUC__ == 7 && __GNUC_MINOR__ <= 5)
#pragma GCC optimize("O1")
#else
#pragma GCC optimize("O0")
#endif
#endif
#endif
            static bool Write(ITransmission* transmission, YieldContext& y, const void* packet, int packet_length) noexcept {
                using AsynchronousWriteCallback = ITransmission::AsynchronousWriteCallback;
                if (transmission->disposed_.load(std::memory_order_acquire)) {
                    return false;
                }

                YieldContext* co = y.GetPtr();
                if (NULLPTR != co) {
                    // Inside a coroutine: use the yielding version.
                    bool ok = transmission->DoWriteYield<AsynchronousWriteCallback>(
                        *co, packet, packet_length,
                        [transmission](const void* p, int len, const AsynchronousWriteCallback& cb) noexcept {
                            return ITransmissionBridge::Write(transmission, p, len, cb);
                        });
                    if (!ok && !transmission->disposed_.load(std::memory_order_acquire)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelWriteFailed);
                    }

                    return ok;
                }
                else {
                    // Not in a coroutine: direct callback‑based write.
                    /* The completion callback may fire while the transmission is
                     * being destroyed (the write queue base class fails pending
                     * writes during its destructor). Capturing the raw pointer then
                     * calling Dispose() would hit shared_from_this() with a zero
                     * strong count -> bad_weak_ptr -> std::terminate. Capture a
                     * shared reference so the object survives until the callback
                     * runs, mirroring the vmux self_weak_ fix pattern. */
                    std::shared_ptr<ITransmission> self =
                        std::static_pointer_cast<ITransmission>(transmission->shared_from_this());
                    bool ok = ITransmissionBridge::Write(transmission, packet, packet_length,
                        [self](bool ok) noexcept {
                            if (!ok) {
                                self->Dispose();
                            }
                        });
                    if (!ok && !transmission->disposed_.load(std::memory_order_acquire)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelWriteFailed);
                    }

                    return ok;
                }
            }
#if defined(_WIN32)
#pragma optimize("", on)
#else
#if defined(__clang__)
#pragma clang optimize on
#else
#pragma GCC pop_options
#endif
#endif

            /**
             * @brief Encrypts packet bytes and dispatches asynchronous transport write.
             */
            static bool Write(ITransmission* transmission, const void* packet, int packet_length, const ITransmission::AsynchronousWriteBytesCallback& cb) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TransmissionBridgeWriteInvalidPacket);
                    return false;
                }

                if (NULLPTR == cb) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TransmissionBridgeWriteNullCallback);
                    return false;
                }

                if (transmission->disposed_.load(std::memory_order_acquire)) {
                    return false;
                }

                int messages_size = 0;
                ppp::diagnostics::datapath_perf::Scope encode_scope;
                std::shared_ptr<Byte> messages = Encrypt(transmission, (Byte*)packet, packet_length, messages_size);
                // Lab-only JSONL: plaintext input, framed output, and synchronous Encrypt duration.
                ppp::diagnostics::datapath_perf::RecordFrameEncode(packet_length,
                    NULLPTR != messages && messages_size > 0 ? messages_size : 0, encode_scope.Elapsed());
                if (NULLPTR == messages) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                    return false;
                }

                if (!transmission->WriteBytes(messages, messages_size, cb)) {
                    if (!transmission->disposed_.load(std::memory_order_acquire)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelWriteFailed);
                    }
                    return false;
                }
                // Lab-only JSONL: current accepted carrier queue and all-time high-water.
                ppp::diagnostics::datapath_perf::ObserveCarrierQueue(
                    transmission->GetPendingItems(), transmission->GetPendingBytes());

                return true;
            }

        private:
            /**
             * @brief Encodes payload length into randomized base94 framing header bytes.
             */
            static ppp::string base94_encode_length(ITransmission* transmission, const AppConfigurationPtr& configuration, int length, int kf) noexcept {
                const int MOD = configuration->Lcgmod(ITransmission::AppConfiguration::LCGMOD_TYPE_TRANSMISSION);
                const int KF_MOD = abs(kf % MOD);

                int N = (length + KF_MOD) % MOD;
                ppp::string d = ssea::base94_decimal(N);

                int dl = d.size();
                if (dl < 1 || dl >= EVP_HEADER_XSS) {
                    return ppp::string();   // invalid
                }

                // Header buffer: 4 bytes (simple) + 3 bytes (extended checksum).
                Byte h[EVP_HEADER_XSS + EVP_HEADER_MSS] = { 0x20, 0x20, 0x20, 0x20, 0,0,0 };
                Byte& k = h[0];            // random key byte
                Byte& f = h[1];            // random filler byte

                // Place base94 digits at the end of the 4‑byte area.
                memcpy(h + (EVP_HEADER_XSS - dl), d.data(), dl);

                k = RandomNext('\x20', '\x7e');
                if (f == '\x20') {
                    int v = k & '\x01';
                    if (v != '\x00') {
                        ++k;               // make key even
                    }

                    f = RandomNext('\x20', '\x7e');
                }
                elif ((k & '\x01') == '\x00') {
                    if (++k > '\x7e') {
                        k = '\x21';
                    }
                }

                std::swap(h[2], h[3]);     // obfuscation swap
                if (transmission->frame_tn_.load(std::memory_order_acquire)) {
                    // Simple header (4 bytes) already in use.
                    return ppp::string(reinterpret_cast<char*>(h), EVP_HEADER_XSS);
                }
                else {
                    // Extended header: include 3‑byte checksum.
                    int K = ppp::net::native::inet_chksum(h, EVP_HEADER_XSS) ^ length;
                    N = (K + KF_MOD) % MOD;
                    d = ssea::base94_decimal(N);
                    if (d.size() != EVP_HEADER_MSS) {
                        return ppp::string();
                    }

                    Byte* pbc = h + EVP_HEADER_XSS;
                    transmission->frame_tn_.store(true, std::memory_order_release);   // switch to simple mode for future packets

                    memcpy(pbc, d.data(), EVP_HEADER_MSS);
                    ssea::shuffle_data((char*)pbc, EVP_HEADER_MSS, kf);

                    return ppp::string(reinterpret_cast<char*>(h), sizeof(h));
                }
            }

            static int base94_decode_length(const AppConfigurationPtr& configuration, Byte* data, int kf) noexcept {
                const int MOD = configuration->Lcgmod(ITransmission::AppConfiguration::LCGMOD_TYPE_TRANSMISSION);
                const int N = ssea::base94_decimal(data, EVP_HEADER_MSS);
                const int KF_MOD = abs(kf % MOD);
                return (N - KF_MOD + MOD) % MOD;   // reverse obfuscation
            }

            /**
             * @brief Restores obfuscated base94 header bytes to canonical form.
             */
            static void base94_decode_kf(Byte* h) noexcept {
                Byte& k = h[0];
                Byte& f = h[1];
                if ((k & '\x01') == '\x00') {
                    f = '\x20';
                }

                k = '\x20';
                std::swap(h[2], h[3]);    // undo the swap
            }

            static std::shared_ptr<Byte> base94_encode(
                ITransmission*                                          transmission,
                const AppConfigurationPtr&                              configuration,
                const std::shared_ptr<BufferswapAllocator>&             allocator,
                Byte*                                                   data, 
                int                                                     datalen, 
                int                                                     kf, 
                int&                                                    outlen) noexcept {

                std::shared_ptr<Byte> payload = ssea::base94_encode(allocator, data, datalen, kf, outlen);
                if (NULLPTR == payload) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed, NULLPTR);
                }

                ppp::string k = base94_encode_length(transmission, configuration, outlen, kf);
                if (k.size() < EVP_HEADER_XSS) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed, NULLPTR);
                }

                int k_size = k.size();
                int packet_length = outlen + k_size;
                std::shared_ptr<Byte> packet = BufferswapAllocator::MakeByteArray(allocator, packet_length);
                if (NULLPTR == packet) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TransmissionBase94EncodePacketAllocFailed, NULLPTR);
                }

                Byte* memory = packet.get();
                memcpy(memory, k.data(), k_size);
                memcpy(memory + k_size, payload.get(), outlen);

                outlen = packet_length;
                return packet;
            }

            static std::shared_ptr<Byte> base94_decode(
                const AppConfigurationPtr&                              configuration,
                const std::shared_ptr<BufferswapAllocator>&             allocator,
                Byte*                                                   data, 
                int                                                     datalen, 
                int                                                     kf, 
                int&                                                    outlen) noexcept {
                    
                outlen = 0;
                if (NULLPTR == data || datalen < EVP_HEADER_XSS) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid, NULLPTR);
                }

                base94_decode_kf(data);
                
                int payload_length = base94_decode_length(configuration, data + 1, kf);
                if (payload_length < 1) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid, NULLPTR);
                }

                /**
                 * @brief Frame length upper-bound check (P0-4A): reject in-memory base94 frames
                 *        exceeding the encoded ceiling.
                 *
                 * @details The send side caps plaintext/base94 TCP chunks (see
                 *          VirtualEthernetTcpipConnection / vmux_skt) so a conforming peer never
                 *          emits a frame this large.  We accept up to EVP_BASE94_MAX_FRAME
                 *          (2 * PPP_BUFFER_SIZE, the worst-case byte-codec expansion) rather than
                 *          the raw PPP_BUFFER_SIZE, so a peer running an older, un-capped build
                 *          that emits a full-expansion frame still interoperates.  The decoded
                 *          output is re-bounded by PPP_BUFFER_SIZE in the binary decrypt path.
                 */
                if (payload_length > EVP_BASE94_MAX_FRAME) {
                    ppp::telemetry::Log(Level::kInfo,
                        "transmission",
                        "base94 frame too large payload_length=%d max=%d in_memory=yes",
                        payload_length,
                        EVP_BASE94_MAX_FRAME);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid, NULLPTR);
                }

                if ((payload_length + EVP_HEADER_XSS) != datalen) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid, NULLPTR);   // integrity check
                }

                Byte* payload = data + EVP_HEADER_XSS;
                std::shared_ptr<Byte> decoded = ssea::base94_decode(allocator, payload, payload_length, kf, outlen);
                if (NULLPTR == decoded) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed, NULLPTR);
                }

                return decoded;
            }

            /**
             * @brief Reads compact base94 header and extracts payload length.
             */
            static int base94_decode_length_rn(ITransmission* transmission, YieldContext& y) noexcept {
                std::shared_ptr<Byte> packet = ReadBytes(transmission, y, EVP_HEADER_XSS);
                if (NULLPTR == packet) {
                    if (!transmission->disposed_.load(std::memory_order_acquire)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelReadFailed);
                    }
                    return -1;
                }

                Byte* data = packet.get();
                AppConfigurationPtr& cfg = transmission->configuration_;
                base94_decode_kf(data);

                int len = base94_decode_length(cfg, data + 1, cfg->key.kf);
                if (len > 0) {
                    return len;
                }

                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                return -1;
            }

            /**
             * @brief Reads extended base94 header and validates checksum payload length.
             */
            static int base94_decode_length_r1(ITransmission* transmission, YieldContext& y) noexcept {
                std::shared_ptr<Byte> packet = ReadBytes(transmission, y, EVP_HEADER_XSS + EVP_HEADER_MSS);
                if (NULLPTR == packet) {
                    if (!transmission->disposed_.load(std::memory_order_acquire)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelReadFailed);
                    }
                    return -1;
                }

                Byte* data = packet.get();
                int K = ppp::net::native::inet_chksum(data, EVP_HEADER_XSS);

                AppConfigurationPtr& cfg = transmission->configuration_;
                base94_decode_kf(data);

                int payload_length = base94_decode_length(cfg, data + 1, cfg->key.kf);
                if (payload_length < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                    return -1;
                }

                Byte* pbc = data + EVP_HEADER_XSS;
                ssea::unshuffle_data((char*)pbc, EVP_HEADER_MSS, cfg->key.kf);

                int N = base94_decode_length(cfg, pbc, cfg->key.kf);
                K = K ^ payload_length;
                if (N != K) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                    return -1;   // checksum mismatch – tampering detected
                }

                transmission->frame_rn_.store(true, std::memory_order_release);   // switch to simple header for subsequent reads
                return payload_length;
            }

            /**
             * @brief Selects base94 header parser according to negotiated frame mode.
             */
            static int base94_decode_length(ITransmission* transmission, YieldContext& y) noexcept {
                if (transmission->frame_rn_.load(std::memory_order_acquire)) {
                    return base94_decode_length_rn(transmission, y);
                }

                return base94_decode_length_r1(transmission, y);
            }

            /**
             * @brief Reads and decodes one base94-framed payload from the transport.
             */
            static std::shared_ptr<Byte> base94_decode(ITransmission* transmission, YieldContext& y, int& outlen) noexcept {
                outlen = 0;
                int payload_length = base94_decode_length(transmission, y);
                if (payload_length < 1) {
                    if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                    }
                    return NULLPTR;
                }

                /** @brief Frame length upper-bound check (P0-4A): reject base94 frames that exceed the encoded ceiling. */
                if (payload_length > EVP_BASE94_MAX_FRAME) {
                    ppp::telemetry::Log(Level::kInfo,
                        "transmission",
                        "base94 frame too large payload_length=%d max=%d in_memory=no",
                        payload_length,
                        EVP_BASE94_MAX_FRAME);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid, NULLPTR);
                }

                std::shared_ptr<Byte> packet = ReadBytes(transmission, y, payload_length);
                if (NULLPTR == packet) {
                    if (!transmission->disposed_.load(std::memory_order_acquire)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelReadFailed);
                    }
                    return NULLPTR;
                }

                AppConfigurationPtr& cfg = transmission->configuration_;
                std::shared_ptr<Byte> decoded = ssea::base94_decode(transmission->BufferAllocator,
                    packet.get(), payload_length,
                    cfg->key.kf, outlen);
                if (NULLPTR == decoded) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed, NULLPTR);
                }

                return decoded;
            }
        };

        // -----------------------------------------------------------------------------
        // Packet encryption/decryption helpers.
        // -----------------------------------------------------------------------------
        /**
         * @brief Builds and encrypts packet header containing payload length metadata.
         */
        static std::shared_ptr<Byte> Transmission_Header_Encrypt(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            const CiphertextPtr&                        EVP_protocol,
            int                                         EVP_payload_length,
            int&                                        EVP_header_length,
            int&                                        EVP_header_kf) noexcept {

            // Adjust length: 65536 → 65535 (avoid zero‑length packets).
            if (--EVP_payload_length < 0) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TransmissionHeaderEncryptInvalidPayloadLength, NULLPTR);
            }

            // Header array: [seed_byte, high_byte, low_byte]
            Byte EVP_payload_length_array[EVP_HEADER_MSS] = {
                (Byte)(RandomNext(0x01, 0xff)),
                (Byte)(EVP_payload_length >> 0x08),
                (Byte)(EVP_payload_length & 0xff)
            };

            int EVP_header_datalen = sizeof(EVP_payload_length_array);
            EVP_header_kf = APP->key.kf ^ *EVP_payload_length_array;

            // Encrypt the length field using protocol cipher if available.
            if (EVP_protocol) {
                std::shared_ptr<Byte> EVP_header_length_buff = EVP_protocol->Encrypt(
                    allocator, EVP_payload_length_array + 1, EVP_HEADER_TSS, EVP_header_length);
                if (NULLPTR == EVP_header_length_buff || EVP_header_length != EVP_HEADER_TSS) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed, NULLPTR);
                }

                memcpy(EVP_payload_length_array + 1, EVP_header_length_buff.get(), EVP_HEADER_TSS);
            }

            // XOR mask with per‑packet key.
            for (int i = 1; i < EVP_HEADER_MSS; i++) {
                EVP_payload_length_array[i] ^= EVP_header_kf;
            }

            EVP_header_length = sizeof(EVP_payload_length_array);
            ssea::shuffle_data(reinterpret_cast<char*>(EVP_payload_length_array + 1), EVP_HEADER_TSS, EVP_header_kf);

            std::shared_ptr<Byte> output;
            if (ssea::delta_encode(allocator, EVP_payload_length_array, EVP_header_datalen,
                APP->key.kf, output) != EVP_header_length) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed, NULLPTR);
            }

            return output;
        }

        /**
         * @brief Decrypts packet header and returns decoded payload length.
         */
        static int Transmission_Header_Decrypt(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            const CiphertextPtr&                        EVP_protocol,
            Byte*                                       EVP_header_array,
            int&                                        EVP_header_kf) noexcept {

            std::shared_ptr<Byte> decoded;
            if (ssea::delta_decode(allocator, EVP_header_array, EVP_HEADER_MSS,
                APP->key.kf, decoded) != EVP_HEADER_MSS) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                return 0;
            }

            Byte* array = decoded.get();
            EVP_header_kf = APP->key.kf ^ *array;

            ssea::unshuffle_data(reinterpret_cast<char*>(array + 1), EVP_HEADER_TSS, EVP_header_kf);
            for (int i = 1; i < EVP_HEADER_MSS; i++) {
                array[i] ^= EVP_header_kf;
            }

            int len = 0;
            if (EVP_protocol) {
                std::shared_ptr<Byte> dec = EVP_protocol->Decrypt(allocator, array + 1, EVP_HEADER_TSS, len);
                if (NULLPTR == dec || len != EVP_HEADER_TSS) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                    return 0;
                }

                memcpy(array + 1, dec.get(), EVP_HEADER_TSS);
            }

            len = array[1] << 0x08 | array[2];
            return len + 1;   // add back the adjustment
        }

        /**
         * @brief Applies optional masked/shuffle payload transforms before framing.
         */
        static void Transmission_Payload_Encrypt_Partial(
            const AppConfigurationPtr&                  APP,
            int                                         kf,
            Byte*                                       data,
            int                                         datalen,
            bool                                        safest) noexcept {

            if (safest || APP->key.masked) {
                ssea::masked_xor_random_next(data, data + datalen, kf);
            }

            if (safest || APP->key.shuffle_data) {
                ssea::shuffle_data(reinterpret_cast<char*>(data), datalen, kf);
            }
        }

        /**
         * @brief Encrypts payload transform stage and optional delta encoding.
         */
        static std::shared_ptr<Byte> Transmission_Payload_Encrypt(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            int                                         kf,
            Byte*                                       data,
            int                                         datalen,
            int&                                        outlen,
            bool                                        safest) noexcept {

            outlen = datalen;
            Transmission_Payload_Encrypt_Partial(APP, kf, data, datalen, safest);

            std::shared_ptr<Byte> output;
            if (safest || APP->key.delta_encode) {
                if (ssea::delta_encode(allocator, data, datalen, APP->key.kf, output) != datalen) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed, NULLPTR);
                }

                return output;
            }
            else {
                output = BufferswapAllocator::MakeByteArray(allocator, datalen);
                if (NULLPTR == output) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TransmissionPayloadEncryptCopyAllocFailed, NULLPTR);
                }

                memcpy(output.get(), data, datalen);
                return output;
            }
        }

        /**
         * @brief Reverses optional masked/shuffle transforms on payload bytes.
         */
        static void Transmission_Payload_Decrypt_Partial(
            const AppConfigurationPtr&                  APP,
            int                                         kf,
            Byte*                                       data,
            int                                         datalen,
            bool                                        safest) noexcept {

            if (safest || APP->key.shuffle_data) {
                ssea::unshuffle_data(reinterpret_cast<char*>(data), datalen, kf);
            }

            if (safest || APP->key.masked) {
                ssea::masked_xor_random_next(data, data + datalen, kf);
            }
        }

        /**
         * @brief Decrypts framed payload and reverses transport obfuscation layers.
         */
        static std::shared_ptr<Byte> Transmission_Payload_Decrypt(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            int                                         kf,
            const std::shared_ptr<Byte>&                data,
            int                                         datalen,
            int&                                        outlen,
            bool                                        safest) noexcept {

            outlen = datalen;
            if (safest || APP->key.delta_encode) {
                std::shared_ptr<Byte> decoded;
                if (ssea::delta_decode(allocator, data.get(), datalen, APP->key.kf, decoded) != datalen) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed, NULLPTR);
                }

                Transmission_Payload_Decrypt_Partial(APP, kf, decoded.get(), datalen, safest);
                return decoded;
            }
            else {
                Transmission_Payload_Decrypt_Partial(APP, kf, data.get(), datalen, safest);
                return data;
            }
        }

        /**
         * @brief Concatenates encrypted header and payload into one packet buffer.
         */
        static std::shared_ptr<Byte> Transmission_Packet_Pack(
            const std::shared_ptr<BufferswapAllocator>& allocator,
            const std::shared_ptr<Byte>&                EVP_header,
            int                                         EVP_header_length,
            const std::shared_ptr<Byte>&                EVP_payload,
            int                                         EVP_payload_length,
            int&                                        EVP_packet_length) noexcept {

            EVP_packet_length = EVP_header_length + EVP_payload_length;

            auto packet = BufferswapAllocator::MakeByteArray(allocator, EVP_packet_length);
            if (NULLPTR == packet) {
                return NULLPTR;
            }

            Byte* mem = packet.get();
            memcpy(mem, EVP_header.get(), EVP_header_length);
            memcpy(mem + EVP_header_length, EVP_payload.get(), EVP_payload_length);

            return packet;
        }

        /**
         * @brief Encrypts plaintext payload and assembles transmission packet bytes.
         */
        static std::shared_ptr<Byte> Transmission_Packet_Encrypt(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            const CiphertextPtr&                        EVP_protocol,
            const CiphertextPtr&                        EVP_transport,
            Byte*                                       data,
            int                                         datalen,
            int&                                        outlen,
            bool                                        safest) noexcept {

            int payload_len = 0, header_kf = 0, header_len = 0;
            outlen = 0;

            if (EVP_protocol && EVP_transport) {
                // Layer 1: transport cipher.
                ppp::diagnostics::datapath_perf::Scope transport_encrypt_scope;
                auto payload = EVP_transport->Encrypt(allocator, data, datalen, payload_len);
                if (NULLPTR == payload || payload_len != datalen) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed, NULLPTR);
                }
                ppp::diagnostics::datapath_perf::RecordFrameTransportEncrypt(datalen,
                    transport_encrypt_scope.Elapsed());

                // Layer 2: header encryption (protocol cipher).
                ppp::diagnostics::datapath_perf::Scope header_encrypt_scope;
                auto header = Transmission_Header_Encrypt(APP, allocator, EVP_protocol,
                    payload_len, header_len, header_kf);
                if (NULLPTR == header) {
                    return NULLPTR;
                }
                ppp::diagnostics::datapath_perf::RecordFrameHeaderEncrypt(header_len,
                    header_encrypt_scope.Elapsed());
                
                // Layer 3: payload obfuscation using header-derived key.
                ppp::diagnostics::datapath_perf::Scope payload_encrypt_scope;
                payload = Transmission_Payload_Encrypt(APP, allocator, header_kf,
                    payload.get(), datalen, payload_len, safest);
                if (NULLPTR == payload) {
                    return NULLPTR;
                }
                ppp::diagnostics::datapath_perf::RecordFramePayloadEncrypt(payload_len,
                    payload_encrypt_scope.Elapsed());

                ppp::diagnostics::datapath_perf::Scope pack_scope;
                auto packet = Transmission_Packet_Pack(allocator, header, header_len,
                    payload, payload_len, outlen);
                if (NULLPTR != packet) {
                    ppp::diagnostics::datapath_perf::RecordFramePack(outlen, pack_scope.Elapsed());
                }
                return packet;
            }
            else {
                // No transport cipher – only header + payload obfuscation.
                auto header = Transmission_Header_Encrypt(APP, allocator, EVP_protocol,
                    datalen, header_len, header_kf);
                if (NULLPTR == header) {
                    return NULLPTR;
                }

                auto payload = Transmission_Payload_Encrypt(APP, allocator, header_kf,
                    data, datalen, payload_len, safest);
                if (NULLPTR == payload) {
                    return NULLPTR;
                }

                return Transmission_Packet_Pack(allocator, header, header_len,
                    payload, payload_len, outlen);
            }
        }

        /**
         * @brief Decrypts full transmission packet into plaintext payload bytes.
         */
        static std::shared_ptr<Byte> Transmission_Packet_Decrypt(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            const CiphertextPtr&                        EVP_protocol,
            const CiphertextPtr&                        EVP_transport,
            Byte*                                       data,
            int                                         datalen,
            int&                                        outlen,
            bool                                        safest) noexcept {

            int header_kf = 0;
            outlen = 0;

            if (datalen <= EVP_HEADER_MSS) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid, NULLPTR);
            }

            int payload_len = Transmission_Header_Decrypt(APP, allocator, EVP_protocol, data, header_kf);
            if (payload_len < 1) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed, NULLPTR);
            }

            /** @brief Frame length upper-bound check (P0-4A): reject decoded payloads exceeding PPP_BUFFER_SIZE. */
            if (payload_len > PPP_BUFFER_SIZE) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid, NULLPTR);
            }

            int expected_len = payload_len + EVP_HEADER_MSS;
            if (expected_len != datalen) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid, NULLPTR);   // size mismatch – possible truncation attack
            }

            auto payload = BufferswapAllocator::MakeByteArray(allocator, payload_len);
            if (NULLPTR == payload) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TransmissionPacketDecryptPayloadAllocFailed, NULLPTR);
            }

            memcpy(payload.get(), data + EVP_HEADER_MSS, payload_len);
            payload = Transmission_Payload_Decrypt(APP, allocator, header_kf,
                payload, payload_len, outlen, safest);
            if (NULLPTR == payload) {
                return NULLPTR;
            }

            if (EVP_protocol && EVP_transport) {
                payload = EVP_transport->Decrypt(allocator, payload.get(), payload_len, outlen);
                if (NULLPTR == payload || payload_len != outlen) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed, NULLPTR);
                }
            }

            return payload;
        }

        /**
         * @brief Reads header and payload from transport and decrypts to plaintext.
         */
        static std::shared_ptr<Byte> Transmission_Packet_Read(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            const CiphertextPtr&                        EVP_protocol,
            const CiphertextPtr&                        EVP_transport,
            int&                                        outlen,
            ITransmission*                              transmission,
            YieldContext&                               y,
            bool                                        safest) noexcept {

            int header_kf = 0;
            outlen = 0;

            auto header = ITransmissionBridge::ReadBytes(transmission, y, EVP_HEADER_MSS);
            if (NULLPTR == header) {
                if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelReadFailed);
                }
                return NULLPTR;
            }

            ppp::diagnostics::datapath_perf::Scope header_decode_scope;
            int payload_len = Transmission_Header_Decrypt(APP, allocator, EVP_protocol, header.get(), header_kf);
            const uint64_t header_decode_us = header_decode_scope.Elapsed();
            if (payload_len < 1) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed, NULLPTR);
            }
            ppp::diagnostics::datapath_perf::RecordFrameHeaderDecrypt(EVP_HEADER_MSS, header_decode_us);

            /** @brief Frame length upper-bound check (P0-4A): reject decoded payloads exceeding PPP_BUFFER_SIZE. */
            if (payload_len > PPP_BUFFER_SIZE) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid, NULLPTR);
            }

            auto payload = ITransmissionBridge::ReadBytes(transmission, y, payload_len);
            if (NULLPTR == payload) {
                if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelReadFailed);
                }
                return NULLPTR;
            }

            ppp::diagnostics::datapath_perf::Scope payload_decode_scope;
            payload = Transmission_Payload_Decrypt(APP, allocator, header_kf,
                payload, payload_len, outlen, safest);
            if (NULLPTR == payload) {
                return NULLPTR;
            }
            const uint64_t payload_decode_us = payload_decode_scope.Elapsed();
            ppp::diagnostics::datapath_perf::RecordFramePayloadDecrypt(payload_len, payload_decode_us);

            uint64_t transport_decode_us = 0;
            if (EVP_protocol && EVP_transport) {
                ppp::diagnostics::datapath_perf::Scope transport_decode_scope;
                payload = EVP_transport->Decrypt(allocator, payload.get(), payload_len, outlen);
                if (NULLPTR == payload || payload_len != outlen) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed, NULLPTR);
                }
                transport_decode_us = transport_decode_scope.Elapsed();
                ppp::diagnostics::datapath_perf::RecordFrameTransportDecrypt(outlen, transport_decode_us);
            }

            ppp::diagnostics::datapath_perf::RecordFrameDecode(outlen,
                header_decode_us + payload_decode_us + transport_decode_us);
            return payload;
        }

        // -----------------------------------------------------------------------------
        // Handshake helpers.
        // -----------------------------------------------------------------------------
        /**
         * @brief Packs handshake session identifier into obfuscated transport payload.
         */
        static std::shared_ptr<Byte> Transmission_Handshake_Pack_SessionId(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            Int128                                      session_id,
            int&                                        packet_length) noexcept {

            Byte kfs[4];
            packet_length = 0;

            ppp::string id_str;
            if (session_id) {
                kfs[0] = RandomNext(0x00, 0x7f);   // MSB clear = real session
                id_str = stl::to_string<ppp::string>(session_id);
            }
            else {
                kfs[0] = RandomNext(0x80, 0xff);   // MSB set = dummy packet

                int64_t v1 = (int64_t)RandomNext() << 32 | (int64_t)(uint32_t)RandomNext();
                int64_t v2 = (int64_t)RandomNext() << 32 | (int64_t)(uint32_t)RandomNext();
                id_str = stl::to_string<ppp::string>(MAKE_OWORD(v2, v1));
            }

            kfs[1] = RandomNext(0x01, 0xff);
            kfs[2] = RandomNext(0x01, 0xff);
            kfs[3] = RandomNext(0x01, 0xff);
            id_str.append(1, RandomNext(0x20, 0x2F));   // separator

            // Add random padding to resist traffic analysis.
            int max = APP->key.kx % 0x100;
            if (max > 0) {
                int i = 0;
                for (; i < max; i++) {
                    id_str.append(1, RandomNext(0x20, 0x7e));
                }

                if (i == max) {
                    id_str.append(1, '/');
                }

                int min = id_str.size() + sizeof(kfs);
                if (min > max) {
                    max = min;
                }

                int loops = RandomNext(1, max << 2);
                for (int i = 0; i < loops; i++) {
                    id_str.append(1, RandomNext(0x20, 0x7e));
                }
            }

            Byte* raw = (Byte*)id_str.data();
            packet_length = id_str.size();

            int kf = APP->key.kf;
            for (int i = 0; i < arraysizeof(kfs); i++) {
                kf ^= kfs[i];
                for (int j = 0; j < packet_length; j++) {
                    raw[j] ^= kf;
                }
            }

            auto msg = BufferswapAllocator::MakeByteArray(allocator, packet_length += sizeof(kfs));
            if (NULLPTR == msg) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TransmissionHandshakePackBufferAllocFailed, NULLPTR);
            }

            Byte* mem = msg.get();
            memcpy(mem, kfs, sizeof(kfs));
            memcpy(mem + sizeof(kfs), raw, id_str.size());
            return msg;
        }

        /**
         * @brief Unpacks handshake session identifier and filters dummy packets.
         */
        static Int128 Transmission_Handshake_Unpack_SessionId(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<Byte>&                packet_managed,
            int                                         packet_length,
            bool&                                       eagin) noexcept {

            eagin = false;
            if (NULLPTR == packet_managed || packet_length < 4) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                return 0;
            }

            Byte* p = packet_managed.get();
            if (*p & 0x80) {
                eagin = true;   // dummy packet – ignore
                return 0;
            }

            Byte kfs[] = { p[0], p[1], p[2], p[3] };
            p += sizeof(kfs);

            packet_length -= sizeof(kfs);
            if (packet_length < 1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                return 0;
            }

            int kf = APP->key.kf;
            for (int i = 0; i < arraysizeof(kfs); i++) {
                kf ^= kfs[i];
                for (int j = 0; j < packet_length; j++) {
                    p[j] ^= kf;
                }
            }

            Int128 sid = ppp::Int128FromString(std::string_view(reinterpret_cast<char*>(p), packet_length), 10);
            if (0 == sid) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionIdInvalid);
            }

            return sid;
        }

        /**
         * @brief Sends one handshake session identifier packet.
         */
        static bool Transmission_Handshake_SessionId(
            const AppConfigurationPtr&                  APP,
            ITransmission*                              transmission,
            ITransmission::YieldContext&                y,
            const Int128&                               session_id) noexcept {

            int len = 0;
            auto pkt = Transmission_Handshake_Pack_SessionId(APP, transmission->BufferAllocator, session_id, len);
            if (NULLPTR == pkt) {
                if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                }
                return false;
            }

            return ITransmissionBridge::Write(transmission, y, pkt.get(), len);
        }

        /**
         * @brief Receives handshake session identifier, skipping dummy handshake frames.
         */
        static Int128 Transmission_Handshake_SessionId(
            const AppConfigurationPtr&                  APP,
            ITransmission*                              transmission,
            ITransmission::YieldContext&                y) noexcept {

            bool eagin = false;
            for (;;) {
                int len = 0;
                auto pkt = ITransmissionBridge::Read(transmission, y, len);
                if (NULLPTR == pkt) {
                    return 0;
                }

                Int128 sid = Transmission_Handshake_Unpack_SessionId(APP, pkt, len, eagin);
                if (eagin) {
                    continue;   // skip dummy packets
                }

                return sid;
            }
        }

        // -----------------------------------------------------------------------------
        // Post-handshake obfuscation-flag fingerprint exchange.
        //
        // The four bool flags `key.masked / key.plaintext / key.delta_encode /
        // key.shuffle_data` plus the 32-bit `key.kf` constant govern the post-
        // handshake framing layer in `Transmission_Payload_Encrypt/Decrypt` and
        // `Transmission_Header_Encrypt/Decrypt`.  When the two endpoints disagree
        // on any of these values the handshake itself still succeeds (handshake
        // packets always run in `safest=true` mode), but the very first data-plane
        // packet is silently mis-framed and `transmission->Read()` blocks until
        // the keep-alive deadline (~15s) tears the session down with no diagnostic.
        //
        // This helper closes that gap by performing one extra `SessionId` round-
        // trip immediately after `handshaked_=true` (i.e. using the *configured*
        // flags, not the safest-mode handshake encoding).  Both sides write a
        // 128-bit canary whose low 64 bits encode the framing-relevant config
        // bits and whose high 64 bits are random.  If the peer cannot decode our
        // canary, or if the decoded low-half does not match our locally-computed
        // canary, we know the framing layers disagree and we emit a structured
        // diagnostic on every available log channel before tearing the session
        // down with `ErrorCode::ObfuscationFlagsMismatch`.
        // -----------------------------------------------------------------------------

        /**
         * @brief Builds a deterministic 64-bit canary that captures every
         *        framing-relevant configuration bit.
         *
         * Layout:
         *   bits  0..47 : 0xC0DEC0DEC0DE   (constant magic; detects total
         *                                   handshake desync vs flag mismatch)
         *   bits 48..51 : masked / plaintext / delta_encode / shuffle_data
         *   bits 52..63 : low 12 bits of `key.kf`
         */
        static uint64_t Transmission_Handshake_FlagCanary(const AppConfigurationPtr& APP) noexcept {
            uint64_t magic = 0xC0DEC0DEC0DEULL;

            uint64_t flags = 0;
            flags |= (APP->key.masked       ? 1ULL : 0ULL) << 0;
            flags |= (APP->key.plaintext    ? 1ULL : 0ULL) << 1;
            flags |= (APP->key.delta_encode ? 1ULL : 0ULL) << 2;
            flags |= (APP->key.shuffle_data ? 1ULL : 0ULL) << 3;

            uint64_t kf_canary = static_cast<uint64_t>(static_cast<uint32_t>(APP->key.kf)) & 0xFFFULL;

            return magic | (flags << 48) | (kf_canary << 52);
        }

        /**
         * @brief Exchanges randomized handshake noise packets before real handshake values.
         */
        bool Transmission_Handshake_Nop(
            const AppConfigurationPtr&                  APP,
            ITransmission*                              transmission,
            ITransmission::YieldContext&                y) noexcept {

            int kl = std::max<int>(0, 1 << APP->key.kl);
            int kh = std::max<int>(0, 1 << APP->key.kh);

            if (kl > kh) {
                std::swap(kl, kh);
            }

            int rounds = (kl == kh) ? kl : RandomNext(kl, kh);
            rounds = static_cast<int>(ceil(rounds / (double)(175 << 3)));

            for (int i = 0; i < rounds; ++i) {
                if (!Transmission_Handshake_SessionId(APP, transmission, y, 0)) {
                    return false;
                }
            }

            return true;
        }

        // -----------------------------------------------------------------------------
        // ITransmission implementation.
        // -----------------------------------------------------------------------------
        /**
         * @brief Initializes transmission state and optional protocol/transport ciphers.
         */
        ITransmission::ITransmission(const ContextPtr& context, const StrandPtr& strand,
            const AppConfigurationPtr& configuration) noexcept
            : IAsynchronousWriteIoQueue(NULLPTR != configuration ? configuration->GetBufferAllocator() : NULLPTR)
            , disposed_(false), frame_rn_(false), frame_tn_(false), handshaked_(false)
            , context_(context), strand_(strand), configuration_(configuration) {

            ppp::telemetry::Log(Level::kInfo, "transmission", "ITransmission created");
            ppp::telemetry::Count("transmission.connection.open", 1);

            if (ppp::configurations::extensions::IsHaveCiphertext(configuration.get())) {
                if (Ciphertext::Support(configuration->key.protocol) && Ciphertext::Support(configuration->key.transport)) {
                    protocol_ = make_shared_object<Ciphertext>(configuration->key.protocol, configuration->key.protocol_key);
                    transport_ = make_shared_object<Ciphertext>(configuration->key.transport, configuration->key.transport_key);
                }
            }
        }

        /**
         * @brief Destroys transmission and finalizes internal resources.
         */
        ITransmission::~ITransmission() noexcept {
            InvalidateAuthenticatedCarrierBinding();
            Finalize();
        }

        AuthenticatedCarrierMethod ITransmission::GetAuthenticatedCarrierMethod() const noexcept {
            std::shared_ptr<NoisePskAuthenticatedCarrierBinding> binding;
            {
                std::lock_guard<std::mutex> lock(authenticated_carrier_mutex_);
                binding = noise_authenticated_carrier_binding_;
            }
            return binding && binding->IsValid()
                ? AuthenticatedCarrierMethod::NoisePskV1
                : AuthenticatedCarrierMethod::None;
        }

        bool ITransmission::IsAuthenticatedCarrierBindingActive() const noexcept {
            if (IsServerLoopbackIngress() ||
                disposed_.load(std::memory_order_acquire) ||
                finalized_.load(std::memory_order_acquire) ||
                !IsHandshakeComplete()) {
                return false;
            }

            std::shared_ptr<NoisePskAuthenticatedCarrierBinding> binding;
            {
                std::lock_guard<std::mutex> lock(authenticated_carrier_mutex_);
                binding = noise_authenticated_carrier_binding_;
            }
            return binding && binding->IsAvailable(context_, strand_);
        }

        bool ITransmission::HasAuthenticatedSessionExporter() const noexcept {
            return IsAuthenticatedCarrierBindingActive();
        }

        bool ITransmission::ExportAuthenticatedSessionKey(
            const char* label,
            const std::uint8_t* context,
            std::size_t context_length,
            std::uint8_t* output,
            std::size_t output_length) noexcept {
            if (IsServerLoopbackIngress() ||
                disposed_.load(std::memory_order_acquire) ||
                finalized_.load(std::memory_order_acquire) ||
                !IsHandshakeComplete()) {
                return false;
            }

            std::shared_ptr<NoisePskAuthenticatedCarrierBinding> binding;
            {
                std::lock_guard<std::mutex> lock(authenticated_carrier_mutex_);
                binding = noise_authenticated_carrier_binding_;
            }
            return binding && binding->Export(context_, strand_, label, context,
                context_length, output, output_length);
        }

        bool ITransmission::InstallNoiseAuthenticatedCarrierBinding(
            ppp::cryptography::noise::NoisePskHandshakeResult&& result) noexcept {
            const AuthenticatedCarrierKind carrier = GetAuthenticatedCarrierKind();
            if ((carrier != AuthenticatedCarrierKind::Tcp &&
                    carrier != AuthenticatedCarrierKind::WebSocket) ||
                IsServerLoopbackIngress() ||
                disposed_.load(std::memory_order_acquire) ||
                finalized_.load(std::memory_order_acquire) ||
                GetAuthenticatedCarrierMethod() != AuthenticatedCarrierMethod::None ||
                !IsHandshakeComplete() || !result.IsValid() ||
                !context_ || !strand_ || context_->stopped() ||
                !strand_->running_in_this_thread()) {
                result.Clear();
                return false;
            }

            std::lock_guard<std::mutex> lock(authenticated_carrier_mutex_);
            if (noise_authenticated_carrier_binding_) {
                result.Clear();
                return false;
            }

            try {
                noise_authenticated_carrier_binding_ =
                    std::make_shared<NoisePskAuthenticatedCarrierBinding>(
                        context_, strand_, std::move(result));
            }
            catch (...) {
                result.Clear();
                return false;
            }
            return noise_authenticated_carrier_binding_->IsValid();
        }

        void ITransmission::InvalidateAuthenticatedCarrierBinding() noexcept {
            std::shared_ptr<NoisePskAuthenticatedCarrierBinding> binding;
            {
                std::lock_guard<std::mutex> lock(authenticated_carrier_mutex_);
                binding = std::move(noise_authenticated_carrier_binding_);
            }
            if (binding) {
                binding->Invalidate();
            }
        }

        /**
         * @brief Finalizes runtime state, cancels timers, and clears optional helpers.
         */
        void ITransmission::Finalize() noexcept {
            ppp::telemetry::SpanScope span("transmission.lifecycle.close");
            InvalidateAuthenticatedCarrierBinding();

            // One-shot guard: only the first caller proceeds; subsequent calls are no-ops.
            bool expected = false;
            if (!finalized_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                return;
            }

            ppp::telemetry::Log(Level::kInfo, "transmission", "ITransmission finalized");
            ppp::telemetry::Count("transmission.connection.close", 1);

            DeadlineTimerPtr t = std::move(timeout_);
            disposed_.store(true, std::memory_order_release);
            handshaked_.store(false, std::memory_order_release);
            QoS.reset();
            Statistics.reset();
            if (NULLPTR != t) {
                Socket::Cancel(*t);
            }
        }

        /**
         * @brief Reads one message using bridge decode workflow.
         */
        std::shared_ptr<Byte> ITransmission::Read(YieldContext& y, int& outlen) noexcept {
            std::shared_ptr<Byte> result = ITransmissionBridge::Read(this, y, outlen);
            if (NULLPTR == result && ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                // Distinguish disposed state from a normal I/O failure.
                if (disposed_.load(std::memory_order_acquire)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelReadFailed);
                }
            }

            if (NULLPTR == result) {
                ppp::telemetry::Log(Level::kInfo,
                    "transmission",
                    "Read failed outlen=%d error=%d disposed=%s finalized=%s",
                    outlen,
                    (int)ppp::diagnostics::GetLastErrorCode(),
                    disposed_.load(std::memory_order_acquire) ? "yes" : "no",
                    finalized_.load(std::memory_order_acquire) ? "yes" : "no");
            }

            return result;
        }

        /**
         * @brief Writes one message using coroutine-aware bridge workflow.
         */
        bool ITransmission::Write(YieldContext& y, const void* packet, int packet_length) noexcept {
            bool ok = ITransmissionBridge::Write(this, y, packet, packet_length);
            if (!ok && ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                if (disposed_.load(std::memory_order_acquire)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelWriteFailed);
                }
            }

            return ok;
        }

        /**
         * @brief Writes one message using callback-based bridge workflow.
         */
        bool ITransmission::Write(const void* packet, int packet_length, const AsynchronousWriteCallback& cb) noexcept {
            bool ok = ITransmissionBridge::Write(this, packet, packet_length, cb);
            if (!ok && ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                if (disposed_.load(std::memory_order_acquire)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                }
                elif (NULLPTR == packet || packet_length < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TransmissionWriteAsyncInvalidPacket);
                }
                elif (NULLPTR == cb) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TransmissionWriteAsyncNullCallback);
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelWriteFailed);
                }
            }

            return ok;
        }

        /**
         * @brief Encrypts caller-provided buffer into framed transmission bytes.
         */
        std::shared_ptr<Byte> ITransmission::Encrypt(Byte* data, int datalen, int& outlen) noexcept {
            outlen = 0;
            if (datalen < 0 || (NULLPTR == data && datalen != 0)) {
                outlen = ~0;
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TransmissionEncryptInvalidArguments);
                return NULLPTR;
            }

            if (datalen == 0) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TransmissionEncryptZeroLengthInput);
                return NULLPTR;
            }

            std::shared_ptr<Byte> result = ITransmissionBridge::Encrypt(this, data, datalen, outlen);
            if (NULLPTR == result) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
            }

            return result;
        }

        /**
         * @brief Decrypts framed transmission bytes into plaintext payload.
         */
        std::shared_ptr<Byte> ITransmission::Decrypt(Byte* data, int datalen, int& outlen) noexcept {
            outlen = 0;
            if (datalen < 0 || (NULLPTR == data && datalen != 0)) {
                outlen = ~0;
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TransmissionDecryptInvalidArguments);
                return NULLPTR;
            }

            if (datalen == 0) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TransmissionDecryptZeroLengthInput);
                return NULLPTR;
            }

            std::shared_ptr<Byte> result = ITransmissionBridge::Decrypt(this, data, datalen, outlen);
            if (NULLPTR == result) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
            }

            return result;
        }

        /**
         * @brief Posts asynchronous cleanup of transmission and write queue resources.
         */
        void ITransmission::Dispose() noexcept {
            InvalidateAuthenticatedCarrierBinding();
            peer_supports_transport_auth_v1_.store(false, std::memory_order_release);
            peer_enables_transport_auth_v1_.store(false, std::memory_order_release);
            disposed_.store(true, std::memory_order_release);
            ppp::telemetry::Log(Level::kInfo, "transmission", "ITransmission disposed");
            ppp::telemetry::Count("transmission.transport.dispose", 1);

            auto self = shared_from_this();
            auto ctx = GetContext();
            auto st = GetStrand();
            ppp::threading::Executors::Post(ctx, st,
                [self, this, ctx, st]() noexcept {
                    Finalize();
                    IAsynchronousWriteIoQueue::Dispose();
                });
        }

        /**
         * @brief Runs client-side handshake state machine and negotiates mux mode.
         */
        Int128 ITransmission::InternalHandshakeClient(YieldContext& y, bool& mux) noexcept {
            // Historical API name: this path runs on the server application side.
            if (!Transmission_Handshake_Nop(configuration_, this, y)) {
                return 0;
            }

            Int128 sid = Transmission_Handshake_SessionId(configuration_, this, y);
            if (sid) {
                Int128 ivv = ppp::auxiliary::StringAuxiliary::GuidStringToInt128(GuidGenerate());
                ivv = TransportAuthHandshakeCapabilityCodec::EncodeServerIvv(
                    ivv, configuration_->server.transport_auth.enabled &&
                        !IsServerLoopbackIngress());
                if (!Transmission_Handshake_SessionId(configuration_, this, y, ivv)) {
                    return 0;
                }

                Int128 nmux = Transmission_Handshake_SessionId(configuration_, this, y);
                if (nmux) {
                    mux = (nmux & 1) != 0;
                    bool peer_supports_transport_auth_v1 = false;
                    bool peer_enables_transport_auth_v1 = false;
                    TransportAuthHandshakeCapabilityCodec::DecodeClientNmux(nmux,
                        peer_supports_transport_auth_v1,
                        peer_enables_transport_auth_v1);

                    // Obfuscation-flag validation, backward-compatible edition.
                    // A new-version client embeds its flag canary in the high 64
                    // bits of `nmux` (see InternalHandshakeServer below); old
                    // clients leave those bits fully random.  The canary carries
                    // a 48-bit magic, so the probability that a random value
                    // collides with the magic is 2^-48 ≈ 3.5e-15.  We therefore
                    // treat a magic match as "peer is new version, enforce
                    // flags" and anything else as "peer is old version, skip
                    // silently" — this keeps legacy clients working while still
                    // giving clear diagnostics when two new-version peers have
                    // mismatched key.masked / key.plaintext / key.delta-encode
                    // / key.shuffle-data / key.kf.
                    uint64_t nmux_high = static_cast<uint64_t>(nmux >> 64);
                    constexpr uint64_t kMagicMask  = 0x0000FFFFFFFFFFFFULL;
                    constexpr uint64_t kMagicValue = 0xC0DEC0DEC0DEULL;
                    if ((nmux_high & kMagicMask) == kMagicValue) {
                        uint64_t local = Transmission_Handshake_FlagCanary(configuration_);
                        if (nmux_high != local) {
                            const char* kind =
                                ((local & kMagicMask) == kMagicValue)
                                    ? "flag bits differ"
                                    : "local canary malformed";

                            ppp::telemetry::Count("transmission.handshake.flag_mismatch", 1);
                            ppp::telemetry::Log(
                                Level::kInfo, "transmission",
                                "obfuscation flag mismatch detected (%s): local=0x%016llx peer=0x%016llx "
                                "local_flags=[masked=%d plaintext=%d delta-encode=%d shuffle-data=%d kf=%d]",
                                kind,
                                static_cast<unsigned long long>(local),
                                static_cast<unsigned long long>(nmux_high),
                                configuration_->key.masked       ? 1 : 0,
                                configuration_->key.plaintext    ? 1 : 0,
                                configuration_->key.delta_encode ? 1 : 0,
                                configuration_->key.shuffle_data ? 1 : 0,
                                configuration_->key.kf);

                            ppp::diagnostics::SetLastErrorCode(
                                ppp::diagnostics::ErrorCode::ObfuscationFlagsMismatch);
                            return 0;
                        }
                    }

                    CiphertextPtr current_protocol = std::atomic_load(&protocol_);
                    CiphertextPtr current_transport = std::atomic_load(&transport_);
                    if (NULLPTR != current_protocol && NULLPTR != current_transport) {
                        ppp::string ivv_str = stl::to_string<ppp::string>(ivv, 32);
                        if (ivv > 0) {
                            ivv_str = "+" + ivv_str;
                        }

                        if (ppp::configurations::extensions::IsHaveCiphertext(configuration_.get())) {
                            CiphertextPtr next_protocol = make_shared_object<Ciphertext>(configuration_->key.protocol,
                                configuration_->key.protocol_key + ivv_str);
                            CiphertextPtr next_transport = make_shared_object<Ciphertext>(configuration_->key.transport,
                                configuration_->key.transport_key + ivv_str);
                            if (NULLPTR == next_protocol || NULLPTR == next_transport) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                                return 0;
                            }

                            std::atomic_store(&protocol_, next_protocol);
                            std::atomic_store(&transport_, next_transport);
                        }
                    }

                    peer_supports_transport_auth_v1_.store(
                        peer_supports_transport_auth_v1, std::memory_order_release);
                    peer_enables_transport_auth_v1_.store(
                        peer_supports_transport_auth_v1 && peer_enables_transport_auth_v1,
                        std::memory_order_release);
                    handshaked_.store(true, std::memory_order_release);
                    return sid;
                }
            }
            return 0;
        }

        /**
         * @brief Runs server-side handshake state machine and validates peer state.
         */
        bool ITransmission::InternalHandshakeServer(YieldContext& y, const Int128& session_id, bool mux) noexcept {
            // Historical API name: this path runs on the client application side.
            if (!Transmission_Handshake_Nop(configuration_, this, y)) {
                return false;
            }

            if (!Transmission_Handshake_SessionId(configuration_, this, y, session_id)) {
                return false;
            }
            
            uint64_t nmux_low = (static_cast<uint64_t>(RandomNext()) << 32) |
                                static_cast<uint32_t>(RandomNext());
            // Advertise the post-handshake obfuscation-flag canary in nmux high
            // 64 bits so the peer server application (if it is a new version)
            // can reject mismatched key.masked / key.plaintext /
            // key.delta-encode / key.shuffle-data / key.kf with a clear error
            // code.  Old server applications ignore this region, so the change
            // is fully backward compatible.  This replaces the previous approach
            // of running an extra Transmission_Handshake_VerifyFlags exchange,
            // which consumed the first post-handshake data packet of legacy
            // clients and therefore broke interop with them.
            uint64_t nmux_high = Transmission_Handshake_FlagCanary(configuration_);
            Int128 nmux = MAKE_OWORD(nmux_low, nmux_high);
            nmux = TransportAuthHandshakeCapabilityCodec::EncodeClientNmux(
                nmux, mux, configuration_->client.transport_auth.enabled);

            if (!Transmission_Handshake_SessionId(configuration_, this, y, nmux)) {
                return false;
            }

            Int128 ivv = Transmission_Handshake_SessionId(configuration_, this, y);
            if (ivv != 0) {
                bool peer_supports_transport_auth_v1 = false;
                bool peer_enables_transport_auth_v1 = false;
                TransportAuthHandshakeCapabilityCodec::DecodeServerIvv(ivv,
                    peer_supports_transport_auth_v1,
                    peer_enables_transport_auth_v1);

                CiphertextPtr current_protocol = std::atomic_load(&protocol_);
                CiphertextPtr current_transport = std::atomic_load(&transport_);
                if (NULLPTR != current_protocol && NULLPTR != current_transport) {
                    ppp::string ivv_str = stl::to_string<ppp::string>(ivv, 32);
                    if (ivv > 0) {
                        ivv_str = "+" + ivv_str;
                    }

                    if (ppp::configurations::extensions::IsHaveCiphertext(configuration_.get())) {
                        CiphertextPtr next_protocol = make_shared_object<Ciphertext>(configuration_->key.protocol,
                            configuration_->key.protocol_key + ivv_str);
                        CiphertextPtr next_transport = make_shared_object<Ciphertext>(configuration_->key.transport,
                            configuration_->key.transport_key + ivv_str);
                        if (NULLPTR == next_protocol || NULLPTR == next_transport) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                            return false;
                        }

                        std::atomic_store(&protocol_, next_protocol);
                        std::atomic_store(&transport_, next_transport);
                    }
                }

                peer_supports_transport_auth_v1_.store(
                    peer_supports_transport_auth_v1, std::memory_order_release);
                peer_enables_transport_auth_v1_.store(
                    peer_supports_transport_auth_v1 && peer_enables_transport_auth_v1,
                    std::memory_order_release);
                handshaked_.store(true, std::memory_order_release);
                // Obfuscation-flag verification is intentionally performed by
                // the peer server application in InternalHandshakeClient, where
                // the high 64-bit nmux canary is received. No extra exchange is
                // added here because it would consume legacy application data.
            }
            return handshaked_.load(std::memory_order_acquire);
        }

        /**
         * @brief Clears and cancels active handshake timeout timer.
         */
        void ITransmission::InternalHandshakeTimeoutClear() noexcept {
            DeadlineTimerPtr t = std::move(timeout_);
            if (NULLPTR != t) {
                Socket::Cancel(*t);
            }
        }

        /**
         * @brief Creates and arms handshake timeout timer with configuration jitter.
         */
        bool ITransmission::InternalHandshakeTimeoutSet() noexcept {
            if (disposed_.load(std::memory_order_acquire)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                return false;
            }

            if (NULLPTR != timeout_) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                return false;
            }

            auto st = strand_;
            auto ctx = context_;
            if (NULLPTR == st && NULLPTR == ctx)  {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                return false;
            }

            auto timer = st ? make_shared_object<DeadlineTimer>(*st) : make_shared_object<DeadlineTimer>(*ctx);
            if (NULLPTR == timer) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTimerCreateFailed);
                return false;
            }

            auto& cfg = configuration_->tcp.connect;
            int64_t expire_ms = (int64_t)cfg.timeout * 1000;
            if (cfg.nexcept > 0) {
                expire_ms = RandomNext(expire_ms, expire_ms + (int64_t)cfg.nexcept * 1000);
            }

            // static_pointer_cast is required: ITransmission::shared_from_this() returns
            // shared_ptr<IAsynchronousWriteIoQueue> (the enable_shared_from_this base),
            // so we cast to the concrete type to access ITransmission members in the lambda.
            std::shared_ptr<ITransmission> self =
                std::static_pointer_cast<ITransmission>(shared_from_this());
            timer->expires_after(std::chrono::milliseconds(expire_ms));

            timer->async_wait(
                [self](boost::system::error_code ec) noexcept {
                    if (ec == boost::system::errc::operation_canceled) {
                        return;   // cancelled normally
                    }

                    auto ctx = self->context_;
                    if (NULLPTR == ctx) {
                        self->Dispose();
                        return;
                    }

                    auto cfg = self->configuration_;
                    if (NULLPTR == cfg) {
                        self->Dispose();
                        return;
                    }

                    auto st = self->strand_;
                    // Spawn a coroutine to send final NOPs and dispose.
                    YieldContext::Spawn(NULLPTR, *ctx, st.get(),
                        [self, st, cfg](YieldContext& y) noexcept {
                            Transmission_Handshake_Nop(cfg, self.get(), y);
                            self->Dispose();
                        });
                });

            timeout_ = std::move(timer);
            return true;
        }

        /**
         * @brief Executes client handshake with timeout protection.
         */
        Int128 ITransmission::HandshakeClient(YieldContext& y, bool& mux) noexcept {
            peer_supports_transport_auth_v1_.store(false, std::memory_order_release);
            peer_enables_transport_auth_v1_.store(false, std::memory_order_release);
            mux = false;
            if (!InternalHandshakeTimeoutSet()) {
                return 0;
            }

            auto handshake_started = std::chrono::steady_clock::now();
            ppp::telemetry::Log(Level::kDebug, "transmission", "HandshakeClient started");
            ppp::telemetry::Count("transmission.handshake.start", 1);

            Int128 sid = InternalHandshakeClient(y, mux);
            InternalHandshakeTimeoutClear();
            auto handshake_elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - handshake_started).count();
            ppp::telemetry::Histogram("transmission.handshake.us", handshake_elapsed);

            if (!sid) {
                peer_supports_transport_auth_v1_.store(false, std::memory_order_release);
                peer_enables_transport_auth_v1_.store(false, std::memory_order_release);
                ppp::telemetry::Log(Level::kDebug, "transmission", "HandshakeClient failed");
                ppp::telemetry::Count("transmission.handshake.failure", 1);
                // Only set the generic SessionHandshakeFailed code when the
                // inner handshake did not already publish a more specific
                // diagnosis (e.g. ObfuscationFlagsMismatch).
                if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionHandshakeFailed);
                }
            } else {
                ppp::telemetry::Log(Level::kDebug, "transmission", "HandshakeClient completed");
                ppp::telemetry::Count("transmission.handshake.success", 1);
            }

            return sid;
        }

        /**
         * @brief Executes server handshake with timeout protection.
         */
        bool ITransmission::HandshakeServer(YieldContext& y, const Int128& session_id, bool mux) noexcept {
            peer_supports_transport_auth_v1_.store(false, std::memory_order_release);
            peer_enables_transport_auth_v1_.store(false, std::memory_order_release);
            if (session_id == 0) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionIdInvalid);
                return false;
            }

            if (!InternalHandshakeTimeoutSet()) {
                return false;
            }
            
            auto handshake_started = std::chrono::steady_clock::now();
            ppp::telemetry::Log(Level::kDebug, "transmission", "HandshakeServer started");
            ppp::telemetry::Count("transmission.handshake.start", 1);
            
            bool ok = InternalHandshakeServer(y, session_id, mux);
            InternalHandshakeTimeoutClear();
            auto handshake_elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - handshake_started).count();
            ppp::telemetry::Histogram("transmission.handshake.us", handshake_elapsed);

            if (!ok) {
                peer_supports_transport_auth_v1_.store(false, std::memory_order_release);
                peer_enables_transport_auth_v1_.store(false, std::memory_order_release);
                ppp::telemetry::Log(Level::kDebug, "transmission", "HandshakeServer failed");
                ppp::telemetry::Count("transmission.handshake.failure", 1);
                // Preserve specific inner-handshake diagnoses (e.g.
                // ObfuscationFlagsMismatch) over the generic fallback.
                if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionHandshakeFailed);
                }
            } else {
                ppp::telemetry::Log(Level::kDebug, "transmission", "HandshakeServer completed");
                ppp::telemetry::Count("transmission.handshake.success", 1);
            }

            return ok;
        }

        // -----------------------------------------------------------------------------
        // ITransmissionBridge binary encrypt/decrypt implementations.
        // -----------------------------------------------------------------------------
        /**
         * @brief Encrypts payload via packet encryption path selected by cipher state.
         */
        std::shared_ptr<Byte> ITransmissionBridge::EncryptBinary(ITransmission* transmission, Byte* data, int datalen, int& outlen) noexcept {
            bool safest = !transmission->handshaked_.load(std::memory_order_acquire);
            AppConfigurationPtr cfg = transmission->configuration_;
            const auto& alloc = transmission->BufferAllocator;
            CiphertextPtr protocol = std::atomic_load(&transmission->protocol_);
            CiphertextPtr transport = std::atomic_load(&transmission->transport_);

            if (protocol && transport) {
                return Transmission_Packet_Encrypt(cfg, alloc, protocol,
                    transport, data, datalen, outlen, safest);
            }
            else {
                return Transmission_Packet_Encrypt(cfg, alloc, NULLPTR, NULLPTR,
                    data, datalen, outlen, safest);
            }
        }

        /**
         * @brief Decrypts payload via packet decryption path selected by cipher state.
         */
        std::shared_ptr<Byte> ITransmissionBridge::DecryptBinary(ITransmission* transmission, Byte* data, int datalen, int& outlen) noexcept {
            bool safest = !transmission->handshaked_.load(std::memory_order_acquire);
            AppConfigurationPtr cfg = transmission->configuration_;
            const auto& alloc = transmission->BufferAllocator;
            CiphertextPtr protocol = std::atomic_load(&transmission->protocol_);
            CiphertextPtr transport = std::atomic_load(&transmission->transport_);

            if (protocol && transport) {
                return Transmission_Packet_Decrypt(cfg, alloc, protocol,
                    transport, data, datalen, outlen, safest);
            }
            else {
                return Transmission_Packet_Decrypt(cfg, alloc, NULLPTR, NULLPTR,
                    data, datalen, outlen, safest);
            }
        }

    } // namespace transmissions
} // namespace ppp
