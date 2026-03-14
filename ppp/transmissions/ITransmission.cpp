#include <ppp/transmissions/ITransmission.h>      
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

namespace ppp {
    namespace transmissions {
        // Type aliases to simplify code and improve readability
        typedef ITransmission::AppConfigurationPtr      AppConfigurationPtr;   
        typedef ITransmission::CiphertextPtr            CiphertextPtr;         
        typedef ppp::net::Socket                        Socket;                
        typedef ppp::threading::Thread                  Thread;                
        typedef ppp::cryptography::ssea                 ssea;                  
        typedef ppp::io::Stream                         Stream;                
        typedef ppp::io::MemoryStream                   MemoryStream;          
        typedef ITransmission::YieldContext             YieldContext;          
        typedef ppp::threading::BufferswapAllocator     BufferswapAllocator;   

        // Header size constants used in packet encryption/decryption
        static constexpr int                            EVP_HEADER_TSS = 2;    // Size of encrypted length field (2 bytes)
        static constexpr int                            EVP_HEADER_MSS = EVP_HEADER_TSS + 1; // 3 bytes: total header size after first byte
        static constexpr int                            EVP_HEADER_XSS = EVP_HEADER_MSS + 1; // 4 bytes: full header with first random byte

        // Forward declaration of a helper function that reads and decrypts a packet from the transmission
        static std::shared_ptr<Byte>                    Transmission_Packet_Read(
            const AppConfigurationPtr&                  APP,                   // Application configuration
            const std::shared_ptr<BufferswapAllocator>& allocator,            // Buffer allocator
            const CiphertextPtr&                        EVP_protocol,         // Protocol-layer cipher (optional)
            const CiphertextPtr&                        EVP_transport,        // Transport-layer cipher (optional)
            int&                                        outlen,               // Output length of decrypted data
            ITransmission*                              transmission,         // Transmission instance
            YieldContext&                               y,                    // Coroutine yield context
            bool                                        safest) noexcept;     // Whether to use safest mode (pre-handshake)

        // Bridge class that encapsulates low-level I/O and encryption operations for ITransmission
        class ITransmissionBridge final {
        public:
            // Reads a raw byte array of given length from the transmission (no decryption)
            static std::shared_ptr<Byte>                ReadBytes(ITransmission* transmission, YieldContext& y, int length) noexcept {
                return transmission->DoReadBytes(y, length);
            }

            // Reads a binary message from the transmission, applying appropriate decryption based on handshake state
            static std::shared_ptr<Byte>                ReadBinary(ITransmission* transmission, YieldContext& y, int& outlen) noexcept {
                bool safest = !transmission->handshaked_;                     // Before handshake, use safest mode
                CiphertextPtr EVP_protocol = transmission->protocol_;         // Protocol cipher (may be null)
                CiphertextPtr EVP_transport = transmission->transport_;       // Transport cipher (may be null)

                const std::shared_ptr<BufferswapAllocator>& allocator = transmission->BufferAllocator;
                if (EVP_protocol && EVP_transport) {
                    // Both ciphers present: use full packet decryption
                    return Transmission_Packet_Read(transmission->configuration_, allocator, EVP_protocol, EVP_transport, outlen, transmission, y, safest);
                }
                else {
                    // No ciphers: use plain packet decryption (only header/payload transformations)
                    return Transmission_Packet_Read(transmission->configuration_, allocator, NULLPTR, NULLPTR, outlen, transmission, y, safest);
                }
            }

        public:
            // Encrypts binary data (without base94 encoding) using the transmission's ciphers
            static std::shared_ptr<Byte>                EncryptBinary(ITransmission* transmission, Byte* data, int datalen, int& outlen) noexcept;
            
            // Decrypts binary data (without base94 decoding) using the transmission's ciphers
            static std::shared_ptr<Byte>                DecryptBinary(ITransmission* transmission, Byte* data, int datalen, int& outlen) noexcept;

        public:
            // Encrypts data with optional base94 encoding (if plaintext mode is active)
            static std::shared_ptr<Byte>                Encrypt(ITransmission* transmission, Byte* data, int datalen, int& outlen) noexcept {
                std::shared_ptr<Byte> packet = EncryptBinary(transmission, data, datalen, outlen);
                if (NULLPTR != packet) {
                    AppConfigurationPtr& configuration = transmission->configuration_;
                    // If handshake not done or plaintext mode enabled, apply base94 encoding
                    if (!transmission->handshaked_ || configuration->key.plaintext) {
                        packet = base94_encode(transmission, configuration, transmission->BufferAllocator,
                            packet.get(), outlen, configuration->key.kf, outlen);
                    }
                }

                if (NULLPTR != packet) {
                    return packet;
                }
                else {
                    outlen = 0;
                    return packet;
                }
            }

            // Decrypts data with optional base94 decoding (if plaintext mode is active)
            static std::shared_ptr<Byte>                Decrypt(ITransmission* transmission, Byte* data, int datalen, int& outlen) noexcept {
                std::shared_ptr<Byte> packet;
                AppConfigurationPtr& configuration = transmission->configuration_;

                if (!transmission->handshaked_ || configuration->key.plaintext) {
                    // Apply base94 decoding first, then binary decryption
                    packet = base94_decode(configuration, transmission->BufferAllocator,
                        data, datalen, configuration->key.kf, outlen);
                    packet = DecryptBinary(transmission, packet.get(), outlen, outlen);
                }
                else {
                    // Direct binary decryption
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

            // Reads a message from the transmission, applying base94 decoding if needed
            static std::shared_ptr<Byte>                Read(ITransmission* transmission, YieldContext& y, int& outlen) noexcept {
                outlen = 0;
                if (transmission->disposed_) {
                    return NULLPTR;
                }

                std::shared_ptr<Byte> packet;
                AppConfigurationPtr& configuration = transmission->configuration_;

                if (!transmission->handshaked_ || configuration->key.plaintext) {
                    // Read and base94 decode, then binary decrypt
                    packet = base94_decode(transmission, y, outlen);
                    packet = DecryptBinary(transmission, packet.get(), outlen, outlen);
                }
                else {
                    // Read directly as binary (already encrypted)
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

#if defined(_WIN32)
#pragma optimize("", off)
#pragma optimize("gsyb2", on) /* Enable optimizations similar to /O1 on Windows */
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
            // Writes a packet to the transmission asynchronously, with coroutine support.
            // This function must not be optimized above O1 due to compiler bugs.
            static bool                                 Write(ITransmission* transmission, YieldContext& y, const void* packet, int packet_length) noexcept {
                using AsynchronousWriteCallback = ITransmission::AsynchronousWriteCallback;

                if (transmission->disposed_) {
                    return false;
                }

                YieldContext* co = y.GetPtr();
                if (NULLPTR != co) {
                    // If inside a coroutine, use DoWriteYield to handle async write
                    return transmission->DoWriteYield<AsynchronousWriteCallback>(*co, packet, packet_length,
                        [transmission](const void* packet, int packet_length, const AsynchronousWriteCallback& cb) noexcept {
                            return ITransmissionBridge::Write(transmission, packet, packet_length, cb);
                        });
                }
                else {
                    // Direct synchronous-like write (with callback)
                    return ITransmissionBridge::Write(transmission, packet, packet_length,
                        [transmission](bool ok) noexcept {
                            if (!ok) {
                                transmission->Dispose();
                            }
                        });
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

            // Low-level write: encrypts the packet and calls WriteBytes on the transmission
            static bool                                 Write(ITransmission* transmission, const void* packet, int packet_length, const ITransmission::AsynchronousWriteBytesCallback& cb) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    return false;
                }

                if (NULLPTR == cb) {
                    return false;
                }

                if (transmission->disposed_) {
                    return false;
                }

                int messages_size = 0;
                std::shared_ptr<Byte> messages = Encrypt(transmission, (Byte*)packet, packet_length, messages_size);
                if (NULLPTR == messages) {
                    return false;
                }

                return transmission->WriteBytes(messages, messages_size, cb);
            }

        private:
            // Encodes the length field for base94 mode, generating a variable-length header
            static ppp::string                          base94_encode_length(ITransmission* transmission, const AppConfigurationPtr& configuration, int length, int kf) noexcept {
                // FORMULA: (N + KF_MOD) % MOD
                const int EVP_HEADER_MSS_MOD = configuration->Lcgmod(ITransmission::AppConfiguration::LCGMOD_TYPE_TRANSMISSION);
                const int KF_MOD = abs(kf % EVP_HEADER_MSS_MOD);
                int N = (length + KF_MOD) % EVP_HEADER_MSS_MOD;

                ppp::string d = ssea::base94_decimal(N);          // Convert to base94 string
                int dl = d.size();

                if (dl < 1) {
                    return ppp::string();
                }

                if (dl >= EVP_HEADER_XSS) {
                    return ppp::string();
                }

                Byte h[EVP_HEADER_XSS + EVP_HEADER_MSS];          // Buffer for full header (max 4+3=7 bytes)
                *((int*)h) = 0x20202020;                          // Initialize with spaces

                Byte& k = h[0];                                    // First byte: random key byte
                Byte& f = h[1];                                    // Second byte: random filler
                memcpy(h + (EVP_HEADER_XSS - dl), d.data(), dl);   // Place base94 length at the end of 4-byte area

                k = RandomNext('\x20', '\x7e');                    // Random printable character
                if (f == '\x20') {
                    int v = k & '\x01';
                    if (v != '\x00') {
                        ++k;
                    }

                    f = RandomNext('\x20', '\x7e');
                }
                elif((k & '\x01') == '\x00') {
                    if (++k > '\x7e') {
                        k = '\x21';
                    }
                }

                std::swap(h[2], h[3]);                              // Swap bytes 2 and 3 for obfuscation

                if (transmission->frame_tn_) {
                    // Use simple header (only 4 bytes) if frame_tn_ is true
                    return ppp::string(reinterpret_cast<char*>(h), EVP_HEADER_XSS);
                }
                else {
                    // Use extended header (4+3 bytes) with checksum
                    int K = ppp::net::native::inet_chksum(h, EVP_HEADER_XSS) ^ length;

                    N = (K + KF_MOD) % EVP_HEADER_MSS_MOD;
                    d = ssea::base94_decimal(N);

                    if (d.size() != EVP_HEADER_MSS) {
                        return ppp::string();
                    }

                    Byte* pbc = h + EVP_HEADER_XSS;
                    transmission->frame_tn_ = true;

                    memcpy(pbc, d.data(), EVP_HEADER_MSS);
                    ssea::shuffle_data((char*)pbc, EVP_HEADER_MSS, kf);   // Shuffle the extra bytes

                    return ppp::string(reinterpret_cast<char*>(h), sizeof(h));
                }
            }

            // Decodes the length from a base94 header
            static int                                  base94_decode_length(const AppConfigurationPtr& configuration, Byte* data, int kf) noexcept {
                // FORMULA: (N - KF_MOD + MOD) % MOD
                const int EVP_HEADER_MSS_MOD = configuration->Lcgmod(ITransmission::AppConfiguration::LCGMOD_TYPE_TRANSMISSION);
                const int N = ssea::base94_decimal(data, EVP_HEADER_MSS);
                const int KF_MOD = abs(kf % EVP_HEADER_MSS_MOD);

                return (N - KF_MOD + EVP_HEADER_MSS_MOD) % EVP_HEADER_MSS_MOD;
            }

        private:
            // Resets the first two bytes of a header to default values after reading
            static void                                 base94_decode_kf(Byte* h) noexcept {
                Byte& k = h[0];
                Byte& f = h[1];
                if ((k & '\x01') == '\x00') {
                    f = '\x20';
                }

                k = '\x20';
                std::swap(h[2], h[3]);
            }

            // Encodes data using base94 and prepends a length header
            static std::shared_ptr<Byte>                base94_encode(ITransmission* transmission, const AppConfigurationPtr& configuration, const std::shared_ptr<BufferswapAllocator>& allocator, Byte* data, int datalen, int kf, int& outlen) noexcept {
                std::shared_ptr<Byte> payload = ssea::base94_encode(allocator, data, datalen, kf, outlen);
                if (NULLPTR == payload) {
                    return NULLPTR;
                }

                ppp::string k = base94_encode_length(transmission, configuration, outlen, kf);
                if (k.size() < EVP_HEADER_XSS) {
                    return NULLPTR;
                }

                int k_size = k.size();
                int packet_length = outlen + k_size;

                std::shared_ptr<Byte> packet = BufferswapAllocator::MakeByteArray(allocator, packet_length);
                if (NULLPTR == packet) {
                    return NULLPTR;
                }

                Byte* memory = packet.get();
                memcpy(memory, k.data(), k_size);
                memcpy(memory + k_size, payload.get(), outlen);

                outlen = packet_length;
                return packet;
            }

            // Decodes base94 data after reading and verifying the header
            static std::shared_ptr<Byte>                base94_decode(const AppConfigurationPtr& configuration, const std::shared_ptr<BufferswapAllocator>& allocator, Byte* data, int datalen, int kf, int& outlen) noexcept {
                outlen = 0;

                if (NULLPTR == data || datalen < EVP_HEADER_XSS) {
                    return NULLPTR;
                }
                else {
                    base94_decode_kf(data);   // Restore header fields
                }

                int payload_length = base94_decode_length(configuration, data, kf);
                if (payload_length < 1) {
                    return NULLPTR;
                }

                if ((payload_length + EVP_HEADER_XSS) != datalen) {
                    return NULLPTR;
                }

                Byte* payload = data + EVP_HEADER_XSS;
                return ssea::base94_decode(allocator, payload, payload_length, kf, outlen);
            }

            // Reads and decodes length from a simple header (frame_rn_ mode)
            static int                                  base94_decode_length_rn(ITransmission* transmission, YieldContext& y) noexcept {
                std::shared_ptr<Byte> packet = ReadBytes(transmission, y, EVP_HEADER_XSS);
                if (NULLPTR == packet) {
                    return -1;
                }

                Byte* data = packet.get();
                AppConfigurationPtr& configuration = transmission->configuration_;
                base94_decode_kf(data);

                int payload_length = base94_decode_length(configuration, data + 1, configuration->key.kf);
                return payload_length > 0 ? payload_length : -1;
            }

            // Reads and decodes length from an extended header (with checksum)
            static int                                  base94_decode_length_r1(ITransmission* transmission, YieldContext& y) noexcept {
                std::shared_ptr<Byte> packet = ReadBytes(transmission, y, EVP_HEADER_XSS + EVP_HEADER_MSS);
                if (NULLPTR == packet) {
                    return -1;
                }

                Byte* data = packet.get();
                int K = ppp::net::native::inet_chksum(data, EVP_HEADER_XSS);

                AppConfigurationPtr& configuration = transmission->configuration_;
                base94_decode_kf(data);

                int payload_length = base94_decode_length(configuration, data + 1, configuration->key.kf);
                if (payload_length < 1) {
                    return -1;
                }

                Byte* pbc = data + EVP_HEADER_XSS;
                ssea::shuffle_data((char*)pbc, EVP_HEADER_MSS, configuration->key.kf);

                int N = base94_decode_length(configuration, pbc, configuration->key.kf);
                K = K ^ payload_length;

                if (N != K) {
                    return -1;
                }

                transmission->frame_rn_ = true;   // Switch to simple header mode for subsequent reads
                return payload_length;
            }

            // Determines which header format to use and reads the length
            static int                                  base94_decode_length(ITransmission* transmission, YieldContext& y) noexcept {
                if (transmission->frame_rn_) {
                    return base94_decode_length_rn(transmission, y);
                }

                return base94_decode_length_r1(transmission, y);
            }

            // Reads a full base94-encoded message from the transmission
            static std::shared_ptr<Byte>                base94_decode(ITransmission* transmission, YieldContext& y, int& outlen) noexcept {
                outlen = 0;

                int payload_length = base94_decode_length(transmission, y);
                if (payload_length < 1) {
                    return NULLPTR;
                }

                std::shared_ptr<Byte> packet = ReadBytes(transmission, y, payload_length);
                if (NULLPTR == packet) {
                    return NULLPTR;
                }

                AppConfigurationPtr& configuration = transmission->configuration_;
                return ssea::base94_decode(transmission->BufferAllocator,
                    packet.get(),
                    payload_length,
                    configuration->key.kf,
                    outlen);
            }
        };

        // ==================== Packet Encryption/Decryption Helpers ====================

        // Encrypts the packet header (length field) using protocol cipher and obfuscation
        static std::shared_ptr<Byte>                    Transmission_Header_Encrypt(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            const CiphertextPtr&                        EVP_protocol,
            int                                         EVP_payload_length,
            int&                                        EVP_header_length,
            int&                                        EVP_header_kf) noexcept {

            // Packet Alignment: 65536 -> 65535
            if (--EVP_payload_length < 0) {
                return NULLPTR;
            }

            Byte EVP_payload_length_array[EVP_HEADER_MSS] = {
                (Byte)(RandomNext(0x01, 0xff)),     // Variable frame word (used as key seed)
                (Byte)(EVP_payload_length >> 0x08), // High-order byte of length
                (Byte)(EVP_payload_length & 0xff),  // Low-order byte of length
            };

            int EVP_header_datalen = sizeof(EVP_payload_length_array);
            EVP_header_kf = APP->key.kf ^ *EVP_payload_length_array;   // Derive key for further obfuscation

            // Byte encryption using protocol cipher (if available)
            if (EVP_protocol) {
                std::shared_ptr<Byte> EVP_header_length_buff = EVP_protocol->Encrypt(allocator, EVP_payload_length_array + 1, EVP_HEADER_TSS, EVP_header_length);
                if (NULLPTR == EVP_header_length_buff || EVP_header_length != EVP_HEADER_TSS) {
                    return NULLPTR;
                }

                memcpy(EVP_payload_length_array + 1, EVP_header_length_buff.get(), EVP_HEADER_TSS);
            }

            // Mask encryption: XOR with header key
            for (int i = 1; i < EVP_HEADER_MSS; i++) {
                EVP_payload_length_array[i] ^= EVP_header_kf;
            }

            // Shuffle the two length bytes
            EVP_header_length = sizeof(EVP_payload_length_array);
            ssea::shuffle_data(reinterpret_cast<char*>(EVP_payload_length_array + 1), EVP_HEADER_TSS, EVP_header_kf);

            // Delta encoding (compression/obfuscation)
            std::shared_ptr<Byte> output;
            return ssea::delta_encode(allocator, EVP_payload_length_array, EVP_header_datalen, APP->key.kf, output) != EVP_header_length ? NULLPTR : output;
        }

        // Decrypts the packet header to retrieve the original payload length
        static int                                      Transmission_Header_Decrypt(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            const CiphertextPtr&                        EVP_protocol,
            Byte*                                       EVP_header_array,
            int&                                        EVP_header_kf) noexcept {

            // Delta decode
            std::shared_ptr<Byte> EVP_payload_length_array_managed;
            if (ssea::delta_decode(allocator, EVP_header_array, EVP_HEADER_MSS, APP->key.kf, EVP_payload_length_array_managed) != EVP_HEADER_MSS) {
                return 0;
            }

            // Restore original array
            Byte* EVP_payload_length_array = EVP_payload_length_array_managed.get();
            EVP_header_kf = APP->key.kf ^ *EVP_payload_length_array;
            ssea::unshuffle_data(reinterpret_cast<char*>(EVP_payload_length_array + 1), EVP_HEADER_TSS, EVP_header_kf);

            // Reverse mask
            for (int i = 1; i < EVP_HEADER_MSS; i++) {
                EVP_payload_length_array[i] ^= EVP_header_kf;
            }

            // Decrypt using protocol cipher if available
            int EVP_header_length = 0;
            if (EVP_protocol) {
                std::shared_ptr<Byte> EVP_header_length_buff = EVP_protocol->Decrypt(allocator, EVP_payload_length_array + 1, EVP_HEADER_TSS, EVP_header_length);
                if (NULLPTR == EVP_header_length_buff || EVP_header_length != EVP_HEADER_TSS) {
                    return 0;
                }

                memcpy(EVP_payload_length_array + 1, EVP_header_length_buff.get(), EVP_HEADER_TSS);
            }

            // Reconstruct length (note: we subtracted 1 during encryption)
            EVP_header_length = EVP_payload_length_array[1] << 0x08 | EVP_payload_length_array[2];
            return EVP_header_length + 1;
        }

        // Partial encryption of payload: mask and shuffle (no delta)
        static void                                     Transmission_Payload_Encrypt_Partial(
            const AppConfigurationPtr&                  APP,
            int                                         kf,
            Byte*                                       data,
            int                                         datalen,
            bool                                        safest) noexcept {

            // Mask encryption (XOR with pseudo-random sequence)
            if (safest || APP->key.masked) {
                ssea::masked_xor_random_next(data, data + datalen, kf);
            }

            // Shuffle data bytes
            if (safest || APP->key.shuffle_data) {
                ssea::shuffle_data(reinterpret_cast<char*>(data), datalen, kf);
            }
        }

        // Full payload encryption: partial + delta encoding
        static std::shared_ptr<Byte>                    Transmission_Payload_Encrypt(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            int                                         kf,
            Byte*                                       data,
            int                                         datalen,
            int&                                        outlen,
            bool                                        safest) noexcept {

            outlen = datalen;
            Transmission_Payload_Encrypt_Partial(APP, kf, data, datalen, safest);

            // Delta encoding (optional)
            std::shared_ptr<Byte> output;
            if (safest || APP->key.delta_encode) {
                return ssea::delta_encode(allocator, data, datalen, APP->key.kf, output) != datalen ? NULLPTR : output;
            }
            else {
                output = BufferswapAllocator::MakeByteArray(allocator, datalen);
                if (NULLPTR == output) {
                    return NULLPTR;
                }
                else {
                    memcpy(output.get(), data, datalen);
                    return output;
                }
            }
        }

        // Partial decryption of payload: unshuffle and unmask
        static void                                     Transmission_Payload_Decrypt_Partial(
            const AppConfigurationPtr&                  APP,
            int                                         kf,
            Byte*                                       data,
            int                                         datalen,
            bool                                        safest) noexcept {

            // Unshuffle
            if (safest || APP->key.shuffle_data) {
                ssea::unshuffle_data(reinterpret_cast<char*>(data), datalen, kf);
            }

            // Unmask (XOR again)
            if (safest || APP->key.masked) {
                ssea::masked_xor_random_next(data, data + datalen, kf);
            }
        }

        // Full payload decryption: delta decode + partial
        static std::shared_ptr<Byte>                    Transmission_Payload_Decrypt(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            int                                         kf,
            const std::shared_ptr<Byte>&                data,
            int                                         datalen,
            int&                                        outlen,
            bool                                        safest) noexcept {

            outlen = datalen;
            if (safest || APP->key.delta_encode) {
                std::shared_ptr<Byte> EVP_payload_array_managed; // Delta decode
                if (ssea::delta_decode(allocator, data.get(), datalen, APP->key.kf, EVP_payload_array_managed) != datalen) {
                    return NULLPTR;
                }

                Transmission_Payload_Decrypt_Partial(APP, kf, EVP_payload_array_managed.get(), datalen, safest);
                return EVP_payload_array_managed;
            }
            else {
                Transmission_Payload_Decrypt_Partial(APP, kf, data.get(), datalen, safest);
                return data;
            }
        }

        // Combines header and payload into a single packet buffer
        static std::shared_ptr<Byte>                    Transmission_Packet_Pack(
            const std::shared_ptr<BufferswapAllocator>& allocator,
            const std::shared_ptr<Byte>&                EVP_header,
            int                                         EVP_header_length,
            const std::shared_ptr<Byte>&                EVP_payload,
            int                                         EVP_payload_length,
            int&                                        EVP_packet_length) noexcept {

            EVP_packet_length = EVP_header_length + EVP_payload_length;

            std::shared_ptr<Byte> packet = BufferswapAllocator::MakeByteArray(allocator, EVP_packet_length);
            if (NULLPTR == packet) {
                return NULLPTR;
            }

            Byte* memory = packet.get();
            memcpy(memory, EVP_header.get(), EVP_header_length);
            memcpy(memory + EVP_header_length, EVP_payload.get(), EVP_payload_length);
            return packet;
        }

        // Full packet encryption: header + payload (with optional transport cipher)
        static std::shared_ptr<Byte>                    Transmission_Packet_Encrypt(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            const CiphertextPtr&                        EVP_protocol,
            const CiphertextPtr&                        EVP_transport,
            Byte*                                       data,
            int                                         datalen,
            int&                                        outlen,
            bool                                        safest) noexcept {

            int EVP_payload_length = 0;
            int EVP_header_kf = 0;
            int EVP_header_length = 0;

            outlen = 0;
            if (EVP_protocol && EVP_transport) {
                // Step 1: Transport encryption (A)
                std::shared_ptr<Byte> EVP_payload = EVP_transport->Encrypt(allocator, data, datalen, EVP_payload_length);
                if (NULLPTR == EVP_payload || EVP_payload_length != datalen) {
                    return NULLPTR;
                }

                // Step 2: Header encryption (using protocol cipher)
                std::shared_ptr<Byte> EVP_header = Transmission_Header_Encrypt(APP, allocator, EVP_protocol, EVP_payload_length, EVP_header_length, EVP_header_kf);
                if (NULLPTR == EVP_header) {
                    return NULLPTR;
                }

                // Step 3: Payload obfuscation (B) using header-derived key
                EVP_payload = Transmission_Payload_Encrypt(APP, allocator, EVP_header_kf, EVP_payload.get(), datalen, EVP_payload_length, safest);
                if (NULLPTR == EVP_payload) {
                    return NULLPTR;
                }
                else {
                    return Transmission_Packet_Pack(allocator, EVP_header, EVP_header_length, EVP_payload, EVP_payload_length, outlen);
                }
            }
            else {
                // No transport cipher: only header and payload obfuscation
                std::shared_ptr<Byte> EVP_header = Transmission_Header_Encrypt(APP, allocator, EVP_protocol, datalen, EVP_header_length, EVP_header_kf);
                if (NULLPTR == EVP_header) {
                    return NULLPTR;
                }

                std::shared_ptr<Byte> EVP_payload = Transmission_Payload_Encrypt(APP, allocator, EVP_header_kf, data, datalen, EVP_payload_length, safest);
                if (NULLPTR == EVP_payload) {
                    return NULLPTR;
                }
                else {
                    return Transmission_Packet_Pack(allocator, EVP_header, EVP_header_length, EVP_payload, EVP_payload_length, outlen);
                }
            }
        }

        // Full packet decryption: header + payload (with optional transport cipher)
        static std::shared_ptr<Byte>                    Transmission_Packet_Decrypt(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            const CiphertextPtr&                        EVP_protocol,
            const CiphertextPtr&                        EVP_transport,
            Byte*                                       data,
            int                                         datalen,
            int&                                        outlen,
            bool                                        safest) noexcept {

            int EVP_header_kf = 0;
            outlen = 0;

            if (datalen <= EVP_HEADER_MSS) {
                return NULLPTR;
            }

            // Decrypt header to get payload length
            int EVP_payload_length = Transmission_Header_Decrypt(APP, allocator, EVP_protocol, data, EVP_header_kf);
            if (EVP_payload_length < 1) {
                return NULLPTR;
            }

            int EVP_packet_length = EVP_payload_length + EVP_HEADER_MSS;
            if (EVP_packet_length != datalen) {
                return NULLPTR;
            }

            // Extract payload
            std::shared_ptr<Byte> EVP_payload = BufferswapAllocator::MakeByteArray(allocator, EVP_payload_length);
            if (NULLPTR == EVP_payload) {
                return NULLPTR;
            }
            else {
                memcpy(EVP_payload.get(), data + EVP_HEADER_MSS, EVP_payload_length);
            }

            // Decrypt payload obfuscation
            EVP_payload = Transmission_Payload_Decrypt(APP, allocator, EVP_header_kf, EVP_payload, EVP_payload_length, outlen, safest);
            if (NULLPTR == EVP_payload) {
                return NULLPTR;
            }

            // If transport cipher present, apply it
            if (EVP_protocol && EVP_transport) {
                EVP_payload = EVP_transport->Decrypt(allocator, EVP_payload.get(), EVP_payload_length, outlen);
                if (NULLPTR == EVP_payload || EVP_payload_length != outlen) {
                    return NULLPTR;
                }
            }

            return EVP_payload;
        }

        // Reads a packet from the transmission and decrypts it (used by ReadBinary)
        static std::shared_ptr<Byte>                    Transmission_Packet_Read(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            const CiphertextPtr&                        EVP_protocol,
            const CiphertextPtr&                        EVP_transport,
            int&                                        outlen,
            ITransmission*                              transmission,
            YieldContext&                               y,
            bool                                        safest) noexcept {

            int EVP_header_kf = 0;
            outlen = 0;

            // Read header (fixed size)
            std::shared_ptr<Byte> EVP_header = ITransmissionBridge::ReadBytes(transmission, y, EVP_HEADER_MSS);
            if (NULLPTR == EVP_header) {
                return NULLPTR;
            }

            // Decrypt header to get payload length
            int EVP_payload_length = Transmission_Header_Decrypt(APP, allocator, EVP_protocol, EVP_header.get(), EVP_header_kf);
            if (EVP_payload_length < 1) {
                return NULLPTR;
            }

            // Read payload
            std::shared_ptr<Byte> EVP_payload = ITransmissionBridge::ReadBytes(transmission, y, EVP_payload_length);
            if (NULLPTR == EVP_payload) {
                return NULLPTR;
            }

            // Decrypt payload obfuscation
            EVP_payload = Transmission_Payload_Decrypt(APP, allocator, EVP_header_kf, EVP_payload, EVP_payload_length, outlen, safest);
            if (NULLPTR == EVP_payload) {
                return NULLPTR;
            }

            // If transport cipher present, apply it
            if (EVP_protocol && EVP_transport) {
                EVP_payload = EVP_transport->Decrypt(allocator, EVP_payload.get(), EVP_payload_length, outlen);
                if (NULLPTR == EVP_payload || EVP_payload_length != outlen) {
                    return NULLPTR;
                }
            }

            return EVP_payload;
        }

        // ==================== Handshake Helpers ====================

        // Packs a session ID into a handshake packet (with obfuscation)
        static std::shared_ptr<Byte>                    Transmission_Handshake_Pack_SessionId(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            Int128                                      session_id,
            int&                                        packet_length) noexcept {

            Byte kfs[4];
            packet_length = 0;

            ppp::string session_id_string;
            if (session_id) {
                kfs[0] = RandomNext(0x00, 0x7f);          // First byte < 0x80 indicates real session ID
                session_id_string = stl::to_string<ppp::string>(session_id);
            }
            else {
                kfs[0] = RandomNext(0x80, 0xff);          // First byte >= 0x80 indicates dummy packet (for NOP)
                int64_t v1 = (int64_t)RandomNext() << 32 | (int64_t)(uint32_t)RandomNext();
                int64_t v2 = (int64_t)RandomNext() << 32 | (int64_t)(uint32_t)RandomNext();
                session_id_string = stl::to_string<ppp::string>(MAKE_OWORD(v2, v1));
            }

            kfs[1] = RandomNext(0x01, 0xff);
            kfs[2] = RandomNext(0x01, 0xff);
            kfs[3] = RandomNext(0x01, 0xff);
            session_id_string.append(1, RandomNext(0x20, 0x2F));   // Append a random separator

            // Add random padding to confuse traffic analysis
            int max = APP->key.kx % 0x100;
            if (max > 0) {
                int i = 0;
                for (; i < max; i++) {
                    session_id_string.append(1, RandomNext(0x20, 0x7e));
                }

                if (i == max) {
                    session_id_string.append(1, '/');
                }

                int min = session_id_string.size() + sizeof(kfs);
                if (min > max) {
                    max = min;
                }

                int max_loops = RandomNext(1, max << 2);
                for (int i = 0; i < max_loops; i++) {
                    session_id_string.append(1, RandomNext(0x20, 0x7e));
                }
            }

            Byte* packet = (Byte*)session_id_string.data();
            packet_length = session_id_string.size();

            // Obfuscation: XOR with key derived from kfs
            int kf = APP->key.kf;
            for (int i = 0; i < arraysizeof(kfs); i++) {
                kf ^= kfs[i];
                for (int j = 0; j < packet_length; j++) {
                    packet[j] ^= kf;
                }
            }

            // Prepend the four kfs bytes
            std::shared_ptr<Byte> messages = BufferswapAllocator::MakeByteArray(allocator, packet_length += sizeof(kfs));
            if (NULLPTR == messages) {
                return NULLPTR;
            }

            Byte* memory = messages.get();
            memcpy(memory, kfs, sizeof(kfs));
            memcpy(memory + sizeof(kfs), packet, session_id_string.size());
            return messages;
        }

        // Unpacks a session ID from a handshake packet
        static Int128                                   Transmission_Handshake_Unpack_SessionId(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<Byte>&                packet_managed,
            int                                         packet_length,
            bool&                                       eagin) noexcept {

            eagin = false;
            if (NULLPTR == packet_managed) {
                return 0;
            }

            if (packet_length < 4) {
                return 0;
            }

            // If the first byte's high bit is set, it's a dummy packet (eagin)
            Byte* packet = packet_managed.get();
            if (*packet & 0x80) {
                eagin = true;          // Indicates we should ignore and continue
                return 0;
            }

            Byte kfs[] = { packet[0], packet[1], packet[2], packet[3] }; // Extract keys
            packet += sizeof(kfs);
            packet_length -= sizeof(kfs);
            if (packet_length < 1) {
                return 0;
            }

            // Reverse obfuscation
            int kf = APP->key.kf;
            for (int i = 0; i < arraysizeof(kfs); i++) {
                kf ^= kfs[i];
                for (int j = 0; j < packet_length; j++) {
                    packet[j] ^= kf;
                }
            }

            // Convert remaining data to integer (session ID)
            Int128 session_id = stl::to_number<Int128>(std::string_view(reinterpret_cast<char*>(packet), packet_length), 10);
            return session_id;
        }

        // Sends a session ID packet during handshake
        static bool                                     Transmission_Handshake_SessionId(
            const AppConfigurationPtr&                  APP,
            ITransmission*                              transmission,
            ITransmission::YieldContext&                y,
            const Int128&                               session_id) noexcept {

            int packet_length = 0;
            std::shared_ptr<Byte> packet_managed = Transmission_Handshake_Pack_SessionId(APP,
                transmission->BufferAllocator, session_id, packet_length);
            if (NULLPTR == packet_managed) {
                return false;
            }

            return ITransmissionBridge::Write(transmission, y, packet_managed.get(), packet_length);
        }

        // Receives a session ID packet during handshake
        static Int128                                   Transmission_Handshake_SessionId(
            const AppConfigurationPtr&                  APP,
            ITransmission*                              transmission,
            ITransmission::YieldContext&                y) noexcept {

            bool eagin = false;
            for (;;) {
                // Read a message (with full decryption, including base94 if needed)
                int packet_length = 0;
                std::shared_ptr<Byte> packet_managed = ITransmissionBridge::Read(transmission, y, packet_length);
                if (NULLPTR == packet_managed) {
                    return 0;
                }

                Int128 session_id = Transmission_Handshake_Unpack_SessionId(APP, packet_managed, packet_length, eagin);
                if (eagin) {
                    continue;   // Dummy packet, read next
                }

                return session_id;
            }
        }

        // Sends a series of dummy packets (NOP) to simulate traffic and evade firewalls
        bool                                            Transmission_Handshake_Nop(
            const AppConfigurationPtr&                  APP,
            ITransmission*                              transmission,
            ITransmission::YieldContext&                y) noexcept {

            int roundof = 0;
            int kl = std::max<int>(0, 1 << APP->key.kl);
            int kh = std::max<int>(0, 1 << APP->key.kh);
            if (kl > kh) {
                std::swap(kl, kh);
            }

            if (kl == kh) {
                roundof = kl;
            }
            else {
                roundof = RandomNext(kl, kh);
            }

            // Scale down to a reasonable number of rounds
            roundof = ceil(roundof / (double)(175 << 3));
            for (int i = 0; i < roundof; i++) {
                if (!Transmission_Handshake_SessionId(APP, transmission, y, 0)) {
                    return false;
                }
            }

            return true;
        }

        // ==================== ITransmission Implementation ====================

        // Constructor: initializes transmission with context, strand, and configuration
        ITransmission::ITransmission(const ContextPtr& context, const StrandPtr& strand, const AppConfigurationPtr& configuration) noexcept
            : IAsynchronousWriteIoQueue(NULLPTR != configuration ? configuration->GetBufferAllocator() : NULLPTR)
            , disposed_(false)
            , frame_rn_(false)
            , frame_tn_(false)
            , handshaked_(false)
            , context_(context)
            , strand_(strand)
            , configuration_(configuration) {

            // Create cipher objects if supported by configuration
            if (ppp::configurations::extensions::IsHaveCiphertext(configuration.get())) {
                if (Ciphertext::Support(configuration->key.protocol) && Ciphertext::Support(configuration->key.transport)) {
                    protocol_ = make_shared_object<Ciphertext>(configuration->key.protocol, configuration->key.protocol_key);
                    transport_ = make_shared_object<Ciphertext>(configuration->key.transport, configuration->key.transport_key);
                }
            }
        }

        // Destructor: calls Finalize
        ITransmission::~ITransmission() noexcept {
            Finalize();
        }

        // Cleans up resources, cancels timers, resets state
        void ITransmission::Finalize() noexcept {
            DeadlineTimerPtr timeout = std::move(timeout_);
            timeout_.reset();

            disposed_ = true;
            handshaked_ = false;
            QoS.reset();
            Statistics.reset();

            if (NULLPTR != timeout) {
                Socket::Cancel(*timeout);
            }
        }

        // Public read method (coroutine-aware)
        std::shared_ptr<Byte> ITransmission::Read(YieldContext& y, int& outlen) noexcept {
            return ITransmissionBridge::Read(this, y, outlen);
        }

        // Public write method (coroutine-aware)
        bool ITransmission::Write(YieldContext& y, const void* packet, int packet_length) noexcept {
            return ITransmissionBridge::Write(this, y, packet, packet_length);
        }

        // Asynchronous write with callback
        bool ITransmission::Write(const void* packet, int packet_length, const AsynchronousWriteCallback& cb) noexcept {
            return ITransmissionBridge::Write(this, packet, packet_length, cb);
        }

        // Encrypts data (may apply base94)
        std::shared_ptr<Byte> ITransmission::Encrypt(Byte* data, int datalen, int& outlen) noexcept {
            outlen = 0;
            if (datalen < 0 || (NULLPTR == data && datalen != 0)) {
                outlen = ~0;
                return NULLPTR;
            }

            if (datalen == 0) {
                return NULLPTR;
            }

            return ITransmissionBridge::Encrypt(this, data, datalen, outlen);
        }

        // Decrypts data (may decode base94)
        std::shared_ptr<Byte> ITransmission::Decrypt(Byte* data, int datalen, int& outlen) noexcept {
            outlen = 0;
            if (datalen < 0 || (NULLPTR == data && datalen != 0)) {
                outlen = ~0;
                return NULLPTR;
            }

            if (datalen == 0) {
                return NULLPTR;
            }

            return ITransmissionBridge::Decrypt(this, data, datalen, outlen);
        }

        // Asynchronously disposes the transmission
        void ITransmission::Dispose() noexcept {
            auto self = shared_from_this();
            ppp::threading::Executors::ContextPtr context = GetContext();
            ppp::threading::Executors::StrandPtr strand = GetStrand();

            ppp::threading::Executors::Post(context, strand,
                [self, this, context, strand]() noexcept {
                    Finalize();
                    IAsynchronousWriteIoQueue::Dispose();
                });
        }

        // Internal client-side handshake (returns session ID and mux flag)
        Int128 ITransmission::InternalHandshakeClient(YieldContext& y, bool& mux) noexcept {
            // Send dummy packets
            if (!Transmission_Handshake_Nop(configuration_, this, y)) {
                return 0;
            }

            // Receive server's session ID
            Int128 session_id = Transmission_Handshake_SessionId(configuration_, this, y);
            if (session_id) {
                // Generate and send a random IVV
                Int128 ivv = ppp::auxiliary::StringAuxiliary::GuidStringToInt128(GuidGenerate());
                if (!Transmission_Handshake_SessionId(configuration_, this, y, ivv)) {
                    return 0;
                }

                // Receive multiplexing flag
                Int128 nmux = Transmission_Handshake_SessionId(configuration_, this, y);
                if (nmux) {
                    handshaked_ = true;
                    mux = (nmux & 1) != 0;

                    // Update cipher keys with IVV if both ciphers exist
                    if (NULLPTR != protocol_ && NULLPTR != transport_) {
                        ppp::string ivv_string = stl::to_string<ppp::string>(ivv, 32);
                        if (ivv > 0) {
                            ivv_string = "+" + ivv_string;
                        }

                        if (ppp::configurations::extensions::IsHaveCiphertext(configuration_.get())) {
                            if (NULLPTR != protocol_ && NULLPTR != transport_) {
                                protocol_ = make_shared_object<Ciphertext>(configuration_->key.protocol, configuration_->key.protocol_key + ivv_string);
                                transport_ = make_shared_object<Ciphertext>(configuration_->key.transport, configuration_->key.transport_key + ivv_string);
                            }
                        }
                    }

                    return session_id;
                }
            }
            return 0;
        }

        // Internal server-side handshake (accepts client's session ID and mux)
        bool ITransmission::InternalHandshakeServer(YieldContext& y, const Int128& session_id, bool mux) noexcept {
            // Send dummy packets
            if (!Transmission_Handshake_Nop(configuration_, this, y)) {
                return false;
            }

            // Send our session ID (should match client's)
            if (!Transmission_Handshake_SessionId(configuration_, this, y, session_id)) {
                return false;
            }

            // Generate multiplexing flag with parity based on mux
            Int128 nmux = (Int128)RandomNext() << 32 |
                (Int128)RandomNext() << 64 |
                (Int128)RandomNext() << 96 |
                (Int128)RandomNext();
            if (mux) {
                while ((nmux & 1) == 0) {
                    nmux++;
                }
            }
            else {
                while ((nmux & 1) != 0) {
                    nmux++;
                }
            }

            // Send multiplexing flag
            if (!Transmission_Handshake_SessionId(configuration_, this, y, nmux)) {
                return false;
            }

            // Receive client's IVV
            Int128 ivv = Transmission_Handshake_SessionId(configuration_, this, y);
            if (ivv != 0) {
                handshaked_ = true;
                // Update cipher keys with IVV
                if (NULLPTR != protocol_ && NULLPTR != transport_) {
                    ppp::string ivv_string = stl::to_string<ppp::string>(ivv, 32);
                    if (ivv > 0) {
                        ivv_string = "+" + ivv_string;
                    }

                    if (ppp::configurations::extensions::IsHaveCiphertext(configuration_.get())) {
                        if (NULLPTR != protocol_ && NULLPTR != transport_) {
                            protocol_ = make_shared_object<Ciphertext>(configuration_->key.protocol, configuration_->key.protocol_key + ivv_string);
                            transport_ = make_shared_object<Ciphertext>(configuration_->key.transport, configuration_->key.transport_key + ivv_string);
                        }
                    }
                }
            }

            return handshaked_;
        }

        // Clears the handshake timeout timer
        void ITransmission::InternalHandshakeTimeoutClear() noexcept {
            DeadlineTimerPtr timeout = std::move(timeout_);
            timeout_.reset();

            if (NULLPTR != timeout) {
                Socket::Cancel(*timeout);
            }
        }

        // Sets a timeout for handshake; if expired, sends NOP and disposes
        bool ITransmission::InternalHandshakeTimeoutSet() noexcept {
            if (disposed_) {
                return false;
            }

            DeadlineTimerPtr timeout = timeout_;
            if (NULLPTR != timeout) {
                return false;
            }

            StrandPtr strand = strand_;
            ContextPtr context = context_;
            if (NULLPTR == strand && NULLPTR == context) {
                return false;
            }

            timeout = strand ?
                make_shared_object<DeadlineTimer>(*strand) :
                make_shared_object<DeadlineTimer>(*context);
            if (NULLPTR == timeout) {
                return false;
            }

            auto& connect_cfg = configuration_->tcp.connect;
            int64_t expired_time = (int64_t)connect_cfg.timeout * 1000;
            if (connect_cfg.nexcept > 0) {
                expired_time = RandomNext(expired_time, expired_time + (int64_t)connect_cfg.nexcept * 1000);
            }

            auto self = shared_from_this();
            timeout->expires_from_now(boost::posix_time::milliseconds(expired_time));
            timeout->async_wait(
                [self, this](boost::system::error_code ec) noexcept {
                    if (ec == boost::system::errc::operation_canceled) {
                        return false;
                    }

                    for (;;) {
                        std::shared_ptr<boost::asio::io_context> context = context_;
                        if (NULLPTR == context) {
                            break;
                        }

                        AppConfigurationPtr configuration = configuration_;
                        if (NULLPTR == configuration) {
                            break;
                        }

                        StrandPtr strand = strand_;
                        return YieldContext::Spawn(NULLPTR, *context, strand.get(),
                            [self, this, strand, configuration](YieldContext& y) noexcept {
                                Transmission_Handshake_Nop(configuration, this, y);
                                Dispose();
                            });
                    }

                    Dispose();
                    return true;
                });

            timeout_ = std::move(timeout);
            return true;
        }

        // Public client handshake: sets timeout, performs internal handshake, clears timeout
        Int128 ITransmission::HandshakeClient(YieldContext& y, bool& mux) noexcept {
            mux = false;
            if (!InternalHandshakeTimeoutSet()) {
                return 0;
            }

            Int128 session_id = InternalHandshakeClient(y, mux);
            InternalHandshakeTimeoutClear();
            return session_id;
        }

        // Public server handshake: sets timeout, performs internal handshake, clears timeout
        bool ITransmission::HandshakeServer(YieldContext& y, const Int128& session_id, bool mux) noexcept {
            if (session_id == 0) {
                return false;
            }

            if (!InternalHandshakeTimeoutSet()) {
                return false;
            }

            bool ok = InternalHandshakeServer(y, session_id, mux);
            InternalHandshakeTimeoutClear();
            return ok;
        }

        // Implementation of EncryptBinary (without base94)
        std::shared_ptr<Byte> ITransmissionBridge::EncryptBinary(ITransmission* transmission, Byte* data, int datalen, int& outlen) noexcept {
            bool safest = !transmission->handshaked_;
            CiphertextPtr EVP_protocol = transmission->protocol_;
            CiphertextPtr EVP_transport = transmission->transport_;

            const std::shared_ptr<BufferswapAllocator>& allocator = transmission->BufferAllocator;
            if (EVP_protocol && EVP_transport) {
                return Transmission_Packet_Encrypt(transmission->configuration_, allocator, EVP_protocol, EVP_transport, data, datalen, outlen, safest);
            }
            else {
                return Transmission_Packet_Encrypt(transmission->configuration_, allocator, NULLPTR, NULLPTR, data, datalen, outlen, safest);
            }
        }

        // Implementation of DecryptBinary (without base94)
        std::shared_ptr<Byte> ITransmissionBridge::DecryptBinary(ITransmission* transmission, Byte* data, int datalen, int& outlen) noexcept {
            bool safest = !transmission->handshaked_;
            CiphertextPtr EVP_protocol = transmission->protocol_;
            CiphertextPtr EVP_transport = transmission->transport_;

            const std::shared_ptr<BufferswapAllocator>& allocator = transmission->BufferAllocator;
            if (EVP_protocol && EVP_transport) {
                return Transmission_Packet_Decrypt(transmission->configuration_, allocator, EVP_protocol, EVP_transport, data, datalen, outlen, safest);
            }
            else {
                return Transmission_Packet_Decrypt(transmission->configuration_, allocator, NULLPTR, NULLPTR, data, datalen, outlen, safest);
            }
        }
    }
}