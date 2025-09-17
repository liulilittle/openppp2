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
        typedef ITransmission::AppConfigurationPtr      AppConfigurationPtr;
        typedef ITransmission::CiphertextPtr            CiphertextPtr;
        typedef ppp::net::Socket                        Socket;
        typedef ppp::threading::Thread                  Thread;
        typedef ppp::cryptography::ssea                 ssea;
        typedef ppp::io::Stream                         Stream;
        typedef ppp::io::MemoryStream                   MemoryStream;
        typedef ITransmission::YieldContext             YieldContext;
        typedef ppp::threading::BufferswapAllocator     BufferswapAllocator;

        static constexpr int                            EVP_HEADER_TSS = 2;
        static constexpr int                            EVP_HEADER_MSS = EVP_HEADER_TSS + 1;
        static constexpr int                            EVP_HEADER_XSS = EVP_HEADER_MSS + 1;
        static constexpr int                            EVP_HEADER_MSS_MOD = (94 * 94 * 94) - 1;

        static std::shared_ptr<Byte>                    Transmission_Packet_Read(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            const CiphertextPtr&                        EVP_protocol,
            const CiphertextPtr&                        EVP_transport,
            int&                                        outlen,
            ITransmission*                              transmission,
            YieldContext&                               y,
            bool                                        safest) noexcept;

        class ITransmissionBridge final {
        public:
            static std::shared_ptr<Byte>                ReadBytes(ITransmission* transmission, YieldContext& y, int length) noexcept {
                return transmission->DoReadBytes(y, length);
            }
            static std::shared_ptr<Byte>                ReadBinary(ITransmission* transmission, YieldContext& y, int& outlen) noexcept {
                bool safest = !transmission->handshaked_;
                CiphertextPtr EVP_protocol = transmission->protocol_;
                CiphertextPtr EVP_transport = transmission->transport_;

                const std::shared_ptr<BufferswapAllocator>& allocator = transmission->BufferAllocator;
                if (EVP_protocol && EVP_transport) {
                    return Transmission_Packet_Read(transmission->configuration_, allocator, EVP_protocol, EVP_transport, outlen, transmission, y, safest);
                }
                else {
                    return Transmission_Packet_Read(transmission->configuration_, allocator, NULL, NULL, outlen, transmission, y, safest);
                }
            }

        public:
            static std::shared_ptr<Byte>                EncryptBinary(ITransmission* transmission, Byte* data, int datalen, int& outlen) noexcept;
            static std::shared_ptr<Byte>                DecryptBinary(ITransmission* transmission, Byte* data, int datalen, int& outlen) noexcept;

        public:
            static std::shared_ptr<Byte>                Encrypt(ITransmission* transmission, Byte* data, int datalen, int& outlen) noexcept {
                std::shared_ptr<Byte> packet = EncryptBinary(transmission, data, datalen, outlen);
                if (NULL != packet) {
                    AppConfigurationPtr& configuration = transmission->configuration_;
                    if (!transmission->handshaked_ || configuration->key.plaintext) {
                        packet = base94_encode(transmission, transmission->BufferAllocator, 
                            packet.get(), outlen, configuration->key.kf, outlen);
                    }
                }

                if (NULL != packet) {
                    return packet;
                }
                else {
                    outlen = 0;
                    return packet;
                }
            }
            static std::shared_ptr<Byte>                Decrypt(ITransmission* transmission, Byte* data, int datalen, int& outlen) noexcept {
                std::shared_ptr<Byte> packet;
                AppConfigurationPtr& configuration = transmission->configuration_;

                if (!transmission->handshaked_ || configuration->key.plaintext) {
                    packet = base94_decode(transmission->BufferAllocator, 
                        data, datalen, configuration->key.kf, outlen);
                    packet = DecryptBinary(transmission, packet.get(), outlen, outlen);
                }
                else {
                    packet = DecryptBinary(transmission, data, datalen, outlen);
                }

                if (NULL != packet) {
                    return packet;
                }
                else {
                    outlen = 0;
                    return packet;
                }
            }
            static std::shared_ptr<Byte>                Read(ITransmission* transmission, YieldContext& y, int& outlen) noexcept {
                outlen = 0;
                if (transmission->disposed_) {
                    return NULL;
                }

                std::shared_ptr<Byte> packet;
                AppConfigurationPtr& configuration = transmission->configuration_;

                if (!transmission->handshaked_ || configuration->key.plaintext) {
                    packet = base94_decode(transmission, y, outlen);
                    packet = DecryptBinary(transmission, packet.get(), outlen, outlen);
                }
                else {
                    packet = ReadBinary(transmission, y, outlen);
                }

                if (NULL != packet) {
                    return packet;
                }
                else {
                    outlen = 0;
                    return NULL;
                }
            }

#if defined(_WIN32)
#pragma optimize("", off)
#pragma optimize("gsyb2", on) /* /O1 = /Og /Os /Oy /Ob2 /GF /Gy */
#else
// TRANSMISSIONO1 compiler macros are defined to perform O1 optimizations, 
// Otherwise gcc compiler version If <= 7.5.X, 
// The O1 optimization will also be applied, 
// And the other cases will not be optimized, 
// Because this will cause the program to crash, 
// Which is a fatal BUG caused by the gcc compiler optimization. 
// Higher-version compilers should not optimize the code for gcc compiling this section.
#if defined(__clang__)
#pragma clang optimize off
#else
#pragma GCC push_options
#if defined(TRANSMISSION_O1) || (__GNUC__ < 7) || (__GNUC__ == 7 && __GNUC_MINOR__ <= 5) /* __GNUC_PATCHLEVEL__ */
#pragma GCC optimize("O1")
#else
#pragma GCC optimize("O0")
#endif
#endif
#endif
            // This function cannot be optimized or the optimization level cannot be greater than O1, 
            // Otherwise it will cause problems with the compiler. In fact, there will be no problems under WIN, 
            // And there will be no problems with higher versions of GCC. 
            // The problem is that the compiler version is GCC7.X or above. 
            // Found, but in order to maintain consistency, 
            // Both VC++ and GCC should uniformly require the compiler to use the corresponding range of C/C++ code optimization levels.
            static bool                                 Write(ITransmission* transmission, YieldContext& y, const void* packet, int packet_length) noexcept {
                using AsynchronousWriteCallback = ITransmission::AsynchronousWriteCallback;

                if (transmission->disposed_) {
                    return false;
                }

                YieldContext* co = y.GetPtr();
                if (NULL != co) {
                    return transmission->DoWriteYield<AsynchronousWriteCallback>(*co, packet, packet_length,
                        [transmission](const void* packet, int packet_length, const AsynchronousWriteCallback& cb) noexcept {
                            return ITransmissionBridge::Write(transmission, packet, packet_length, cb);
                        });
                }
                else {
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

            static bool                                 Write(ITransmission* transmission, const void* packet, int packet_length, const ITransmission::AsynchronousWriteBytesCallback& cb) noexcept {
                if (NULL == packet || packet_length < 1) {
                    return false;
                }

                if (NULL == cb) {
                    return false;
                }

                if (transmission->disposed_) {
                    return false;
                }

                int messages_size = 0;
                std::shared_ptr<Byte> messages = Encrypt(transmission, (Byte*)packet, packet_length, messages_size);
                if (NULL == messages) {
                    return false;
                }

                return transmission->WriteBytes(messages, messages_size, cb);
            }

        private:
            static ppp::string                          base94_encode_length(ITransmission* transmission, int length, int kf) noexcept {
                // FORMULA: (N + KF_MOD) % MOD
                const int KF_MOD = kf % EVP_HEADER_MSS_MOD;
                int N = (length + KF_MOD) % EVP_HEADER_MSS_MOD;

                ppp::string d = ssea::base94_decimal(N);
                int dl = d.size();

                if (dl < 1) {
                    return ppp::string();
                }

                if (dl >= EVP_HEADER_XSS) {
                    return ppp::string();
                }

                Byte h[EVP_HEADER_XSS + EVP_HEADER_MSS];
                *((int*)h) = 0x20202020;

                Byte& k = h[0];
                Byte& f = h[1];
                memcpy(h + (EVP_HEADER_XSS - dl), d.data(), dl);

                k = RandomNext('\x20', '\x7e');
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

                std::swap(h[2], h[3]);

                if (transmission->frame_tn_) {
                    return ppp::string(reinterpret_cast<char*>(h), EVP_HEADER_XSS);
                }
                else {
                    int K = ppp::net::native::inet_chksum(h, EVP_HEADER_XSS) ^ length;

                    N = (K + KF_MOD) % EVP_HEADER_MSS_MOD;
                    d = ssea::base94_decimal(N);

                    if (d.size() != EVP_HEADER_MSS) {
                        return ppp::string();
                    }

                    Byte* pbc = h + EVP_HEADER_XSS;
                    transmission->frame_tn_ = true;
                    
                    memcpy(pbc, d.data(), EVP_HEADER_MSS);
                    ssea::shuffle_data((char*)pbc, EVP_HEADER_MSS, kf);

                    return ppp::string(reinterpret_cast<char*>(h), sizeof(h));
                }
            }
            static int                                  base94_decode_length(Byte* data, int kf) noexcept {
                // FORMULA: (N - KF_MOD + MOD) % MOD
                const int N = ssea::base94_decimal(data, EVP_HEADER_MSS);
                const int KF_MOD = kf % EVP_HEADER_MSS_MOD;

                return (N - KF_MOD + EVP_HEADER_MSS_MOD) % EVP_HEADER_MSS_MOD;
            }                                  

        private:
            static void                                 base94_decode_kf(Byte* h) noexcept {
                Byte& k = h[0];
                Byte& f = h[1];
                if ((k & '\x01') == '\x00') {
                    f = '\x20';
                }

                k = '\x20';
                std::swap(h[2], h[3]);
            }
            static std::shared_ptr<Byte>                base94_encode(ITransmission* transmission, const std::shared_ptr<BufferswapAllocator>& allocator, Byte* data, int datalen, int kf, int& outlen) noexcept {
                std::shared_ptr<Byte> payload = ssea::base94_encode(allocator, data, datalen, kf, outlen);
                if (NULL == payload) {
                    return NULL;
                }

                ppp::string k = base94_encode_length(transmission, outlen, kf);
                if (k.size() < EVP_HEADER_XSS) {
                    return NULL;
                }

                int k_size = k.size();
                int packet_length = outlen + k_size;

                std::shared_ptr<Byte> packet = BufferswapAllocator::MakeByteArray(allocator, packet_length);
                if (NULL == packet) {
                    return NULL;
                }

                Byte* memory = packet.get();
                memcpy(memory, k.data(), k_size);
                memcpy(memory + k_size, payload.get(), outlen);

                outlen = packet_length;
                return packet;
            }
            static std::shared_ptr<Byte>                base94_decode(const std::shared_ptr<BufferswapAllocator>& allocator, Byte* data, int datalen, int kf, int& outlen) noexcept {
                outlen = 0;

                if (NULL == data || datalen < EVP_HEADER_XSS) {
                    return NULL;
                }
                else {
                    base94_decode_kf(data);
                }

                int payload_length = base94_decode_length(data, kf);
                if (payload_length < 1) {
                    return NULL;
                }

                if ((payload_length + EVP_HEADER_XSS) != datalen) {
                    return NULL;
                }

                Byte* payload = data + EVP_HEADER_XSS;
                return ssea::base94_decode(allocator, payload, payload_length, kf, outlen);
            }
            static int                                  base94_decode_length_rn(ITransmission* transmission, YieldContext& y) noexcept {
                std::shared_ptr<Byte> packet = ReadBytes(transmission, y, EVP_HEADER_XSS);
                if (NULL == packet) {
                    return -1;
                }

                Byte* data = packet.get();
                AppConfigurationPtr& configuration = transmission->configuration_;
                base94_decode_kf(data);

                int payload_length = base94_decode_length(data + 1, configuration->key.kf);
                return payload_length > 0 ? payload_length : -1;
            }
            static int                                  base94_decode_length_r1(ITransmission* transmission, YieldContext& y) noexcept {
                std::shared_ptr<Byte> packet = ReadBytes(transmission, y, EVP_HEADER_XSS + EVP_HEADER_MSS);
                if (NULL == packet) {
                    return -1;
                }

                Byte* data = packet.get();
                int K = ppp::net::native::inet_chksum(data, EVP_HEADER_XSS);

                AppConfigurationPtr& configuration = transmission->configuration_;
                base94_decode_kf(data);

                int payload_length = base94_decode_length(data + 1, configuration->key.kf);
                if (payload_length < 1) {
                    return -1;
                }

                Byte* pbc = data + EVP_HEADER_XSS;
                ssea::shuffle_data((char*)pbc, EVP_HEADER_MSS, configuration->key.kf);

                int N = base94_decode_length(pbc, configuration->key.kf);
                K = K ^ payload_length;

                if (N != K) {
                    return -1;
                }

                transmission->frame_rn_ = true;
                return payload_length;
            }
            static int                                  base94_decode_length(ITransmission* transmission, YieldContext& y) noexcept {
                if (transmission->frame_rn_) {
                    return base94_decode_length_rn(transmission, y);
                }
                
                return base94_decode_length_r1(transmission, y);
            }
            static std::shared_ptr<Byte>                base94_decode(ITransmission* transmission, YieldContext& y, int& outlen) noexcept {
                outlen = 0;

                int payload_length = base94_decode_length(transmission, y);
                if (payload_length < 1) {
                    return NULL;
                }

                std::shared_ptr<Byte> packet = ReadBytes(transmission, y, payload_length);
                if (NULL == packet) {
                    return NULL;
                }

                AppConfigurationPtr& configuration = transmission->configuration_;
                return ssea::base94_decode(transmission->BufferAllocator, 
                    packet.get(), 
                    payload_length, 
                    configuration->key.kf, 
                    outlen);
            }
        };

        static std::shared_ptr<Byte>                    Transmission_Header_Encrypt(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            const CiphertextPtr&                        EVP_protocol,
            int                                         EVP_payload_length,
            int&                                        EVP_header_length,
            int&                                        EVP_header_kf) noexcept {

            // Packet Alignment: 65536 -> 65535   
            if (--EVP_payload_length < 0) {
                return NULL;
            }

            Byte EVP_payload_length_array[EVP_HEADER_MSS] = {
                (Byte)(RandomNext(0x01, 0xff)),     // Variable frame word.
                (Byte)(EVP_payload_length >> 0x08), // High-order
                (Byte)(EVP_payload_length & 0xff),  // Low-order
            };

            int EVP_header_datalen = sizeof(EVP_payload_length_array);
            EVP_header_kf = APP->key.kf ^ *EVP_payload_length_array;

            // Byte encryption.
            if (EVP_protocol) {
                std::shared_ptr<Byte> EVP_header_length_buff = EVP_protocol->Encrypt(allocator, EVP_payload_length_array + 1, EVP_HEADER_TSS, EVP_header_length);
                if (NULL == EVP_header_length_buff || EVP_header_length != EVP_HEADER_TSS) {
                    return NULL;
                }

                memcpy(EVP_payload_length_array + 1, EVP_header_length_buff.get(), EVP_HEADER_TSS);
            }

            // Mask encryption.
            for (int i = 1; i < EVP_HEADER_MSS; i++) {
                EVP_payload_length_array[i] ^= EVP_header_kf;
            }

            // Shuffle datas.
            EVP_header_length = sizeof(EVP_payload_length_array);
            ssea::shuffle_data(reinterpret_cast<char*>(EVP_payload_length_array + 1), EVP_HEADER_TSS, EVP_header_kf);

            // Delta encode.
            std::shared_ptr<Byte> output;
            return ssea::delta_encode(allocator, EVP_payload_length_array, EVP_header_datalen, APP->key.kf, output) != EVP_header_length ? NULL : output;
        }

        static int                                      Transmission_Header_Decrypt(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            const CiphertextPtr&                        EVP_protocol,
            Byte*                                       EVP_header_array,
            int&                                        EVP_header_kf) noexcept {

            // Delta encode.
            std::shared_ptr<Byte> EVP_payload_length_array_managed;
            if (ssea::delta_decode(allocator, EVP_header_array, EVP_HEADER_MSS, APP->key.kf, EVP_payload_length_array_managed) != EVP_HEADER_MSS) {
                return 0;
            }

            // Unshuffle data.
            Byte* EVP_payload_length_array = EVP_payload_length_array_managed.get();
            EVP_header_kf = APP->key.kf ^ *EVP_payload_length_array;
            ssea::unshuffle_data(reinterpret_cast<char*>(EVP_payload_length_array + 1), EVP_HEADER_TSS, EVP_header_kf);

            // Mask decode data.
            for (int i = 1; i < EVP_HEADER_MSS; i++) {
                EVP_payload_length_array[i] ^= EVP_header_kf;
            }

            // Byte decode.
            int EVP_header_length = 0;
            if (EVP_protocol) {
                std::shared_ptr<Byte> EVP_header_length_buff = EVP_protocol->Decrypt(allocator, EVP_payload_length_array + 1, EVP_HEADER_TSS, EVP_header_length);
                if (NULL == EVP_header_length_buff || EVP_header_length != EVP_HEADER_TSS) {
                    return 0;
                }

                memcpy(EVP_payload_length_array + 1, EVP_header_length_buff.get(), EVP_HEADER_TSS);
            }

            EVP_header_length = EVP_payload_length_array[1] << 0x08 | EVP_payload_length_array[2];
            return EVP_header_length + 1;
        }

        static void                                     Transmission_Payload_Encrypt_Partial(
            const AppConfigurationPtr&                  APP,
            int                                         kf,
            Byte*                                       data,
            int                                         datalen,
            bool                                        safest) noexcept {

            // Mask encryption.
            if (safest || APP->key.masked) {
                for (int i = 0; i < datalen; i++) {
                    data[i] ^= kf;
                }
            }

            // Shuffle datas.
            if (safest || APP->key.shuffle_data) {
                ssea::shuffle_data(reinterpret_cast<char*>(data), datalen, kf);
            }
        }

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

            // Delta encode.
            std::shared_ptr<Byte> output;
            if (safest || APP->key.delta_encode) {
                return ssea::delta_encode(allocator, data, datalen, APP->key.kf, output) != datalen ? NULL : output;
            }
            else {
                output = BufferswapAllocator::MakeByteArray(allocator, datalen);
                if (NULL == output) {
                    return NULL;
                }
                else {
                    memcpy(output.get(), data, datalen);
                    return output;
                }
            }
        }

        static void                                     Transmission_Payload_Decrypt_Partial(
            const AppConfigurationPtr&                  APP,
            int                                         kf,
            Byte*                                       data,
            int                                         datalen,
            bool                                        safest) noexcept {

            // Unshuffle data.
            if (safest || APP->key.shuffle_data) {
                ssea::unshuffle_data(reinterpret_cast<char*>(data), datalen, kf);
            }

            // Mask decode data.
            if (safest || APP->key.masked) {
                for (int i = 0; i < datalen; i++) {
                    data[i] ^= kf;
                }
            }
        }

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
                std::shared_ptr<Byte> EVP_payload_array_managed; // Delta encode.
                if (ssea::delta_decode(allocator, data.get(), datalen, APP->key.kf, EVP_payload_array_managed) != datalen) {
                    return NULL;
                }

                Transmission_Payload_Decrypt_Partial(APP, kf, EVP_payload_array_managed.get(), datalen, safest);
                return EVP_payload_array_managed;
            }
            else {
                Transmission_Payload_Decrypt_Partial(APP, kf, data.get(), datalen, safest);
                return data;
            }
        }

        static std::shared_ptr<Byte>                    Transmission_Packet_Pack(
            const std::shared_ptr<BufferswapAllocator>& allocator,
            const std::shared_ptr<Byte>&                EVP_header,
            int                                         EVP_header_length,
            const std::shared_ptr<Byte>&                EVP_payload,
            int                                         EVP_payload_length,
            int&                                        EVP_packet_length) noexcept {

            EVP_packet_length =
                EVP_header_length + EVP_payload_length;

            std::shared_ptr<Byte> packet = BufferswapAllocator::MakeByteArray(allocator, EVP_packet_length);
            if (NULL == packet) {
                return NULL;
            }

            Byte* memory = packet.get();
            memcpy(memory, EVP_header.get(), EVP_header_length);
            memcpy(memory + EVP_header_length, EVP_payload.get(), EVP_payload_length);
            return packet;
        }

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
                // Encrypt payload data (A).
                std::shared_ptr<Byte> EVP_payload = EVP_transport->Encrypt(allocator, data, datalen, EVP_payload_length);
                if (NULL == EVP_payload || EVP_payload_length != datalen) {
                    return NULL;
                }

                // Encrypt header data.
                std::shared_ptr<Byte> EVP_header = Transmission_Header_Encrypt(APP, allocator, EVP_protocol, EVP_payload_length, EVP_header_length, EVP_header_kf);
                if (NULL == EVP_header) {
                    return NULL;
                }

                // Encrypt payload data (B).
                EVP_payload = Transmission_Payload_Encrypt(APP, allocator, EVP_header_kf, EVP_payload.get(), datalen, EVP_payload_length, safest);
                if (NULL == EVP_payload) {
                    return NULL;
                }
                else {
                    return Transmission_Packet_Pack(allocator, EVP_header, EVP_header_length, EVP_payload, EVP_payload_length, outlen);
                }
            }
            else {
                // Encrypt header data.
                std::shared_ptr<Byte> EVP_header = Transmission_Header_Encrypt(APP, allocator, EVP_protocol, datalen, EVP_header_length, EVP_header_kf);
                if (NULL == EVP_header) {
                    return NULL;
                }

                // Encrypt payload data.
                std::shared_ptr<Byte> EVP_payload = Transmission_Payload_Encrypt(APP, allocator, EVP_header_kf, data, datalen, EVP_payload_length, safest);
                if (NULL == EVP_payload) {
                    return NULL;
                }
                else {
                    return Transmission_Packet_Pack(allocator, EVP_header, EVP_header_length, EVP_payload, EVP_payload_length, outlen);
                }
            }
        }

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
                return NULL;
            }

            int EVP_payload_length = Transmission_Header_Decrypt(APP, allocator, EVP_protocol, data, EVP_header_kf);
            if (EVP_payload_length < 1) {
                return NULL;
            }

            int EVP_packet_length = EVP_payload_length + EVP_HEADER_MSS;
            if (EVP_packet_length != datalen) {
                return NULL;
            }

            std::shared_ptr<Byte> EVP_payload = BufferswapAllocator::MakeByteArray(allocator, EVP_payload_length);
            if (NULL == EVP_payload) {
                return NULL;
            }
            else {
                memcpy(EVP_payload.get(), data + EVP_HEADER_MSS, EVP_payload_length);
            }

            EVP_payload = Transmission_Payload_Decrypt(APP, allocator, EVP_header_kf, EVP_payload, EVP_payload_length, outlen, safest);
            if (NULL == EVP_payload) {
                return NULL;
            }

            if (EVP_protocol && EVP_transport) {
                EVP_payload = EVP_transport->Decrypt(allocator, EVP_payload.get(), EVP_payload_length, outlen);
                if (NULL == EVP_payload || EVP_payload_length != outlen) {
                    return NULL;
                }
            }

            return EVP_payload;
        }

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

            std::shared_ptr<Byte> EVP_header = ITransmissionBridge::ReadBytes(transmission, y, EVP_HEADER_MSS);
            if (NULL == EVP_header) {
                return NULL;
            }

            int EVP_payload_length = Transmission_Header_Decrypt(APP, allocator, EVP_protocol, EVP_header.get(), EVP_header_kf);
            if (EVP_payload_length < 1) {
                return NULL;
            }

            std::shared_ptr<Byte> EVP_payload = ITransmissionBridge::ReadBytes(transmission, y, EVP_payload_length);
            if (NULL == EVP_payload) {
                return NULL;
            }

            EVP_payload = Transmission_Payload_Decrypt(APP, allocator, EVP_header_kf, EVP_payload, EVP_payload_length, outlen, safest);
            if (NULL == EVP_payload) {
                return NULL;
            }

            if (EVP_protocol && EVP_transport) {
                EVP_payload = EVP_transport->Decrypt(allocator, EVP_payload.get(), EVP_payload_length, outlen);
                if (NULL == EVP_payload || EVP_payload_length != outlen) {
                    return NULL;
                }
            }

            return EVP_payload;
        }

        static std::shared_ptr<Byte>                    Transmission_Handshake_Pack_SessionId(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<BufferswapAllocator>& allocator,
            Int128                                      session_id,
            int&                                        packet_length) noexcept {

            Byte kfs[4];
            packet_length = 0;

            ppp::string session_id_string;
            if (session_id) {
                kfs[0] = RandomNext(0x00, 0x7f);
                session_id_string = stl::to_string<ppp::string>(session_id);
            }
            else {
                kfs[0] = RandomNext(0x80, 0xff);
                int64_t v1 = (int64_t)RandomNext() << 32 | (int64_t)(uint32_t)RandomNext();
                int64_t v2 = (int64_t)RandomNext() << 32 | (int64_t)(uint32_t)RandomNext();
                session_id_string = stl::to_string<ppp::string>(MAKE_OWORD(v2, v1));
            }

            kfs[1] = RandomNext(0x01, 0xff);
            kfs[2] = RandomNext(0x01, 0xff);
            kfs[3] = RandomNext(0x01, 0xff);
            session_id_string.append(1, RandomNext(0x20, 0x2F));

            int max = APP->key.kx % 0x100;
            if (max > 0) {
                int i = 0;
                for (; i < max; i++) {
                    session_id_string.append(1, RandomNext(0x20, 0x7e));
                    break;
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

            int kf = APP->key.kf;
            for (int i = 0; i < arraysizeof(kfs); i++) {
                kf ^= kfs[i];
                for (int j = 0; j < packet_length; j++) {
                    packet[j] ^= kf;
                }
            }

            std::shared_ptr<Byte> messages = BufferswapAllocator::MakeByteArray(allocator, packet_length += sizeof(kfs));
            if (NULL == messages) {
                return NULL;
            }

            Byte* memory = messages.get();
            memcpy(memory, kfs, sizeof(kfs));
            memcpy(memory + sizeof(kfs), packet, session_id_string.size());
            return messages;
        }

        static Int128                                   Transmission_Handshake_Unpack_SessionId(
            const AppConfigurationPtr&                  APP,
            const std::shared_ptr<Byte>&                packet_managed,
            int                                         packet_length,
            bool&                                       eagin) noexcept {

            eagin = false;
            if (NULL == packet_managed) {
                return 0;
            }

            if (packet_length < 4) {
                return 0;
            }

            // If the symbol bit is set, it means that it is a pre-random circular flower arrangement packet 
            // Used to brush the whitelist rules on the mainstream firewall network stack.
            Byte* packet = packet_managed.get();
            if (*packet & 0x80) {
                eagin = true;
                return 0;
            }

            Byte kfs[] = { packet[0], packet[1], packet[2], packet[3] }; // Dynamic random value.
            packet += sizeof(kfs);
            packet_length -= sizeof(kfs);
            if (packet_length < 1) {
                return 0;
            }

            int kf = APP->key.kf;
            for (int i = 0; i < arraysizeof(kfs); i++) {
                kf ^= kfs[i];
                for (int j = 0; j < packet_length; j++) {
                    packet[j] ^= kf;
                }
            }

            // GUID is an INT128 integer and cannot be 0.
            Int128 session_id = stl::to_number<Int128>(std::string_view(reinterpret_cast<char*>(packet), packet_length), 10);
            return session_id;
        }

        static bool                                     Transmission_Handshake_SessionId(
            const AppConfigurationPtr&                  APP,
            ITransmission*                              transmission,
            ITransmission::YieldContext&                y,
            const Int128&                               session_id) noexcept {

            int packet_length = 0;
            std::shared_ptr<Byte> packet_managed = Transmission_Handshake_Pack_SessionId(APP, 
                transmission->BufferAllocator, session_id, packet_length);
            if (NULL == packet_managed) {
                return false;
            }

            return ITransmissionBridge::Write(transmission, y, packet_managed.get(), packet_length);
        }

        static Int128                                   Transmission_Handshake_SessionId(
            const AppConfigurationPtr&                  APP,
            ITransmission*                              transmission,
            ITransmission::YieldContext&                y) noexcept {

            bool eagin = false;
            for (;;) {
                // The handshake is protected by the maximum granularity transport layer before completion 
                // (e.g., printable plaintext, differential restoration, byte sequence scrambling, advanced encryption layer, etc.)
                int packet_length = 0;
                std::shared_ptr<Byte> packet_managed = ITransmissionBridge::Read(transmission, y, packet_length);
                if (NULL == packet_managed) {
                    return 0;
                }

                Int128 session_id = Transmission_Handshake_Unpack_SessionId(APP, packet_managed, packet_length, eagin);
                if (eagin) {
                    continue;
                }

                return session_id;
            }
        }

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

            roundof = ceil(roundof / (double)(175 << 3));
            for (int i = 0; i < roundof; i++) {
                if (!Transmission_Handshake_SessionId(APP, transmission, y, 0)) {
                    return false;
                }
            }

            return true;
        }

        ITransmission::ITransmission(const ContextPtr& context, const StrandPtr& strand, const AppConfigurationPtr& configuration) noexcept
            : IAsynchronousWriteIoQueue(NULL != configuration ? configuration->GetBufferAllocator() : NULL)
            , disposed_(false)
            , frame_rn_(false)
            , frame_tn_(false)
            , handshaked_(false)
            , context_(context)
            , strand_(strand)
            , configuration_(configuration) {
    
            if (ppp::configurations::extensions::IsHaveCiphertext(configuration.get())) {
                if (Ciphertext::Support(configuration->key.protocol) && Ciphertext::Support(configuration->key.transport)) {
                    protocol_ = make_shared_object<Ciphertext>(configuration->key.protocol, configuration->key.protocol_key);
                    transport_ = make_shared_object<Ciphertext>(configuration->key.transport, configuration->key.transport_key);
                }
            }
        }

        ITransmission::~ITransmission() noexcept {
            Finalize();
        }

        void ITransmission::Finalize() noexcept {
            DeadlineTimerPtr timeout = std::move(timeout_);
            timeout_.reset();

            disposed_ = false;
            handshaked_ = false;
            QoS.reset();
            Statistics.reset();

            if (NULL != timeout) {
                Socket::Cancel(*timeout);
            }
        }

        std::shared_ptr<Byte> ITransmission::Read(YieldContext& y, int& outlen) noexcept {
            return ITransmissionBridge::Read(this, y, outlen);
        }

        bool ITransmission::Write(YieldContext& y, const void* packet, int packet_length) noexcept {
            return ITransmissionBridge::Write(this, y, packet, packet_length);
        }

        bool ITransmission::Write(const void* packet, int packet_length, const AsynchronousWriteCallback& cb) noexcept {
            return ITransmissionBridge::Write(this, packet, packet_length, cb);
        }

        std::shared_ptr<Byte> ITransmission::Encrypt(Byte* data, int datalen, int& outlen) noexcept {
            outlen = 0;
            if (datalen < 0 || (NULL == data && datalen != 0)) {
                outlen = ~0;
                return NULL;
            }

            if (datalen == 0) {
                return NULL;
            }

            return ITransmissionBridge::Encrypt(this, data, datalen, outlen);
        }

        std::shared_ptr<Byte> ITransmission::Decrypt(Byte* data, int datalen, int& outlen) noexcept {
            outlen = 0;
            if (datalen < 0 || (NULL == data && datalen != 0)) {
                outlen = ~0;
                return NULL;
            }

            if (datalen == 0) {
                return NULL;
            }

            return ITransmissionBridge::Decrypt(this, data, datalen, outlen);
        }

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

        Int128 ITransmission::InternalHandshakeClient(YieldContext& y, bool& mux) noexcept {
            if (!Transmission_Handshake_Nop(configuration_, this, y)) {
                return 0;
            }

            Int128 session_id = Transmission_Handshake_SessionId(configuration_, this, y);
            if (session_id) {
                Int128 ivv = ppp::auxiliary::StringAuxiliary::GuidStringToInt128(GuidToString(GuidGenerate()));
                if (!Transmission_Handshake_SessionId(configuration_, this, y, ivv)) {
                    return 0;
                }

                Int128 nmux = Transmission_Handshake_SessionId(configuration_, this, y);
                if (nmux) {
                    handshaked_ = true;
                    if (nmux & 1) {
                        mux = true;
                    }
                    else {
                        mux = false;
                    }

                    if (NULL != protocol_ && NULL != transport_) {
                        ppp::string ivv_string = stl::to_string<ppp::string>(ivv, 32);
                        if (ivv > 0) {
                            ivv_string = "+" + ivv_string;
                        }

                        if (ppp::configurations::extensions::IsHaveCiphertext(configuration_.get())) {
                            if (NULL != protocol_ && NULL != transport_) {
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

        bool ITransmission::InternalHandshakeServer(YieldContext& y, const Int128& session_id, bool mux) noexcept {
            if (!Transmission_Handshake_Nop(configuration_, this, y)) {
                return false;
            }

            if (!Transmission_Handshake_SessionId(configuration_, this, y, session_id)) {
                return false;
            }

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

            if (!Transmission_Handshake_SessionId(configuration_, this, y, nmux)) {
                return false;
            }

            Int128 ivv = Transmission_Handshake_SessionId(configuration_, this, y);
            if (ivv != 0) {
                handshaked_ = true;
                if (NULL != protocol_ && NULL != transport_) {
                    ppp::string ivv_string = stl::to_string<ppp::string>(ivv, 32);
                    if (ivv > 0) {
                        ivv_string = "+" + ivv_string;
                    }

                    if (ppp::configurations::extensions::IsHaveCiphertext(configuration_.get())) {
                        if (NULL != protocol_ && NULL != transport_) {
                            protocol_ = make_shared_object<Ciphertext>(configuration_->key.protocol, configuration_->key.protocol_key + ivv_string);
                            transport_ = make_shared_object<Ciphertext>(configuration_->key.transport, configuration_->key.transport_key + ivv_string);
                        }
                    }
                }
            }

            return handshaked_;
        }

        void ITransmission::InternalHandshakeTimeoutClear() noexcept {
            DeadlineTimerPtr timeout = std::move(timeout_);
            timeout_.reset();

            if (NULL != timeout) {
                Socket::Cancel(*timeout);
            }
        }

        bool ITransmission::InternalHandshakeTimeoutSet() noexcept {
            if (disposed_) {
                return false;
            }

            DeadlineTimerPtr timeout = timeout_;
            if (NULL != timeout) {
                return false;
            }

            StrandPtr strand = strand_;
            ContextPtr context = context_;
            if (NULL == strand && NULL == context) {
                return false;
            }

            timeout = strand ?
                make_shared_object<DeadlineTimer>(*strand) :
                make_shared_object<DeadlineTimer>(*context);
            if (NULL == timeout) {
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
                        if (NULL == context) {
                            break;
                        }

                        AppConfigurationPtr configuration = configuration_;
                        if (NULL == configuration) {
                            break;
                        }
                        
                        StrandPtr strand = strand_;
                        return YieldContext::Spawn(NULL, *context, strand.get(), 
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

        Int128 ITransmission::HandshakeClient(YieldContext& y, bool& mux) noexcept {
            mux = false;
            if (!InternalHandshakeTimeoutSet()) {
                return 0;
            }

            Int128 session_id = InternalHandshakeClient(y, mux);
            InternalHandshakeTimeoutClear();
            return session_id;
        }

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

        std::shared_ptr<Byte> ITransmissionBridge::EncryptBinary(ITransmission* transmission, Byte* data, int datalen, int& outlen) noexcept {
            bool safest = !transmission->handshaked_;
            CiphertextPtr EVP_protocol = transmission->protocol_;
            CiphertextPtr EVP_transport = transmission->transport_;

            const std::shared_ptr<BufferswapAllocator>& allocator = transmission->BufferAllocator;
            if (EVP_protocol && EVP_transport) {
                return Transmission_Packet_Encrypt(transmission->configuration_, allocator, EVP_protocol, EVP_transport, data, datalen, outlen, safest);
            }
            else {
                return Transmission_Packet_Encrypt(transmission->configuration_, allocator, NULL, NULL, data, datalen, outlen, safest);
            }
        }

        std::shared_ptr<Byte> ITransmissionBridge::DecryptBinary(ITransmission* transmission, Byte* data, int datalen, int& outlen) noexcept {
            bool safest = !transmission->handshaked_;
            CiphertextPtr EVP_protocol = transmission->protocol_;
            CiphertextPtr EVP_transport = transmission->transport_;

            const std::shared_ptr<BufferswapAllocator>& allocator = transmission->BufferAllocator;
            if (EVP_protocol && EVP_transport) {
                return Transmission_Packet_Decrypt(transmission->configuration_, allocator, EVP_protocol, EVP_transport, data, datalen, outlen, safest);
            }
            else {
                return Transmission_Packet_Decrypt(transmission->configuration_, allocator, NULL, NULL, data, datalen, outlen, safest);
            }
        }
    }
}