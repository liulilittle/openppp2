#pragma once

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/cryptography/Ciphertext.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/transmissions/ITransmissionQoS.h>
#include <ppp/transmissions/ITransmissionStatistics.h>

namespace ppp {
    namespace transmissions {
        class ITransmission : public ppp::net::asio::IAsynchronousWriteIoQueue {
            friend class ITransmissionBridge;
            friend class ITransmissionQoS;

        public:
            typedef ppp::configurations::AppConfiguration           AppConfiguration;
            typedef std::shared_ptr<AppConfiguration>               AppConfigurationPtr;
            typedef ppp::cryptography::Ciphertext                   Ciphertext;
            typedef std::shared_ptr<Ciphertext>                     CiphertextPtr;
            typedef ppp::coroutines::YieldContext                   YieldContext;
            typedef std::shared_ptr<boost::asio::io_context>        ContextPtr;
            typedef ppp::function<void(bool)>                       AsynchronousWriteBytesCallback, AsynchronousWriteCallback;

        public:
            ITransmission(const ContextPtr& context, const AppConfigurationPtr& configuration) noexcept;
            virtual ~ITransmission() noexcept;

        public:
            std::shared_ptr<ITransmissionStatistics>                Statistics;
            std::shared_ptr<ITransmissionQoS>                       QoS;

        public:
            AppConfigurationPtr                                     GetConfiguration() noexcept;
            ContextPtr                                              GetContext() noexcept;

        public:
            virtual std::shared_ptr<Byte>                           Read(YieldContext& y, int& outlen) noexcept;
            virtual bool                                            Write(YieldContext& y, const void* packet, int packet_length) noexcept;
            virtual bool                                            Write(const void* packet, int packet_length, const AsynchronousWriteCallback& cb) noexcept;
            virtual void                                            Dispose() noexcept override;
            virtual boost::asio::ip::tcp::endpoint                  GetRemoteEndPoint() noexcept;

        public:
            virtual Int128                                          HandshakeClient(YieldContext& y, bool& mux) noexcept;
            virtual bool                                            HandshakeServer(YieldContext& y, const Int128& session_id, bool mux) noexcept;

        public:
            std::shared_ptr<Byte>                                   Encrypt(Byte* data, int datalen, int& outlen) noexcept;
            std::shared_ptr<Byte>                                   Decrypt(Byte* data, int datalen, int& outlen) noexcept;

        protected:
            virtual std::shared_ptr<Byte>                           DoReadBytes(YieldContext& y, int length) noexcept = 0;

        private:
            void                                                    Finalize() noexcept;

        private:
            struct {
                bool                                                disposed_   : 1;
                bool                                                handshaked_ : 7;
            };
            ContextPtr                                              context_;
            CiphertextPtr                                           protocol_;
            CiphertextPtr                                           transport_;
            AppConfigurationPtr                                     configuration_;
        };
    }
}