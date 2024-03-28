#pragma once

#include <ppp/transmissions/ITransmission.h>

namespace ppp {
    namespace transmissions {
        class ITcpipTransmission : public ITransmission {
            friend class ITransmissionQoS;

        public:
            ITcpipTransmission(
                const ContextPtr&                                       context, 
                const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket, 
                const AppConfigurationPtr&                              configuration) noexcept;
            virtual ~ITcpipTransmission() noexcept;

        public:
            virtual void                                                Dispose() noexcept override;
            virtual boost::asio::ip::tcp::endpoint                      GetRemoteEndPoint() noexcept override;
            virtual std::shared_ptr<Byte>                               ReadBytes(YieldContext& y, int length) noexcept;

        protected:
            virtual std::shared_ptr<Byte>                               DoReadBytes(YieldContext& y, int length) noexcept;
            virtual bool                                                DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept;
        
        private:
            void                                                        Finalize() noexcept;

        private:
            bool                                                        disposed_ = false;
            std::shared_ptr<boost::asio::ip::tcp::socket>               socket_;
            boost::asio::ip::tcp::endpoint                              remoteEP_;
        };
    }
}