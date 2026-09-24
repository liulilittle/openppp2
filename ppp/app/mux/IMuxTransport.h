#pragma once

#include <ppp/transmissions/ITransmission.h>

namespace ppp::app::mux {

class IMuxTransport {
public:
    using ContextPtr = std::shared_ptr<boost::asio::io_context>;
    using StrandPtr = ppp::threading::Executors::StrandPtr;
    using ITransmissionPtr = std::shared_ptr<ppp::transmissions::ITransmission>;

    virtual ~IMuxTransport() noexcept = default;
    virtual bool IsLinked() noexcept = 0;
    virtual ContextPtr GetContext() noexcept = 0;
    virtual StrandPtr GetStrand() noexcept = 0;
    virtual ITransmissionPtr GetTransmission() noexcept = 0;
    virtual Int128 GetId() noexcept = 0;
    virtual void Update() noexcept = 0;
    virtual void Dispose() noexcept = 0;
};

using IMuxTransportPtr = std::shared_ptr<IMuxTransport>;

} // namespace ppp::app::mux
