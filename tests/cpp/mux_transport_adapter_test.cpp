#define BOOST_TEST_MODULE mux_transport_adapter_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/mux/MuxTransportAdapter.h>

namespace mux = ppp::app::mux;

namespace {

class FakeConnection final {
public:
    using ContextPtr = std::shared_ptr<boost::asio::io_context>;
    using StrandPtr = ppp::threading::Executors::StrandPtr;
    using ITransmissionPtr = std::shared_ptr<ppp::transmissions::ITransmission>;

    bool IsLinked() noexcept { return linked; }
    ContextPtr GetContext() noexcept { return context; }
    StrandPtr GetStrand() noexcept { return strand; }
    const ITransmissionPtr& GetTransmission() noexcept { return transmission; }
    ppp::Int128 GetId() noexcept { return id; }
    void Update() noexcept { ++updates; }
    void Dispose() noexcept { ++disposals; linked = false; }

    bool linked = true;
    ContextPtr context = std::make_shared<boost::asio::io_context>();
    StrandPtr strand = std::make_shared<ppp::threading::Executors::Strand>(
        context->get_executor());
    ITransmissionPtr transmission;
    ppp::Int128 id = 17;
    int updates = 0;
    int disposals = 0;
};

} // namespace

BOOST_AUTO_TEST_CASE(adapter_forwards_transport_state_and_disposes_owner_once) {
    auto connection = std::make_shared<FakeConnection>();
    auto transmission_owner = std::make_shared<int>(1);
    connection->transmission = FakeConnection::ITransmissionPtr(
        transmission_owner,
        reinterpret_cast<ppp::transmissions::ITransmission*>(transmission_owner.get()));
    auto owner_lifetime = std::make_shared<int>(2);
    std::weak_ptr<int> owner_lifetime_view = owner_lifetime;
    int owner_disposals = 0;
    auto transport = mux::MakeMuxTransport(
        connection, [owner_lifetime, &owner_disposals]() noexcept { ++owner_disposals; });
    owner_lifetime.reset();

    BOOST_REQUIRE(transport);
    BOOST_TEST(transport->IsLinked());
    BOOST_TEST(transport->GetContext() == connection->context);
    BOOST_TEST(transport->GetStrand() == connection->strand);
    BOOST_TEST(transport->GetTransmission() == connection->transmission);
    BOOST_TEST(static_cast<bool>(transport->GetId() == connection->id));

    transport->Update();
    BOOST_TEST(connection->updates == 1);

    transport->Dispose();
    transport->Dispose();
    BOOST_TEST(connection->disposals == 1);
    BOOST_TEST(owner_disposals == 1);
    BOOST_TEST(!transport->IsLinked());
    BOOST_TEST(!owner_lifetime_view.expired());
    transport.reset();
    BOOST_TEST(owner_lifetime_view.expired());
}
