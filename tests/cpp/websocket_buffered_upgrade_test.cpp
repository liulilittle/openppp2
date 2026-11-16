#define BOOST_TEST_MODULE websocket_buffered_upgrade
#include <boost/test/included/unit_test.hpp>
#include <boost/beast/core/buffers_to_string.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/_experimental/test/stream.hpp>
#include <sstream>

BOOST_AUTO_TEST_CASE(upgrade_preserves_first_pipelined_frame) {
    namespace beast = boost::beast;
    boost::asio::io_context context;
    beast::websocket::stream<beast::test::stream> ws(context);
    beast::test::stream peer(context);
    beast::test::connect(ws.next_layer(), peer);
    const std::string request = "GET / HTTP/1.1\r\nHost: localhost\r\n"
        "Upgrade: websocket\r\nConnection: upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n";
    beast::http::request_parser<beast::http::dynamic_body> parser;
    boost::system::error_code ec;
    parser.put(boost::asio::buffer(request), ec);
    BOOST_REQUIRE(!ec);
    std::ostringstream serialized;
    serialized << parser.get();
    std::string prefill = serialized.str();
    const unsigned char frame[] = {0x81, 0x82, 0, 0, 0, 0, 'h', 'i'};
    prefill.append(reinterpret_cast<const char*>(frame), sizeof(frame));
    beast::flat_buffer result;
    bool accepted = false, read = false;
    ws.async_accept(boost::asio::buffer(prefill), [&](boost::system::error_code error) {
        BOOST_REQUIRE(!error);
        accepted = true;
        ws.async_read(result, [&](boost::system::error_code error, std::size_t size) {
            BOOST_REQUIRE(!error);
            BOOST_TEST(size == 2u);
            read = true;
        });
    });
    context.run();
    BOOST_TEST(accepted);
    BOOST_TEST(read);
    BOOST_TEST(beast::buffers_to_string(result.data()) == "hi");
}
