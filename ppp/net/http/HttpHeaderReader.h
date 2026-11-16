#pragma once

/**
 * @file HttpHeaderReader.h
 * @brief Reads and splits raw HTTP/1.x request headers from a TCP socket.
 */

#include <ppp/coroutines/YieldContext.h>
#include <ppp/io/MemoryStream.h>

namespace ppp {
    namespace net {
        namespace http {
            /**
             * @brief Reads from @p socket until the header terminator "\r\n\r\n" has arrived.
             * @param headers Receives every byte read, including any bytes after the terminator.
             * @param y Coroutine yield context.
             * @param socket Open source socket.
             * @return True when the full header block has been read.
             */
            bool                                                                    ReadHttpHeaders(ppp::io::MemoryStream& headers, ppp::coroutines::YieldContext& y, boost::asio::ip::tcp::socket& socket) noexcept;

            /**
             * @brief Splits buffered header bytes into CRLF-separated lines.
             * @param headers Buffered header bytes.
             * @param lines Receives the lines.
             * @param raw Optional; receives the whole buffered text.
             * @return True when at least one line was produced.
             */
            bool                                                                    SplitHttpHeaderLines(ppp::io::MemoryStream& headers, ppp::vector<ppp::string>& lines, ppp::string* raw) noexcept;
        }
    }
}
