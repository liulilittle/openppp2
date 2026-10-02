#pragma once

#include <ppp/app/protocol/XtcpDirectIo.h>

namespace ppp::app::client::xtcp {

using XtcpUploadBudget = ppp::app::protocol::XtcpUploadBudget;
using XtcpUploadChunk = ppp::app::protocol::XtcpUploadChunk;
using XtcpDirectResult = ppp::app::protocol::XtcpDirectResult;
using XtcpDirectReadReservation = ppp::app::protocol::XtcpDirectReadReservation;
using XtcpDirectCompletion = ppp::app::protocol::XtcpDirectCompletion;
using XtcpDirectCloseReason = ppp::app::protocol::XtcpDirectCloseReason;

} // namespace ppp::app::client::xtcp
