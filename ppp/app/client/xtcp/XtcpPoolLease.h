#pragma once

#include <memory>

namespace ppp::app::client::xtcp {

class XtcpPoolLease final {
public:
    XtcpPoolLease() noexcept = default;
    ~XtcpPoolLease() noexcept;
    XtcpPoolLease(const XtcpPoolLease&) = delete;
    XtcpPoolLease& operator=(const XtcpPoolLease&) = delete;

    static std::unique_ptr<XtcpPoolLease> Acquire() noexcept;

private:
    explicit XtcpPoolLease(bool acquired) noexcept : acquired_(acquired) {}
    bool acquired_ = false;
};

} // namespace ppp::app::client::xtcp
