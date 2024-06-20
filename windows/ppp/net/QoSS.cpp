#include <ppp/stdafx.h>
#include <ppp/net/IPEndPoint.h>

#include <windows/ppp/net/QoSS.h>

#include <Windows.h>
#include <qos2.h>

using ppp::net::IPEndPoint;

namespace ppp
{
    namespace net
    {
        QoSS::QoSS(int fd) noexcept
            : fd_(fd)
            , h_(NULL)
            , f_(NULL)
        {

        }

        QoSS::~QoSS() noexcept
        {
            if (NULL != h_)
            {
                if (f_ != 0)
                {
                    QOSRemoveSocketFromFlow(h_, fd_, f_, 0);
                }

                QOSCloseHandle(h_);
            }
        }

        std::shared_ptr<QoSS> QoSS::New(int fd, const boost::asio::ip::address& host, int port, bool noaddress) noexcept
        {
            if (fd == INVALID_SOCKET)
            {
                return NULL;
            }

            std::shared_ptr<QoSS> qos = make_shared_object<QoSS>(fd);
            if (NULL == qos)
            {
                return NULL;
            }

            QOS_VERSION ver = { 1, 0 };
            if (!QOSCreateHandle(&ver, &qos->h_))
            {
                return NULL;
            }

            if (noaddress)
            {
                if (!QOSAddSocketToFlow(qos->h_, fd, NULL, QOSTrafficTypeControl, QOS_NON_ADAPTIVE_FLOW, &qos->f_))
                {
                    return NULL;
                }
            }
            else
            {
                if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort)
                {
                    return NULL;
                }

                if (!host.is_v4() && !host.is_v6())
                {
                    return NULL;
                }

                if (IPEndPoint::IsInvalid(host))
                {
                    return NULL;
                }

                if (host.is_v4())
                {
                    sockaddr_in in{};
                    in.sin_family = AF_INET;
                    in.sin_port = htons(port);
                    in.sin_addr.s_addr = htonl(host.to_v4().to_uint());

                    if (!QOSAddSocketToFlow(qos->h_, fd, reinterpret_cast<sockaddr*>(&in), QOSTrafficTypeControl, QOS_NON_ADAPTIVE_FLOW, &qos->f_))
                    {
                        return NULL;
                    }
                }
                else
                {
                    sockaddr_in6 in6{};
                    in6.sin6_family = AF_INET6;
                    in6.sin6_port = htons(port);
                    memcpy(&in6.sin6_addr, host.to_v6().to_bytes().data(), sizeof(in6.sin6_addr));

                    if (!QOSAddSocketToFlow(qos->h_, fd, reinterpret_cast<sockaddr*>(&in6), QOSTrafficTypeControl, QOS_NON_ADAPTIVE_FLOW, &qos->f_))
                    {
                        return NULL;
                    }
                }
            }

            // We shift the complete ToS value by 3 to get rid of the 3 bit ECN field
            DWORD dscp = 26;

            // Sets DSCP to the same as Linux
            // This will fail if we're not admin, but we ignore it
            if (!QOSSetFlow(qos->h_, qos->f_, QOSSetOutgoingDSCPValue, sizeof(DWORD), &dscp, 0, NULL))
            {
                return NULL;
            }

            return qos;
        }
    }
}