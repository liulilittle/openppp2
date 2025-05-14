#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/net/Ipep.h>

namespace ppp 
{
    namespace auxiliary 
    {
        Int128 StringAuxiliary::GuidStringToInt128(const ppp::string& guid_string) noexcept 
        {
            if (guid_string.empty()) 
            {
                return 0;
            }

            boost::uuids::uuid guid = StringToGuid(guid_string);
#if BOOST_VERSION >= 108600
            return ppp::net::Ipep::NetworkToHostOrder(*(Int128*)&guid);
#else
            return ppp::net::Ipep::NetworkToHostOrder(*(Int128*)guid.data);
#endif
        }

        ppp::string StringAuxiliary::Int128ToGuidString(const Int128& guid) noexcept 
        {
            boost::uuids::uuid uuid;
#if BOOST_VERSION >= 108600
            *(Int128*)&uuid = ppp::net::Ipep::HostToNetworkOrder(guid);
#else
            *(Int128*)uuid.data = ppp::net::Ipep::HostToNetworkOrder(guid);
#endif
            return GuidToString(uuid);
        }

        bool StringAuxiliary::WhoisIntegerValueString(const ppp::string& integer_string) noexcept
        {
            int integer_size = integer_string.size();
            if (integer_size < 1)
            {
                return false;
            }

            const char* integer_string_memory = integer_string.data();
            for (int i = 0; i < integer_size; i++)
            {
                char ch = integer_string_memory[i];
                if (ch >= '0' && ch <= '9')
                {
                    continue;
                }

                if (i == 0)
                {
                    if (ch == '-' || ch == '+')
                    {
                        continue;
                    }
                }
                return false;
            }
            return true;
        }

        ppp::string StringAuxiliary::Lstrings(const ppp::string& in, bool colon) noexcept
        {
            static constexpr char keys[] = "; |+*^&#@!'\?%[]{}\\/-_=`~\r\n\t\a\b\v\f";

            if (in.empty()) 
            {
                return ppp::string();
            }

            ppp::string result = in;
            if (colon)
            {
                result = Replace<ppp::string>(result, ":", ",");
            }
            
            for (char ch : keys) 
            {
                char str[2] = { ch, '\x0' };
                result = Replace<ppp::string>(result, str, ",");
            }

            return result;
        }
    }
}