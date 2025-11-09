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
            return StringAuxiliary::GuidStringToInt128(guid);
        }

        Int128 StringAuxiliary::GuidStringToInt128(const boost::uuids::uuid& guid) noexcept
        {
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

        ppp::string StringAuxiliary::ToString(const ppp::unordered_map<ppp::string, ppp::string>& s) noexcept
        {
            ppp::string result;
            for (auto&& [k, v] : s)
            {
                if (!result.empty()) 
                {
                    result += k + ": " + v;
                }
                else
                {
                    result += "\r\n" + k + ": " + v;
                }
            }

            return result;
        }

        bool StringAuxiliary::ToDictionary(const ppp::vector<ppp::string>& lines, ppp::unordered_map<ppp::string, ppp::string>& s) noexcept 
        {
            for (size_t i = 0, l = lines.size(); i < l; ++i)
            {
                const ppp::string& str = lines[i];
                size_t j = str.find(':');
                if (j == ppp::string::npos) 
                {
                    continue;
                }

                size_t n = j + 2;
                if (n >= str.size())
                {
                    continue;
                }

                ppp::string left = str.substr(0, j); 
                if (left.empty()) 
                {
                    continue;
                }
                else 
                {
                    s[left] = str.substr(n);
                }
            }

            return true;
        }

        bool StringAuxiliary::ToDictionary(const ppp::string& lines, ppp::unordered_map<ppp::string, ppp::string>& s) noexcept
        {
            ppp::vector<ppp::string> lists;
            Tokenize<ppp::string>(lines, lists, "\r\n");

            return ToDictionary(lists, s);
        }
    }
}