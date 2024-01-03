#include <ppp/auxiliary/StringAuxiliary.h>

namespace ppp {
    namespace auxiliary {
        Int128 StringAuxiliary::GuidStringToInt128(const ppp::string& guid_string) noexcept {
            if (guid_string.empty()) {
                return 0;
            }

            boost::uuids::uuid guid = StringToGuid(guid_string);
            uint8_t* p = guid.data;
            uint64_t high =
                (uint64_t)p[0] << 0 |
                (uint64_t)p[1] << 8 |
                (uint64_t)p[2] << 16 |
                (uint64_t)p[3] << 24 |
                (uint64_t)p[4] << 32 |
                (uint64_t)p[5] << 40 |
                (uint64_t)p[6] << 48 |
                (uint64_t)p[7] << 56;

            p += sizeof(uint64_t);
            uint64_t low =
                (uint64_t)p[0] << 0 |
                (uint64_t)p[1] << 8 |
                (uint64_t)p[2] << 16 |
                (uint64_t)p[3] << 24 |
                (uint64_t)p[4] << 32 |
                (uint64_t)p[5] << 40 |
                (uint64_t)p[6] << 48 |
                (uint64_t)p[7] << 56;
            return Int128(high, low);
        }

        ppp::string StringAuxiliary::Int128ToGuidString(const Int128& guid) noexcept {
            boost::uuids::uuid uuid;
            uint8_t* p = uuid.data;
            p[0] = (guid.hi >> 0) & 0xff;
            p[1] = (guid.hi >> 8) & 0xff;
            p[2] = (guid.hi >> 16) & 0xff;
            p[3] = (guid.hi >> 24) & 0xff;
            p[4] = (guid.hi >> 32) & 0xff;
            p[5] = (guid.hi >> 40) & 0xff;
            p[6] = (guid.hi >> 48) & 0xff;
            p[7] = (guid.hi >> 56) & 0xff;

            p += sizeof(uint64_t);
            p[0] = (guid.lo >> 0) & 0xff;
            p[1] = (guid.lo >> 8) & 0xff;
            p[2] = (guid.lo >> 16) & 0xff;
            p[3] = (guid.lo >> 24) & 0xff;
            p[4] = (guid.lo >> 32) & 0xff;
            p[5] = (guid.lo >> 40) & 0xff;
            p[6] = (guid.lo >> 48) & 0xff;
            p[7] = (guid.lo >> 56) & 0xff;
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
    }
}