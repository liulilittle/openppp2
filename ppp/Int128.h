#pragma once 

#include <ppp/stdafx.h>

namespace ppp
{
    /* ABI: https://developer.android.com/ndk/guides/cpu-features
     * ABI: Use the preprocessor's pre-defined macros
     * It's usually most convenient to determine the ABI at build time using #ifdef in conjunction with:
     *
     * __arm__ for 32-bit ARM
     * __aarch64__ for 64-bit ARM
     * __i386__ for 32-bit X86
     * __x86_64__ for 64-bit X86
     * Note that 32-bit X86 is called __i386__, not __x86__ as you might expect!
     */
#if defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
#define _PPP_INT128 1
#elif defined(_WIN32) || defined(__arm__) || defined(_ANDROID)
#define _PPP_INT128 1
#elif defined(mips) || defined(__mips__) || defined(__mips)
     /* INT128 is implemented using the GUN C/C++ compiler on the MIPS64 architecture, otherwise INT128 is implemented using PPP. */
#if !(defined(__mips64) || defined(__mips64__) || defined(__LP64__))
#define _PPP_INT128 1
#endif
#endif

#if defined(_PPP_INT128)
#pragma pack(push, 1)
    class Int128 final
    {
    public:
        unsigned long long                                              lo;
        signed long long                                                hi;

    public:
        Int128() : lo(0), hi(0) {};
        Int128(signed char value);
        Int128(signed short int value);
        Int128(signed int value);
        Int128(signed long int value);
        Int128(signed long long value);
        Int128(bool value) : lo(value), hi(0) {};
        Int128(unsigned char value) : lo(value), hi(0) {};
        Int128(unsigned short value) : lo(value), hi(0) {};
        Int128(unsigned int value) : lo(value), hi(0) {};
        Int128(unsigned long int value) : lo(value), hi(0) {};
        Int128(unsigned long long value) : lo(value), hi(0) {};
        Int128(const Int128& value) : lo(value.lo), hi(value.hi) {};
        Int128(const signed long long& high, const unsigned long long& low) : lo(low), hi(high) {};

    private:
        Int128(int sign, unsigned int* ints, int intslen);

    public:
        Int128&                                                         operator = (const Int128& value);
        friend bool                                                     operator == (const Int128& left, const Int128& right);
        friend bool                                                     operator != (const Int128& left, const Int128& right);
        friend bool                                                     operator < (const Int128& left, const Int128& right);
        friend bool                                                     operator > (const Int128& left, const Int128& right);
        friend bool                                                     operator <= (const Int128& left, const Int128& right);
        friend bool                                                     operator >= (const Int128& left, const Int128& right);
        friend Int128                                                   operator + (const Int128& left, const Int128& right);
        friend Int128                                                   operator - (const Int128& left, const Int128& right);
        friend Int128                                                   operator * (const Int128& left, const Int128& right);
        friend Int128                                                   operator / (const Int128& left, const Int128& right);
        friend Int128                                                   operator % (const Int128& left, const Int128& right);
        Int128                                                          operator - () const;
        Int128&                                                         operator ++ () const;
        Int128                                                          operator ++ (int) const;
        Int128&                                                         operator -- () const;
        Int128                                                          operator -- (int) const;
        Int128&                                                         operator += (const Int128& value);
        Int128&                                                         operator -= (const Int128& value);
        friend std::ostream&                                            operator << (std::ostream& out, const Int128& value);
        friend std::istream&                                            operator >> (std::istream& in, const Int128& value);
        friend Int128                                                   operator ~ (const Int128& value);
        friend Int128                                                   operator | (const Int128& left, const Int128& right);
        friend Int128                                                   operator & (const Int128& left, const Int128& right);
        friend Int128                                                   operator ^ (const Int128& left, const Int128& right);
        friend Int128                                                   operator << (const Int128& value, int shift);
        friend Int128                                                   operator >> (const Int128& value, int shift);

#if defined(WIN32) || __cplusplus >= 201103L        
    public:     
        explicit                                                        operator bool() const;
        explicit                                                        operator signed char() const;
        explicit                                                        operator signed short int() const;
        explicit                                                        operator signed int() const;
        explicit                                                        operator signed long() const;
        explicit                                                        operator signed long long() const;
        explicit                                                        operator unsigned char() const;
        explicit                                                        operator unsigned short() const;
        explicit                                                        operator unsigned int() const;
        explicit                                                        operator unsigned long() const;
        explicit                                                        operator unsigned long long() const;
#endif      

    public:     
        int                                                             Sign();

        template <typename TString>     
        static Int128                                                   Parse(const TString& v, int radix);

    public:     
        template <typename TString>     
        TString                                                         ToString();

        template <typename TString>     
        TString                                                         ToString(int radix);

        template <typename TString>     
        TString                                                         ToHex();

        template <typename TString>     
        TString                                                         ToBinary();

    private:        
        static Int128                                                   Multiply(Int128 left, Int128 right);
        static Int128                                                   DivRem(Int128 dividend, Int128 divisor, Int128& remainder);

    private:        
        void                                                            Negate();
        static int                                                      GetNormalizeShift(unsigned int value);
        static int                                                      GetLength(unsigned int* uints, int uintslen);
        static void                                                     Normalize(unsigned int* u, int l, unsigned int* un, int shift);
        static void                                                     Unnormalize(unsigned int* un, unsigned int* r, int shift);
        static void                                                     DivModUnsigned(unsigned int* u, unsigned int* v, unsigned int*& q, unsigned int*& r);

    public:
        static const unsigned long long                                 Base32 = 0x100000000;
        static const unsigned long long                                 NegativeSignMask = 0x1ull << 63;
    };
#pragma pack(pop)

    inline Int128::Int128(signed char value)
    {
        hi = (unsigned long long)(value < 0 ? ~0 : 0);
        lo = (unsigned long long)value;
    }

    inline Int128::Int128(signed short int value)
    {
        hi = (unsigned long long)(value < 0 ? ~0 : 0);
        lo = (unsigned long long)value;
    }

    inline Int128::Int128(signed int value)
    {
        hi = (unsigned long long)(value < 0 ? ~0 : 0);
        lo = (unsigned long long)value;
    }

    inline Int128::Int128(signed long int value)
    {
        hi = (unsigned long long)(value < 0 ? ~0 : 0);
        lo = (unsigned long long)value;
    }

    inline Int128::Int128(signed long long value)
    {
        hi = (unsigned long long)(value < 0 ? ~0 : 0);
        lo = (unsigned long long)value;
    }

    inline Int128::Int128(int sign, unsigned int* ints, int intslen)
    {
        unsigned long long value[2];
        memset(value, 0, sizeof(value));
        for (int i = 0; i < intslen && i < 4; i++)
        {
            memcpy((i * 4) + (char*)value, ints + i, 4);
        }

        hi = value[1];
        lo = value[0];

        if (sign < 0 && (hi > 0 || lo > 0))
        {
            Negate();
            hi |= NegativeSignMask;
        }
    }

    inline Int128& Int128::operator=(const Int128& value)
    {
        lo = value.lo;
        hi = value.hi;
        return *this;
    }

    inline Int128 Int128::operator-() const
    {
        Int128 x = *this;
        x.Negate();
        return x;
    }

    inline Int128& Int128::operator++() const
    {
        Int128& r = const_cast<Int128&>(*this);
        r += 1;
        return r;
    }

    inline Int128 Int128::operator++(int) const
    {
        Int128& c = const_cast<Int128&>(*this);
        Int128 r = c;
        c += 1;
        return r;
    }

    inline Int128& Int128::operator--() const
    {
        Int128& r = const_cast<Int128&>(*this);
        r -= 1;
        return r;
    }

    inline Int128 Int128::operator--(int) const
    {
        Int128& c = const_cast<Int128&>(*this);
        Int128 r = c;
        c -= 1;
        return r;
    }

    inline Int128& Int128::operator+=(const Int128& value)
    {
        *this = *this + value;
        return *this;
    }

    inline Int128& Int128::operator-=(const Int128& value)
    {
        *this = *this - value;
        return *this;
    }

    inline bool operator==(const Int128& left, const Int128& right)
    {
        return (left.lo == right.lo) && (left.hi == right.hi);
    }

    inline bool operator!=(const Int128& left, const Int128& right)
    {
        return !(left == right);
    }

    inline bool operator<(const Int128& left, const Int128& right)
    {
        if (left.hi != right.hi)
        {
            return left.hi < right.hi;
        }
        return left.lo < right.lo;
    }

    inline bool operator>(const Int128& left, const Int128& right)
    {
        if (left.hi != right.hi)
        {
            return left.hi > right.hi;
        }
        return left.lo > right.lo;
    }

    inline bool operator<=(const Int128& left, const Int128& right)
    {
        return (left == right) || (left < right);
    }

    inline bool operator>=(const Int128& left, const Int128& right)
    {
        return (left == right) || (left > right);
    }

    inline Int128 operator+(const Int128& left, const Int128& right)
    {
        Int128 value;
        value.hi = left.hi + right.hi;
        value.lo = left.lo + right.lo;
        
        // Carry
        if (value.lo < left.lo)
        {
            value.hi++;
        }
        return value;
    }

    inline Int128 operator-(const Int128& left, const Int128& right)
    {
        return left + (-right);
    }

    inline Int128 operator*(const Int128& left, const Int128& right)
    {
        return Int128::Multiply(left, right);
    }

    inline Int128 operator/(const Int128& left, const Int128& right)
    {
        Int128 remainder = 0;
        return Int128::DivRem(left, right, remainder);
    }

    inline Int128 operator%(const Int128& left, const Int128& right)
    {
        Int128 remainder = 0;
        Int128::DivRem(left, right, remainder);
        return remainder;
    }

    inline std::ostream& operator<<(std::ostream& out, const Int128& value)
    {
        return out.write((char*)&value.lo, 16);
    }

    inline std::istream& operator>>(std::istream& in, const Int128& value)
    {
        return in.read((char*)&value.lo, 16);
    }

    inline Int128 operator~(const Int128& value)
    {
        return Int128(~value.hi, ~value.lo);
    }

    inline Int128 operator|(const Int128& left, const Int128& right)
    {
        if (left == 0)
        {
            return right;
        }

        if (right == 0)
        {
            return left;
        }

        Int128 R = left;
        R.hi |= right.hi;
        R.lo |= right.lo;
        return R;
    }

    inline Int128 operator&(const Int128& left, const Int128& right)
    {
        if (left == 0)
        {
            return right;
        }

        if (right == 0)
        {
            return left;
        }

        Int128 R = left;
        R.hi &= right.hi;
        R.lo &= right.lo;
        return R;
    }

    inline Int128 operator^(const Int128& left, const Int128& right)
    {
        if (left == 0)
        {
            return right;
        }

        if (right == 0)
        {
            return left;
        }

        Int128 R = left;
        R.hi ^= right.hi;
        R.lo ^= right.lo;
        return R;
    }

    inline Int128 operator<<(const Int128& value, int shift)
    {
        if (shift == 0 || value == 0)
        {
            return value;
        }

        if (shift < 0)
        {
            return value >> -shift;
        }

        unsigned long long* values = (unsigned long long*)&value.lo;

        shift = shift % 128;

        int shiftOffset = shift / 64;
        int bshift = shift % 64;

        unsigned long long shifted[2];
        memset(shifted, 0, sizeof(shifted));

        for (int i = 0; i < 2; i++)
        {
            int ishift = i + shiftOffset;
            if (ishift >= 2)
            {
                continue;
            }

            shifted[ishift] |= values[i] << bshift;
            if (bshift > 0 && i - 1 >= 0)
            {
                shifted[ishift] |= values[i - 1] >> (64 - bshift);
            }
        }

        return Int128((signed long long)(shifted[1]), shifted[0]); // lo is stored in array entry 0  
    }

    inline Int128 operator>>(const Int128& value, int shift)
    {
        if (shift == 0 || value == 0)
        {
            return value;
        }

        if (shift < 0)
        {
            return value << -shift;
        }

        unsigned long long* values = (unsigned long long*)&value.lo;
        shift = shift % 128;     // This is the defined behavior of shift. Shifting by greater than the number of bits uses a mod

        //
        //  First, shift over by full ulongs. This could be optimized a bit for longer arrays (if shifting by multiple longs, we do more copies 
        //  than needed), but for short arrays this is probably the best way to go
        //
        while (shift >= 64)
        {
            for (int i = 0; i < 1; i++)
            {
                values[i] = values[i + 1];
            }

            values[1] = (unsigned long long)((signed long long)values[1] >> (64 - 1));    // Preserve sign of upper long, will either be 0 or all f's
            shift -= 64;
        }

        //
        //  Now, we just have a sub-long shift left to do (shift will be < 64 at this point)
        //
        if (shift == 0)
        {
            return value;
        }

        int bshift = 64 - shift;

        //
        //  In right shifting, upper val is a special case because we need to preserve the sign bits, and because we don't need to or in
        //  any other values
        //
        unsigned long long shifted[2];
        memset(shifted, 0, sizeof(shifted));

        shifted[1] = (unsigned long long)((signed long long)values[1] >> shift);    // Preserve sign of upper long
        for (int i = 0; i < 1; i++)
        {
            shifted[i] = values[i] >> shift;                   // Unsigned, so upper bits stay zero
            shifted[i] |= (values[i + 1] << bshift);
        }

        return Int128((signed long long)(shifted[1]), shifted[0]); // lo is stored in array entry 0  
    }

#if defined(WIN32) || __cplusplus >= 201103L
    inline Int128::operator bool() const
    {
        return lo != 0 || hi != 0;
    }

    inline Int128::operator signed char() const
    {
        return (signed char)lo;
    }

    inline Int128::operator signed short int() const
    {
        return (signed short int)lo;
    }

    inline Int128::operator signed int() const
    {
        return (signed int)lo;
    }

    inline Int128::operator signed long() const
    {
        return (signed long)lo;
    }

    inline Int128::operator signed long long() const
    {
        return (signed long long)lo;
    }

    inline Int128::operator unsigned int() const
    {
        return (unsigned int)lo;
    }

    inline Int128::operator unsigned long() const
    {
        return (unsigned long)lo;
    }

    inline Int128::operator unsigned char() const
    {
        return (unsigned char)lo;
    }

    inline Int128::operator unsigned short() const
    {
        return (unsigned short)lo;
    }

    inline Int128::operator unsigned long long() const
    {
        return (unsigned long long)lo;
    }
#endif

    inline int Int128::Sign()
    {
        if (hi == 0 && lo == 0)
        {
            return 0;
        }

        return ((hi & NegativeSignMask) == 0) ? 1 : -1;
    }

    template <typename TString>
    inline TString Int128::ToString(int radix)
    {
        return stl::to_string<TString, Int128>(*this, radix);
    }

    template <typename TString>
    inline TString Int128::ToString()
    {
        return ToString<TString>(10);
    }

    template <typename TString>
    inline TString Int128::ToHex()
    {
        return ToString<TString>(16);
    }

    template <typename TString>
    inline TString Int128::ToBinary()
    {
        return ToString<TString>(2);
    }

    inline Int128 Int128::Multiply(Int128 left, Int128 right)
    {
        int leftSign = left.Sign();
        left = leftSign < 0 ? -left : left;

        int rightSign = right.Sign();
        right = rightSign < 0 ? -right : right;

        unsigned int xInts[4];
        unsigned int yInts[4];
        memcpy(xInts, &left.lo, 16);
        memcpy(yInts, &right.lo, 16);

        unsigned int mulInts[8] = { 0 };
        for (int i = 0; i < 4; i++)
        {
            int index = i;
            unsigned long long remainder = 0;
            for (int j = 0; j < 4; j++)
            {
                unsigned int yi = yInts[j];
                remainder = remainder + (unsigned long long)xInts[i] * yi + mulInts[index];
                mulInts[index++] = (unsigned int)remainder;
                remainder = remainder >> 32;
            }

            while (remainder != 0)
            {
                remainder += mulInts[index];
                mulInts[index++] = (unsigned int)remainder;
                remainder = remainder >> 32;
            }
        }

        return Int128(leftSign * rightSign, mulInts, 8);
    }

    inline int Int128::GetLength(unsigned int* uints, int uintslen)
    {
        int index = uintslen - 1;
        while ((index >= 0) && (uints[index] == 0))
        {
            index--;
        }

        index = index < 0 ? 0 : index;
        return index + 1;
    }

    inline Int128 Int128::DivRem(Int128 dividend, Int128 divisor, Int128& remainder)
    {
        if (divisor == 0 || dividend == 0)
        {
            return 0; // DivideByZeroException
        }

        int dividendSign = dividend.Sign();
        dividend = dividendSign < 0 ? -dividend : dividend;

        int divisorSign = divisor.Sign();
        divisor = divisorSign < 0 ? -divisor : divisor;

        unsigned int aquotient[4] = { 0 };
        unsigned int arem[4] = { 0 };

        unsigned int* quotient = aquotient;
        unsigned int* rem = arem;
        unsigned int* u = (unsigned int*)&dividend.lo;
        unsigned int* v = (unsigned int*)&divisor.lo;
        Int128::DivModUnsigned(u, v, quotient, rem);

        remainder = Int128(1, rem, 4);
        return Int128(dividendSign * divisorSign, quotient, 4);
    }

    inline void Int128::Negate()
    {
        hi = ~hi;
        lo = ~lo;
        (*this) += 1;
    }

    inline int Int128::GetNormalizeShift(unsigned int value)
    {
        int shift = 0;

        if ((value & 0xFFFF0000) == 0)
        {
            value <<= 16;
            shift += 16;
        }
        if ((value & 0xFF000000) == 0)
        {
            value <<= 8;
            shift += 8;
        }
        if ((value & 0xF0000000) == 0)
        {
            value <<= 4;
            shift += 4;
        }
        if ((value & 0xC0000000) == 0)
        {
            value <<= 2;
            shift += 2;
        }
        if ((value & 0x80000000) == 0)
        {
            value <<= 1;
            shift += 1;
        }

        return shift;
    }

    inline void Int128::Normalize(unsigned int* u, int l, unsigned int* un, int shift)
    {
        unsigned int carry = 0;
        int i;
        if (shift > 0)
        {
            int rshift = 32 - shift;
            for (i = 0; i < l; i++)
            {
                unsigned int ui = u[i];
                un[i] = (ui << shift) | carry;
                carry = ui >> rshift;
            }
        }
        else
        {
            for (i = 0; i < l; i++)
            {
                un[i] = u[i];
            }
        }

        while (i < 4)
        {
            un[i++] = 0;
        }

        if (carry != 0)
        {
            un[l] = carry;
        }
    }

    inline void Int128::Unnormalize(unsigned int* un, unsigned int* r, int shift)
    {
        int length = 4;
        if (shift > 0)
        {
            int lshift = 32 - shift;
            unsigned int carry = 0;
            for (int i = length - 1; i >= 0; i--)
            {
                unsigned int uni = un[i];
                r[i] = (uni >> shift) | carry;
                carry = (uni << lshift);
            }
        }
        else
        {
            for (int i = 0; i < length; i++)
            {
                r[i] = un[i];
            }
        }
    }

    inline void Int128::DivModUnsigned(unsigned int* u, unsigned int* v, unsigned int*& q, unsigned int*& r)
    {
        int m = GetLength(u, 4);
        int n = GetLength(v, 4);

        if (n <= 1)
        {
            //  Divide by single digit
            //
            unsigned long long rem = 0;
            unsigned int v0 = v[0];

            for (int j = m - 1; j >= 0; j--)
            {
                rem *= Base32;
                rem += u[j];

                unsigned long long div = rem / v0;
                rem -= div * v0;
                q[j] = (unsigned int)div;
            }
            r[0] = (unsigned int)rem;
        }
        else if (m >= n)
        {
            int shift = GetNormalizeShift(v[n - 1]);

            unsigned int un[4] = { 0 };
            unsigned int vn[4] = { 0 };

            Normalize(u, m, un, shift);
            Normalize(v, n, vn, shift);

            //  Main division loop
            //
            for (int j = m - n; j >= 0; j--)
            {
                unsigned long long rr, qq;
                unsigned int tvn;
                int i;

                rr = Base32 * un[j + n] + un[j + n - 1];
                tvn = vn[n - 1];
                if (tvn != 0) 
                {
                    qq = rr / tvn;
                    rr -= qq * tvn;
                }
                else
                {
                    qq = 0;
                }

                for (;;)
                {
                    // Estimate too big ?
                    //
                    if ((qq >= Base32) || (qq*vn[n - 2] > (rr*Base32 + un[j + n - 2])))
                    {
                        qq--;
                        rr += vn[n - 1];
                        if (rr < Base32)
                        {
                            continue;
                        }
                    }
                    break;
                }

                //  Multiply and subtract
                //
                signed long long b = 0;
                signed long long t = 0;
                for (i = 0; i < n; i++)
                {
                    unsigned long long p = vn[i] * qq;
                    t = un[i + j] - (signed long long)(unsigned int)p - b;
                    un[i + j] = (unsigned int)t;
                    p >>= 32;
                    t >>= 32;
                    b = (signed long long)p - t;
                }

                t = un[j + n] - b;
                un[j + n] = (unsigned int)t;

                //  Store the calculated value
                //
                q[j] = (unsigned int)qq;

                //  Add back vn[0..n] to un[j..j+n]
                //
                if (t < 0)
                {
                    q[j]--;
                    unsigned long long c = 0;
                    for (i = 0; i < n; i++)
                    {
                        c = (unsigned long long)vn[i] + un[j + i] + c;
                        un[j + i] = (unsigned int)c;
                        c >>= 32;
                    }
                    c += un[j + n];
                    un[j + n] = (unsigned int)c;
                }
            }

            Unnormalize(un, r, shift);
        }
        else
        {
            memset(q, 0, 16);
            memcpy(r, u, 16);
        }
    }
#else
    typedef __int128_t Int128;
#endif

    inline Int128 MAKE_OWORD(uint64_t low, uint64_t high) noexcept 
    {
        // 1 byte (8 bit): byte, DB, RESB
        // 2 bytes (16 bit): word, DW, RESW
        // 4 bytes (32 bit): dword, DD, RESD
        // 8 bytes (64 bit): qword, DQ, RESQ
        // 10 bytes (80 bit): tword, DT, REST
        // 16 bytes (128 bit): oword, DO, RESO, DDQ, RESDQ
        // 32 bytes (256 bit): yword, DY, RESY
        // 64 bytes (512 bit): zword, DZ, RESZ
    
#if defined(_PPP_INT128)
        return Int128(high, low);
#else
        return ((Int128)high << 64) | ((Int128)low);
#endif
    }
}

#if !defined(_MACOS)
namespace std
{
    template <>
    struct hash<ppp::Int128>
    {
    public:
        std::size_t operator()(const ppp::Int128& v) const noexcept
        {
            std::hash<int64_t> h;
#if defined(_PPP_INT128)
            std::size_t h1 = h(v.lo);
            std::size_t h2 = h(v.hi);
#else
            std::size_t h1 = h((int64_t)(v));
            std::size_t h2 = h((int64_t)(v >> 64));
#endif
            return h1 ^ (h2 << 1); 
        }
    };
}
#endif

namespace stl
{
    template <>
    struct is_signed<ppp::Int128> : true_type {};
}