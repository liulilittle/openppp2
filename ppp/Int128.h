#pragma once

#include <ppp/stdafx.h>
#include <cstdint>
#include <iosfwd>       // for std::ostream, std::istream (lightweight)
#include <iostream>
#include <type_traits>  // for true_type

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

    // 128-bit signed integer with explicit layout for endianness.
    // The member order is adjusted so that on big-endian systems the high part (hi)
    // resides at the lower address, matching the natural memory order of a 128-bit value.
    class Int128 final
    {
    public:
        // Endian-sensitive member order:
        // On little-endian: low part (lo) first, then high part (hi).
        // On big-endian:     high part (hi) first, then low part (lo).
        // This ensures that a raw memory dump of the object corresponds to the
        // expected byte order of the architecture.
#if (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)   // Big-endian: hi at lower address
        signed long long                                                hi = 0;
        unsigned long long                                              lo = 0;
#else                                               // Little-endian: lo at lower address
        unsigned long long                                              lo = 0;
        signed long long                                                hi = 0;
#endif

    public:
        Int128() = default;                                            // Zero-initialized by member initializers
        Int128(signed char value) noexcept : lo(static_cast<unsigned long long>(value)), hi(value < 0 ? ~0ULL : 0ULL) {}
        Int128(signed short int value) noexcept : lo(static_cast<unsigned long long>(value)), hi(value < 0 ? ~0ULL : 0ULL) {}
        Int128(signed int value) noexcept : lo(static_cast<unsigned long long>(value)), hi(value < 0 ? ~0ULL : 0ULL) {}
        Int128(signed long int value) noexcept : lo(static_cast<unsigned long long>(value)), hi(value < 0 ? ~0ULL : 0ULL) {}
        Int128(signed long long value) noexcept : lo(static_cast<unsigned long long>(value)), hi(value < 0 ? ~0ULL : 0ULL) {}
        Int128(bool value) noexcept : lo(value), hi(0) {}
        Int128(unsigned char value) noexcept : lo(value), hi(0) {}
        Int128(unsigned short value) noexcept : lo(value), hi(0) {}
        Int128(unsigned int value) noexcept : lo(value), hi(0) {}
        Int128(unsigned long int value) noexcept : lo(value), hi(0) {}
        Int128(unsigned long long value) noexcept : lo(value), hi(0) {}
        Int128(const Int128& value) noexcept = default;
        Int128(signed long long high, unsigned long long low) noexcept : lo(low), hi(high) {}

    private:
        // Construct from a little-endian 32-bit array (ints[0] = least significant).
        // The sign parameter indicates the sign of the final value.
        Int128(int sign, const unsigned int* ints, int intslen);

    public:
        Int128&                                                         operator=(const Int128& value) noexcept = default;

        // Comparison operators (friends)
        friend bool                                                     operator==(const Int128& left, const Int128& right) noexcept;
        friend bool                                                     operator!=(const Int128& left, const Int128& right) noexcept;
        friend bool                                                     operator<(const Int128& left, const Int128& right) noexcept;
        friend bool                                                     operator>(const Int128& left, const Int128& right) noexcept;
        friend bool                                                     operator<=(const Int128& left, const Int128& right) noexcept;
        friend bool                                                     operator>=(const Int128& left, const Int128& right) noexcept;

        // Arithmetic operators
        friend Int128                                                   operator+(const Int128& left, const Int128& right) noexcept;
        friend Int128                                                   operator-(const Int128& left, const Int128& right) noexcept;
        friend Int128                                                   operator*(const Int128& left, const Int128& right) noexcept;
        friend Int128                                                   operator/(const Int128& left, const Int128& right);
        friend Int128                                                   operator%(const Int128& left, const Int128& right);

        // Unary negation
        Int128                                                          operator-() const noexcept;

        // Increment / decrement (now non-const)
        Int128&                                                         operator++() noexcept;      // prefix
        Int128                                                          operator++(int) noexcept;    // postfix
        Int128&                                                         operator--() noexcept;      // prefix
        Int128                                                          operator--(int) noexcept;    // postfix

        // Compound assignment
        Int128&                                                         operator+=(const Int128& value) noexcept;
        Int128&                                                         operator-=(const Int128& value) noexcept;
        Int128&                                                         operator*=(const Int128& value) noexcept;
        Int128&                                                         operator/=(const Int128& value);
        Int128&                                                         operator%=(const Int128& value);
        Int128&                                                         operator&=(const Int128& value) noexcept;
        Int128&                                                         operator|=(const Int128& value) noexcept;
        Int128&                                                         operator^=(const Int128& value) noexcept;
        Int128&                                                         operator<<=(int shift) noexcept;
        Int128&                                                         operator>>=(int shift) noexcept;

        // Bitwise operators
        friend Int128                                                   operator~(const Int128& value) noexcept;
        friend Int128                                                   operator|(const Int128& left, const Int128& right) noexcept;
        friend Int128                                                   operator&(const Int128& left, const Int128& right) noexcept;
        friend Int128                                                   operator^(const Int128& left, const Int128& right) noexcept;

        // Shift operators (shift count modulo 128, arithmetic right shift for negative numbers)
        friend Int128                                                   operator<<(const Int128& value, int shift) noexcept;
        friend Int128                                                   operator>>(const Int128& value, int shift) noexcept;

        // Stream I/O (binary, always little-endian)
        friend std::ostream&                                            operator<<(std::ostream& out, const Int128& value);
        friend std::istream&                                            operator>>(std::istream& in, Int128& value);   // now non-const reference

#if defined(_MSC_VER) || __cplusplus >= 201103L
        // Explicit conversion operators (C++11 and later)
        explicit                                                        operator bool() const noexcept;
        explicit                                                        operator signed char() const noexcept;
        explicit                                                        operator signed short int() const noexcept;
        explicit                                                        operator signed int() const noexcept;
        explicit                                                        operator signed long() const noexcept;
        explicit                                                        operator signed long long() const noexcept;
        explicit                                                        operator unsigned char() const noexcept;
        explicit                                                        operator unsigned short() const noexcept;
        explicit                                                        operator unsigned int() const noexcept;
        explicit                                                        operator unsigned long() const noexcept;
        explicit                                                        operator unsigned long long() const noexcept;
#endif

    public:
        int                                                             Sign() const noexcept;     // -1, 0, or 1

    public:
        // String conversion (delegates to stl::to_string)
        template <typename TString>
        TString                                                         ToString() const;

        template <typename TString>
        TString                                                         ToString(int radix) const;

        template <typename TString>
        TString                                                         ToHex() const;

        template <typename TString>
        TString                                                         ToBinary() const;

    private:
        // Core arithmetic helpers
        static Int128                                                   Multiply(const Int128& left, const Int128& right) noexcept;
        static Int128                                                   Divide(const Int128& dividend, const Int128& divisor, Int128& remainder);

        // Two's complement negation (modifies *this)
        void                                                            Negate() noexcept;

        // Unsigned absolute value (as two 64-bit parts)
        static void                                                     Absolute(const Int128& val, unsigned long long& out_lo, unsigned long long& out_hi) noexcept;

        // Decompose an Int128 into four 32-bit little-endian parts (parts[0] = least significant).
        // This representation is independent of host endianness and is used for all multi-precision arithmetic.
        static void                                                     Decompose(const Int128& val, unsigned int parts[4]) noexcept;

        // Compose an Int128 from four 32-bit little-endian parts (absolute value, sign not applied).
        static Int128                                                   Compose(const unsigned int parts[4]) noexcept;

        // Division helpers (Knuth's algorithm D)
        static int                                                      GetNormalizeShift(unsigned int value) noexcept;
        static int                                                      GetLength(const unsigned int* uints, int uintslen) noexcept;
        static void                                                     Normalize(const unsigned int* u, int l, unsigned int* un, int shift) noexcept;
        static void                                                     Unnormalize(const unsigned int* un, unsigned int* r, int shift) noexcept;
        static void                                                     DivModUnsigned(const unsigned int* u, const unsigned int* v, unsigned int* q, unsigned int* r) noexcept;

    public:
        static const unsigned long long                                 Base32 = 0x100000000ULL;
        static const unsigned long long                                 NegativeSignMask = 0x1ULL << 63;   // mask for the sign bit in hi
    };
#pragma pack(pop)

    // -------------------------------------------------------------------------
    // Constructors from signed integral types
    // (Already defined inline in the class; no need for separate definitions)
    // -------------------------------------------------------------------------

    // Construct from a little-endian 32-bit array (ints[0] = least significant).
    // The sign parameter indicates the sign of the final value.
    inline Int128::Int128(int sign, const unsigned int* ints, int intslen)
    {
        unsigned long long value[2] = { 0, 0 };

        // Only the first four 32-bit words are used (max 128 bits).
        int count = intslen < 4 ? intslen : 4;
        for (int i = 0; i < count; ++i)
        {
            if (i < 2)
                value[0] |= static_cast<unsigned long long>(ints[i]) << (i * 32);
            else
                value[1] |= static_cast<unsigned long long>(ints[i]) << ((i - 2) * 32);
        }

        hi = static_cast<signed long long>(value[1]);
        lo = value[0];

        // If the desired sign is negative and the absolute value is non-zero,
        // negate the number (two's complement).
        if (sign < 0 && (hi != 0 || lo != 0))
        {
            Negate();                           // two's complement negation
            // No need to explicitly set the sign bit; Negate() already does that.
        }
    }

    // -------------------------------------------------------------------------
    // Comparison operators (all noexcept)
    // -------------------------------------------------------------------------
    inline bool operator==(const Int128& left, const Int128& right) noexcept
    {
        return left.lo == right.lo && left.hi == right.hi;
    }

    inline bool operator!=(const Int128& left, const Int128& right) noexcept
    {
        return !(left == right);
    }

    inline bool operator<(const Int128& left, const Int128& right) noexcept
    {
        if (left.hi != right.hi)
            return left.hi < right.hi;
        return left.lo < right.lo;
    }

    inline bool operator>(const Int128& left, const Int128& right) noexcept
    {
        if (left.hi != right.hi)
            return left.hi > right.hi;
        return left.lo > right.lo;
    }

    inline bool operator<=(const Int128& left, const Int128& right) noexcept
    {
        return left == right || left < right;
    }

    inline bool operator>=(const Int128& left, const Int128& right) noexcept
    {
        return left == right || left > right;
    }

    // -------------------------------------------------------------------------
    // Arithmetic operators
    // -------------------------------------------------------------------------

    // Addition: treat both parts as unsigned to avoid UB on overflow,
    // then reinterpret the result as signed (two's complement).
    inline Int128 operator+(const Int128& left, const Int128& right) noexcept
    {
        unsigned long long lo = left.lo + right.lo;
        unsigned long long carry = (lo < left.lo) ? 1ULL : 0ULL;   // detect unsigned overflow
        unsigned long long hi = static_cast<unsigned long long>(left.hi) +
                                static_cast<unsigned long long>(right.hi) + carry;
        return Int128(static_cast<signed long long>(hi), lo);
    }

    // Subtraction via negation and addition.
    inline Int128 operator-(const Int128& left, const Int128& right) noexcept
    {
        return left + (-right);
    }

    // Multiplication: use unsigned multiplication on the bit patterns.
    // The result is the low 128 bits of the full product.
    inline Int128 operator*(const Int128& left, const Int128& right) noexcept
    {
        return Int128::Multiply(left, right);
    }

    // Division and modulus (sign handling according to C++ rules)
    inline Int128 operator/(const Int128& left, const Int128& right)
    {
        Int128 remainder;
        return Int128::Divide(left, right, remainder);
    }

    inline Int128 operator%(const Int128& left, const Int128& right)
    {
        Int128 remainder;
        Int128::Divide(left, right, remainder);
        return remainder;
    }

    // Unary negation (two's complement)
    inline Int128 Int128::operator-() const noexcept
    {
        Int128 result = *this;
        result.Negate();
        return result;
    }

    // Increment/decrement (now non-const)
    inline Int128& Int128::operator++() noexcept
    {
        *this += 1;
        return *this;
    }

    inline Int128 Int128::operator++(int) noexcept
    {
        Int128 tmp = *this;
        ++*this;
        return tmp;
    }

    inline Int128& Int128::operator--() noexcept
    {
        *this -= 1;
        return *this;
    }

    inline Int128 Int128::operator--(int) noexcept
    {
        Int128 tmp = *this;
        --*this;
        return tmp;
    }

    // Compound assignment
    inline Int128& Int128::operator+=(const Int128& value) noexcept
    {
        *this = *this + value;
        return *this;
    }

    inline Int128& Int128::operator-=(const Int128& value) noexcept
    {
        *this = *this - value;
        return *this;
    }

    inline Int128& Int128::operator*=(const Int128& value) noexcept
    {
        *this = *this * value;
        return *this;
    }

    inline Int128& Int128::operator/=(const Int128& value)
    {
        *this = *this / value;
        return *this;
    }

    inline Int128& Int128::operator%=(const Int128& value)
    {
        *this = *this % value;
        return *this;
    }

    inline Int128& Int128::operator&=(const Int128& value) noexcept
    {
        *this = *this & value;
        return *this;
    }

    inline Int128& Int128::operator|=(const Int128& value) noexcept
    {
        *this = *this | value;
        return *this;
    }

    inline Int128& Int128::operator^=(const Int128& value) noexcept
    {
        *this = *this ^ value;
        return *this;
    }

    inline Int128& Int128::operator<<=(int shift) noexcept
    {
        *this = *this << shift;
        return *this;
    }

    inline Int128& Int128::operator>>=(int shift) noexcept
    {
        *this = *this >> shift;
        return *this;
    }

    // -------------------------------------------------------------------------
    // Bitwise operators
    // -------------------------------------------------------------------------
    inline Int128 operator~(const Int128& value) noexcept
    {
        return Int128(~value.hi, ~value.lo);
    }

    inline Int128 operator|(const Int128& left, const Int128& right) noexcept
    {
        return Int128(left.hi | right.hi, left.lo | right.lo);
    }

    inline Int128 operator&(const Int128& left, const Int128& right) noexcept
    {
        return Int128(left.hi & right.hi, left.lo & right.lo);
    }

    inline Int128 operator^(const Int128& left, const Int128& right) noexcept
    {
        return Int128(left.hi ^ right.hi, left.lo ^ right.lo);
    }

    // -------------------------------------------------------------------------
    // Shift operators (shift count modulo 128, arithmetic right shift)
    // -------------------------------------------------------------------------
    inline Int128 operator<<(const Int128& value, int shift) noexcept
    {
        if (shift == 0 || (value.lo == 0 && value.hi == 0))
            return value;

        if (shift < 0)
        {
            // Avoid overflow when shift == INT_MIN
            unsigned int pos_shift = static_cast<unsigned int>(-(shift + 1)) + 1;
            return value >> pos_shift;   // negative shift -> right shift
        }

        shift %= 128;   // modulo 128 to avoid undefined behavior

        // Work on unsigned copies
        unsigned long long lo = value.lo;
        unsigned long long hi = static_cast<unsigned long long>(value.hi);

        if (shift >= 64)
        {
            // Shift by whole 64-bit chunks
            hi = lo << (shift - 64);
            lo = 0;
        }
        else
        {
            // Partial shift
            hi = (hi << shift) | (lo >> (64 - shift));
            lo <<= shift;
        }

        return Int128(static_cast<signed long long>(hi), lo);
    }

    // Arithmetic right shift (preserves sign) - portable implementation
    inline Int128 operator>>(const Int128& value, int shift) noexcept
    {
        if (shift == 0 || (value.lo == 0 && value.hi == 0))
            return value;

        if (shift < 0)
        {
            // Avoid overflow when shift == INT_MIN
            unsigned int pos_shift = static_cast<unsigned int>(-(shift + 1)) + 1;
            return value << pos_shift;   // negative shift -> left shift
        }

        shift %= 128;

        unsigned long long lo = value.lo;
        unsigned long long hi = static_cast<unsigned long long>(value.hi);
        bool negative = (value.hi < 0);
        unsigned long long sign_ext = negative ? ~0ULL : 0ULL;

        if (shift >= 64)
        {
            int shift1 = shift - 64; // shift1 in [0,63]
            // lo becomes the shifted-out high part, possibly with sign extension
            lo = (shift1 == 0) ? hi : (hi >> shift1);
            if (negative && shift1 > 0)
                lo |= (~0ULL << (64 - shift1));
            hi = sign_ext;
        }
        else
        {
            // shift in [1,63]
            lo = (lo >> shift) | (hi << (64 - shift));
            hi = (hi >> shift);
            if (negative)
                hi |= (~0ULL << (64 - shift));
        }

        return Int128(static_cast<signed long long>(hi), lo);
    }

    // -------------------------------------------------------------------------
    // Binary I/O (always little-endian)
    // -------------------------------------------------------------------------

    // Compile-time endianness detection with fallback for unknown compilers.
    // Returns true if the host is little-endian.
    inline bool is_little_endian() noexcept
    {
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
        return __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__;
#elif defined(_MSC_VER)
        // Microsoft compilers target little-endian platforms only.
        return true;
#elif defined(__BIG_ENDIAN__) || defined(_BIG_ENDIAN)
        return false;
#else
        // Unknown: assume little-endian (most common).
        return true;
#endif
    }

    // Convert a 32-bit word to little-endian byte order.
    inline unsigned int htole32(unsigned int x) noexcept
    {
        if (is_little_endian())
            return x;
        // Swap bytes for big-endian host.
        return ((x & 0x000000FFU) << 24) |
               ((x & 0x0000FF00U) << 8) |
               ((x & 0x00FF0000U) >> 8) |
               ((x & 0xFF000000U) >> 24);
    }

    // Convert a little-endian 32-bit word to host byte order.
    inline unsigned int le32toh(unsigned int x) noexcept
    {
        // Conversion is symmetric.
        return htole32(x);
    }

    inline std::ostream& operator<<(std::ostream& out, const Int128& value)
    {
        unsigned int parts[4];
        Int128::Decompose(value, parts);

        for (int i = 0; i < 4; ++i)
        {
            unsigned int word = htole32(parts[i]);   // convert to little-endian
            out.write(reinterpret_cast<const char*>(&word), sizeof(word));
        }
        return out;
    }

    // Input operator now takes non-const reference
    inline std::istream& operator>>(std::istream& in, Int128& value)
    {
        unsigned int parts[4];
        for (int i = 0; i < 4; ++i)
        {
            unsigned int word;
            if (!in.read(reinterpret_cast<char*>(&word), sizeof(word)))
            {
                // Reading failed; set value to zero and return the stream.
                value = 0;
                return in;
            }
            parts[i] = le32toh(word);   // convert from little-endian to host
        }
        value = Int128::Compose(parts);
        return in;
    }

    // -------------------------------------------------------------------------
    // Conversion operators (C++11 and later)
    // -------------------------------------------------------------------------
#if defined(_MSC_VER) || __cplusplus >= 201103L
    inline Int128::operator bool() const noexcept
    {
        return lo != 0 || hi != 0;
    }

    inline Int128::operator signed char() const noexcept
    {
        return static_cast<signed char>(lo);
    }

    inline Int128::operator signed short int() const noexcept
    {
        return static_cast<signed short int>(lo);
    }

    inline Int128::operator signed int() const noexcept
    {
        return static_cast<signed int>(lo);
    }

    inline Int128::operator signed long() const noexcept
    {
        return static_cast<signed long>(lo);
    }

    inline Int128::operator signed long long() const noexcept
    {
        return static_cast<signed long long>(lo);
    }

    inline Int128::operator unsigned char() const noexcept
    {
        return static_cast<unsigned char>(lo);
    }

    inline Int128::operator unsigned short() const noexcept
    {
        return static_cast<unsigned short>(lo);
    }

    inline Int128::operator unsigned int() const noexcept
    {
        return static_cast<unsigned int>(lo);
    }

    inline Int128::operator unsigned long() const noexcept
    {
        return static_cast<unsigned long>(lo);
    }

    inline Int128::operator unsigned long long() const noexcept
    {
        return lo;
    }
#endif

    // -------------------------------------------------------------------------
    // Sign and string conversion
    // -------------------------------------------------------------------------
    inline int Int128::Sign() const noexcept
    {
        if (hi == 0 && lo == 0)
            return 0;
        return (hi & NegativeSignMask) == 0 ? 1 : -1;
    }

    template <typename TString>
    inline TString Int128::ToString(int radix) const
    {
        return stl::to_string<TString, Int128>(*this, radix);
    }

    template <typename TString>
    inline TString Int128::ToString() const
    {
        return ToString<TString>(10);
    }

    template <typename TString>
    inline TString Int128::ToHex() const
    {
        return ToString<TString>(16);
    }

    template <typename TString>
    inline TString Int128::ToBinary() const
    {
        return ToString<TString>(2);
    }

    // -------------------------------------------------------------------------
    // Decomposition / composition helpers
    // -------------------------------------------------------------------------
    inline void Int128::Decompose(const Int128& val, unsigned int parts[4]) noexcept
    {
        unsigned long long low = val.lo;
        unsigned long long high = static_cast<unsigned long long>(val.hi);
        parts[0] = static_cast<unsigned int>(low);
        parts[1] = static_cast<unsigned int>(low >> 32);
        parts[2] = static_cast<unsigned int>(high);
        parts[3] = static_cast<unsigned int>(high >> 32);
    }

    inline Int128 Int128::Compose(const unsigned int parts[4]) noexcept
    {
        unsigned long long low = static_cast<unsigned long long>(parts[0]) |
                                (static_cast<unsigned long long>(parts[1]) << 32);
        unsigned long long high = static_cast<unsigned long long>(parts[2]) |
                                 (static_cast<unsigned long long>(parts[3]) << 32);
        return Int128(static_cast<signed long long>(high), low);
    }

    // -------------------------------------------------------------------------
    // Negation (two's complement)
    // -------------------------------------------------------------------------
    inline void Int128::Negate() noexcept
    {
        hi = ~hi;
        lo = ~lo;
        *this += 1;   // two's complement: ~x + 1
    }

    // -------------------------------------------------------------------------
    // Unsigned absolute value
    // -------------------------------------------------------------------------
    inline void Int128::Absolute(const Int128& val, unsigned long long& out_lo, unsigned long long& out_hi) noexcept
    {
        if (val.hi < 0)
        {
            // Negative: compute two's complement absolute value
            Int128 absVal = -val;   // safe even for min (returns itself, but that's fine for bit pattern)
            out_lo = absVal.lo;
            out_hi = static_cast<unsigned long long>(absVal.hi);
        }
        else
        {
            out_lo = val.lo;
            out_hi = static_cast<unsigned long long>(val.hi);
        }
    }

    // -------------------------------------------------------------------------
    // Multiplication (unsigned algorithm on bit patterns)
    // -------------------------------------------------------------------------
    inline Int128 Int128::Multiply(const Int128& left, const Int128& right) noexcept
    {
        // Decompose both operands into 32-bit little-endian parts
        unsigned int x[4], y[4];
        Decompose(left, x);
        Decompose(right, y);

        unsigned int product[8] = { 0 };   // 256-bit product (we only need low 128 bits)

        // Multiply x by y using base 2^32 arithmetic
        for (int i = 0; i < 4; ++i)
        {
            unsigned long long carry = 0;
            for (int j = 0; j < 4; ++j)
            {
                int idx = i + j;
                unsigned long long p = static_cast<unsigned long long>(x[i]) * y[j] +
                                       product[idx] + carry;
                product[idx] = static_cast<unsigned int>(p);
                carry = p >> 32;
            }
            // Propagate carry through higher words
            if (carry)
            {
                for (int k = i + 4; k < 8 && carry; ++k)
                {
                    carry += product[k];
                    product[k] = static_cast<unsigned int>(carry);
                    carry >>= 32;
                }
            }
        }

        // The low 128 bits of the product are the correct 128-bit result (in little-endian parts)
        return Compose(product);   // product[0..3] are the low 4 parts
    }

    // -------------------------------------------------------------------------
    // Division helpers (Knuth's algorithm D)
    // -------------------------------------------------------------------------
    inline int Int128::GetLength(const unsigned int* uints, int uintslen) noexcept
    {
        int idx = uintslen - 1;
        while (idx >= 0 && uints[idx] == 0)
            --idx;
        return idx + 1;
    }

    inline int Int128::GetNormalizeShift(unsigned int value) noexcept
    {
        int shift = 0;
        if ((value & 0xFFFF0000U) == 0) { value <<= 16; shift += 16; }
        if ((value & 0xFF000000U) == 0) { value <<= 8;  shift += 8;  }
        if ((value & 0xF0000000U) == 0) { value <<= 4;  shift += 4;  }
        if ((value & 0xC0000000U) == 0) { value <<= 2;  shift += 2;  }
        if ((value & 0x80000000U) == 0) { value <<= 1;  shift += 1;  }
        return shift;
    }

    inline void Int128::Normalize(const unsigned int* u, int l, unsigned int* un, int shift) noexcept
    {
        unsigned int carry = 0;
        int i;
        if (shift > 0)
        {
            int rshift = 32 - shift;
            for (i = 0; i < l; ++i)
            {
                unsigned int ui = u[i];
                un[i] = (ui << shift) | carry;
                carry = ui >> rshift;
            }
        }
        else
        {
            for (i = 0; i < l; ++i)
                un[i] = u[i];
        }

        // Zero out the remaining entries (up to 5 to allow for possible extra word)
        for (; i < 5; ++i)
            un[i] = 0;

        if (carry != 0)
            un[l] = carry;   // caller must ensure un has at least l+1 elements
    }

    inline void Int128::Unnormalize(const unsigned int* un, unsigned int* r, int shift) noexcept
    {
        const int length = 4;   // remainder always fits in 4 words
        if (shift > 0)
        {
            int lshift = 32 - shift;
            unsigned int carry = 0;
            for (int i = length - 1; i >= 0; --i)
            {
                unsigned int uni = un[i];
                r[i] = (uni >> shift) | carry;
                carry = uni << lshift;
            }
        }
        else
        {
            for (int i = 0; i < length; ++i)
                r[i] = un[i];
        }
    }

    // Unsigned division: u / v, quotient stored in q, remainder in r.
    // u and v are little-endian 32-bit arrays of length 4 (may have leading zeros).
    // q and r are caller-provided arrays of size at least 4.
    inline void Int128::DivModUnsigned(const unsigned int* u, const unsigned int* v,
                                       unsigned int* q, unsigned int* r) noexcept
    {
        int m = GetLength(u, 4);
        int n = GetLength(v, 4);

        if (n == 0)
        {
            // Division by zero: undefined, we return zero (as original code did)
            for (int i = 0; i < 4; ++i) q[i] = r[i] = 0;
            return;
        }

        if (n == 1)
        {
            // Single digit divisor
            unsigned long long rem = 0;
            unsigned int v0 = v[0];
            for (int j = m - 1; j >= 0; --j)
            {
                rem = (rem << 32) + u[j];
                unsigned long long quot = rem / v0;
                rem -= quot * v0;
                q[j] = static_cast<unsigned int>(quot);
            }

            r[0] = static_cast<unsigned int>(rem);
            for (int i = 1; i < 4; ++i) r[i] = 0;
            return;
        }

        if (m < n)
        {
            // Quotient = 0, remainder = dividend
            for (int i = 0; i < 4; ++i)
            {
                q[i] = 0;
                r[i] = u[i];
            }
            return;
        }

        // General case: Knuth's algorithm D
        int shift = GetNormalizeShift(v[n - 1]);

        unsigned int un[5] = { 0 };   // normalized dividend (size m+1)
        unsigned int vn[5] = { 0 };   // normalized divisor (size n+1)

        Normalize(u, m, un, shift);
        Normalize(v, n, vn, shift);

        // Main division loop
        for (int j = m - n; j >= 0; --j)
        {
            unsigned long long qhat;
            if (un[j + n] == vn[n - 1])
            {
                qhat = Base32 - 1;
            }
            else
            {
                qhat = (static_cast<unsigned long long>(un[j + n]) << 32) + un[j + n - 1];
                qhat /= vn[n - 1];
            }

            // Check and adjust qhat
            for (;;)
            {
                unsigned long long t = static_cast<unsigned long long>(vn[n - 2]) * qhat;
                unsigned long long high = t >> 32;
                unsigned long long low = t & 0xFFFFFFFFULL;
                if (high > un[j + n] ||
                    (high == un[j + n] && low > un[j + n - 1]))
                {
                    --qhat;
                }
                else
                {
                    break;
                }
            }

            // Multiply and subtract (using unsigned arithmetic for borrow propagation)
            unsigned long long borrow = 0;
            for (int i = 0; i < n; ++i)
            {
                unsigned long long p = static_cast<unsigned long long>(vn[i]) * qhat;
                unsigned long long p_low = p & 0xFFFFFFFFULL;
                unsigned long long p_high = p >> 32;
                unsigned long long diff = static_cast<unsigned long long>(un[j + i]) - p_low - borrow;
                un[j + i] = static_cast<unsigned int>(diff);
                // borrow = p_high - (diff >> 32);   // old (incorrect) borrow calculation
                // Correct borrow calculation:
                // If (p_low + borrow) > un[j+i] then we need to borrow 1 from the high part.
                // This condition is exactly when diff has the high bit set (diff > 0xFFFFFFFF).
                // In unsigned arithmetic, diff is in [0, 0x1FFFFFFFF], so diff >> 32 is either 0 or 1.
                // We need to add that borrowed 1 to the borrow for the next subtraction.
                // So borrow = p_high + (diff >> 32);
                borrow = p_high + ((diff >> 32) ? 1ULL : 0ULL);
            }
            unsigned long long diff = static_cast<unsigned long long>(un[j + n]) - borrow;
            un[j + n] = static_cast<unsigned int>(diff);

            q[j] = static_cast<unsigned int>(qhat);

            // If the subtraction resulted in a borrow (diff negative when interpreted as signed),
            // then we need to add back (rare case).
            if (static_cast<signed long long>(diff) < 0)
            {
                --q[j];
                unsigned long long carry = 0;
                for (int i = 0; i < n; ++i)
                {
                    carry += static_cast<unsigned long long>(un[j + i]) + vn[i];
                    un[j + i] = static_cast<unsigned int>(carry);
                    carry >>= 32;
                }
                carry += un[j + n];
                un[j + n] = static_cast<unsigned int>(carry);
            }
        }

        // Unnormalize remainder
        Unnormalize(un, r, shift);

        // Zero out remaining words in q (if any)
        for (int i = m - n + 1; i < 4; ++i)
            q[i] = 0;
    }

    // -------------------------------------------------------------------------
    // Signed division with remainder (C++ rules)
    // -------------------------------------------------------------------------
    inline Int128 Int128::Divide(const Int128& dividend, const Int128& divisor, Int128& remainder)
    {
        if (divisor == 0)
        {
            // Division by zero: undefined behavior; return 0 as original did.
            remainder = 0;
            return 0;
        }

        int dividendSign = dividend.Sign();
        int divisorSign = divisor.Sign();

        if (dividendSign == 0)
        {
            remainder = 0;
            return 0;
        }

        // Get absolute values as unsigned 64-bit parts
        unsigned long long absDividendLo, absDividendHi;
        unsigned long long absDivisorLo, absDivisorHi;
        Absolute(dividend, absDividendLo, absDividendHi);
        Absolute(divisor, absDivisorLo, absDivisorHi);

        // Decompose absolute values into 32-bit arrays
        unsigned int u[4], v[4];
        Int128 absDividend(static_cast<signed long long>(absDividendHi), absDividendLo);
        Int128 absDivisor(static_cast<signed long long>(absDivisorHi), absDivisorLo);
        Decompose(absDividend, u);
        Decompose(absDivisor, v);

        unsigned int quot[4] = { 0 };
        unsigned int rem[4] = { 0 };
        DivModUnsigned(u, v, quot, rem);

        // Compose quotient and remainder as unsigned absolute values
        Int128 absQuotient = Compose(quot);
        Int128 absRemainder = Compose(rem);

        // Determine signs of results
        int quotientSign = dividendSign * divisorSign;
        int remainderSign = dividendSign;   // remainder takes sign of dividend

        // Apply sign to quotient
        Int128 resultQuotient;
        if (quotientSign < 0)
            resultQuotient = -absQuotient;
        else
            resultQuotient = absQuotient;

        // Apply sign to remainder (if non-zero)
        if (absRemainder == 0)
        {
            remainder = 0;
        }
        else
        {
            if (remainderSign < 0)
                remainder = -absRemainder;
            else
                remainder = absRemainder;
        }

        return resultQuotient;
    }

#else   // !defined(_PPP_INT128) ¨C use compiler's built-in __int128_t
    typedef __int128_t Int128;
#endif

    // Helper to construct an Int128 from two 64-bit halves (low, high).
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
        return Int128(static_cast<signed long long>(high), low);
#else
        return (static_cast<Int128>(high) << 64) | static_cast<Int128>(low);
#endif
    }

} // namespace ppp

// -------------------------------------------------------------------------
// std::hash specialization for ppp::Int128
// -------------------------------------------------------------------------
#if !defined(_MACOS)
namespace std
{
    template <>
    struct hash<ppp::Int128>
    {
        std::size_t operator()(const ppp::Int128& v) const noexcept
        {
            std::hash<int64_t> h;
#if defined(_PPP_INT128)
            std::size_t h1 = h(static_cast<int64_t>(v.lo));
            std::size_t h2 = h(static_cast<int64_t>(v.hi));
#else
            std::size_t h1 = h(static_cast<int64_t>(v));
            std::size_t h2 = h(static_cast<int64_t>(v >> 64));
#endif
            return h1 ^ (h2 << 1);
        }
    };
}
#endif

// -------------------------------------------------------------------------
// Type traits
// -------------------------------------------------------------------------
namespace stl
{
    template <>
    struct is_signed<ppp::Int128> : true_type {};
}