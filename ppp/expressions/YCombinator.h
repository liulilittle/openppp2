#pragma once

#include <iostream>
#include <functional>

namespace ppp
{
    namespace expressions
    {
        template <typename T, typename TResult>
        class RecursiveFunction
        {
        public:
            using FunctionType = ppp::function<TResult(T)>;
            using RecursiveType = ppp::function<FunctionType(RecursiveFunction)>;

        public:
            RecursiveFunction(const RecursiveType& f) noexcept
                : m_f(f)
            {

            }

        public:
            TResult         operator ()(T arg) const noexcept
            {
                return m_f(*this)(arg);
            }

        private:
            RecursiveType   m_f;
        };

        template <typename T, typename TResult>
        class YCombinator final
        {
        public:
            // Y = λf.(λx.f(x x)) (λx.f(x x))
            // Y = f => (λx.f(x x)) (λx.f(x x))
            // Y = f => (x => f(x(x)))(x => f(x(x)))
            // Y = (x => arg => f(x(x))(arg))(x => arg => f(x(x))(arg))
            static typename RecursiveFunction<T, TResult>::FunctionType Y(typename RecursiveFunction<T, TResult>::RecursiveType&& f) noexcept
            {
                auto g = [](auto x) -> typename RecursiveFunction<T, TResult>::FunctionType
                {
                    return [x](T arg) noexcept -> TResult
                    {
                        return x(x)(arg);
                    };
                };

                return g([f](auto x) noexcept -> typename RecursiveFunction<T, TResult>::FunctionType
                    {
                        return f(RecursiveFunction<T, TResult>{x});
                    });
            }
        };
    }
}