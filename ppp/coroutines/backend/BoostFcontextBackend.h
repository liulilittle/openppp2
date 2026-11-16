#pragma once

#include <boost/context/detail/fcontext.hpp>

namespace ppp { namespace coroutines { namespace backend {
using Context = boost::context::detail::fcontext_t;
using Transfer = boost::context::detail::transfer_t;
inline constexpr const char* Name = "boost-fcontext";
// Alias the functions themselves so the default adds no wrapper call frames
// or extra inlining decisions, including in unoptimized builds.
inline constexpr auto Make = &boost::context::detail::make_fcontext;
inline constexpr auto Jump = &boost::context::detail::jump_fcontext;
inline constexpr auto Finish = Jump;
}}}
