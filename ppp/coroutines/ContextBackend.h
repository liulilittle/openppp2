#pragma once

#if defined(PPP_COROUTINE_BACKEND_COROCC)
#include <ppp/coroutines/backend/CoroccBackend.h>
#else
#include <ppp/coroutines/backend/BoostFcontextBackend.h>
#endif
