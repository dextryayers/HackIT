#pragma once

// Branch prediction hints
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

// Force-inlining
#define FORCE_INLINE __attribute__((always_inline)) inline

// Function attributes
#define HOT_FUNC    __attribute__((hot))
#define COLD_FUNC   __attribute__((cold))
#define CONST_FUNC  __attribute__((const))
#define PURE_FUNC   __attribute__((pure))

// Cache-line alignment (typical 64-byte cache line)
#define CACHE_ALIGN alignas(64)
