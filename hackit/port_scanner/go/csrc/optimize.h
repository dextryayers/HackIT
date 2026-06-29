#ifndef OPTIMIZE_H
#define OPTIMIZE_H
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>

// Branch prediction
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

// Function attributes
#define ALWAYS_INLINE __attribute__((always_inline)) inline
#define HOT __attribute__((hot))
#define COLD __attribute__((cold))
#define FLATTEN __attribute__((flatten))
#define PACKED __attribute__((packed))
#define RESTRICT restrict
#define CONST_FN __attribute__((const))
#define PURE_FN __attribute__((pure))
#define UNUSED __attribute__((unused))
#define EXPORT __attribute__((visibility("default")))

// Cache line
#define CACHE_ALIGN __attribute__((aligned(64)))
#define CACHE_LINE_SIZE 64

// Memory barriers
#define COMPILER_BARRIER() __asm__ __volatile__("" ::: "memory")
#define MEMORY_BARRIER() __sync_synchronize()

// Likely/unlikely shortcuts
#ifndef bool
#define bool int
#define true 1
#define false 0
#endif

// Fast min/max
static ALWAYS_INLINE int fast_min(int a, int b) { return a < b ? a : b; }
static ALWAYS_INLINE int fast_max(int a, int b) { return a > b ? a : b; }
static ALWAYS_INLINE uint32_t fast_min_u32(uint32_t a, uint32_t b) { return a < b ? a : b; }
static ALWAYS_INLINE uint32_t fast_max_u32(uint32_t a, uint32_t b) { return a > b ? a : b; }

// Fast abs
static ALWAYS_INLINE int fast_abs(int x) {
    int mask = x >> (sizeof(int) * 8 - 1);
    return (x + mask) ^ mask;
}

// Align to cache line
#define CACHE_ALIGNED __attribute__((aligned(64)))

#endif
