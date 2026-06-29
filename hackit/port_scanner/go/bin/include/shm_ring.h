#ifndef PORTSTORM_SHM_RING_H
#define PORTSTORM_SHM_RING_H

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>

#define SHM_RING_MAGIC      0x5054534D
#define SHM_RING_VERSION    2
#define SHM_RING_CAPACITY   262144
#define SHM_RING_MAX_ENTRY  4096
#define SHM_RING_NAME_MAX   64
#define SHM_RING_DATA_MAX   2048
#define CACHE_ALIGNED       __attribute__((aligned(64)))

typedef enum {
    ENTRY_PORT_OPEN     = 1,
    ENTRY_PORT_CLOSED   = 2,
    ENTRY_PORT_FILTERED = 3,
    ENTRY_SERVICE       = 4,
    ENTRY_BANNER        = 5,
    ENTRY_OS_FINGERPRINT = 6,
    ENTRY_VULN          = 7,
    ENTRY_PROGRESS      = 8,
    ENTRY_ERROR         = 9,
    ENTRY_DONE          = 10,
} EntryType;

typedef struct CACHE_ALIGNED {
    uint32_t    type;
    uint32_t    port;
    uint32_t    ip;
    uint32_t    timestamp_ms;
    uint16_t    data_len;
    uint16_t    flags;
    char        data[SHM_RING_DATA_MAX];
} RingEntry;

typedef struct CACHE_ALIGNED {
    uint32_t            magic;
    uint32_t            version;
    uint32_t            capacity;
    uint32_t            entry_size;
    atomic_uint_least64_t write_seq;
    atomic_uint_least64_t read_seq;
    atomic_uint_least64_t committed_seq;
    uint32_t            num_readers;
    uint32_t            flags;
    char                name[SHM_RING_NAME_MAX];
    uint8_t             pad[48];
    RingEntry           entries[];
} ShmRingHeader;

static inline ShmRingHeader *shm_ring_init(void *mem, size_t sz, const char *name) {
    if (!mem || sz < sizeof(ShmRingHeader)) return NULL;
    ShmRingHeader *h = (ShmRingHeader *)mem;
    h->magic = SHM_RING_MAGIC;
    h->version = SHM_RING_VERSION;
    h->entry_size = sizeof(RingEntry);
    size_t avail = sz - sizeof(ShmRingHeader);
    h->capacity = (uint32_t)(avail / sizeof(RingEntry));
    if (h->capacity > SHM_RING_CAPACITY) h->capacity = SHM_RING_CAPACITY;
    atomic_store_explicit(&h->write_seq, 0, memory_order_relaxed);
    atomic_store_explicit(&h->read_seq, 0, memory_order_relaxed);
    atomic_store_explicit(&h->committed_seq, 0, memory_order_relaxed);
    h->num_readers = 0;
    h->flags = 0;
    if (name) {
        int i = 0;
        for (; name[i] && i < SHM_RING_NAME_MAX - 1; i++) h->name[i] = name[i];
        h->name[i] = 0;
    }
    return h;
}

static inline bool shm_ring_valid(const ShmRingHeader *h) {
    return h && h->magic == SHM_RING_MAGIC && h->version == SHM_RING_VERSION && h->capacity > 0;
}

static inline uint64_t shm_ring_write_acquire(ShmRingHeader *h) {
    return atomic_fetch_add_explicit(&h->write_seq, 1, memory_order_acquire);
}

static inline void shm_ring_write_commit(ShmRingHeader *h, uint64_t slot) {
    while (!atomic_compare_exchange_weak_explicit(
        &h->committed_seq, &(uint64_t){slot}, slot + 1,
        memory_order_release, memory_order_relaxed));
}

static inline RingEntry *shm_ring_slot(ShmRingHeader *h, uint64_t seq) {
    return &h->entries[seq % h->capacity];
}

static inline uint64_t shm_ring_read_available(const ShmRingHeader *h) {
    return atomic_load_explicit(&h->committed_seq, memory_order_acquire)
         - atomic_load_explicit(&h->read_seq, memory_order_relaxed);
}

enum { SHM_RING_OK = 0, SHM_RING_FULL = -1, SHM_RING_INVALID = -2 };

static inline int shm_ring_push(ShmRingHeader *h, const RingEntry *e) {
    if (!shm_ring_valid(h)) return SHM_RING_INVALID;
    uint64_t slot = shm_ring_write_acquire(h);
    RingEntry *dest = shm_ring_slot(h, slot);
    __builtin_memcpy(dest, e, sizeof(RingEntry));
    __builtin___clear_cache((char*)dest, (char*)dest + sizeof(RingEntry));
    shm_ring_write_commit(h, slot);
    return SHM_RING_OK;
}

static inline int shm_ring_pop(ShmRingHeader *h, RingEntry *out) {
    if (!shm_ring_valid(h)) return SHM_RING_INVALID;
    uint64_t avail = shm_ring_read_available(h);
    if (avail == 0) return SHM_RING_FULL;
    uint64_t seq = atomic_load_explicit(&h->read_seq, memory_order_relaxed);
    RingEntry *src = shm_ring_slot(h, seq);
    __builtin_memcpy(out, src, sizeof(RingEntry));
    atomic_store_explicit(&h->read_seq, seq + 1, memory_order_release);
    return SHM_RING_OK;
}

static inline void shm_ring_make_entry(RingEntry *e, EntryType type, uint32_t port,
                                        uint32_t ip, const char *data, uint16_t data_len) {
    e->type = (uint32_t)type;
    e->port = port;
    e->ip = ip;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    e->timestamp_ms = (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
    e->data_len = data_len < SHM_RING_DATA_MAX ? data_len : SHM_RING_DATA_MAX - 1;
    e->flags = 0;
    if (data && e->data_len > 0) {
        __builtin_memcpy(e->data, data, e->data_len);
        e->data[e->data_len] = 0;
    } else {
        e->data[0] = 0;
    }
}

#endif
