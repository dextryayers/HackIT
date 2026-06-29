package main

/*
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SHM_RING_MAGIC      0x5054534D
#define SHM_RING_VERSION    2
#define SHM_RING_CAPACITY   262144
#define SHM_RING_DATA_MAX   2048

typedef struct {
    uint32_t    type;
    uint32_t    port;
    uint32_t    ip;
    uint32_t    timestamp_ms;
    uint16_t    data_len;
    uint16_t    flags;
    char        data[SHM_RING_DATA_MAX];
} RingEntry;

typedef struct {
    uint32_t    magic;
    uint32_t    version;
    uint32_t    capacity;
    uint32_t    entry_size;
    uint64_t    write_seq;
    uint64_t    read_seq;
    uint64_t    committed_seq;
    uint32_t    num_readers;
    uint32_t    flags;
    char        name[64];
    uint8_t     pad[48];
    RingEntry   entries[];
} ShmRingHeader;

static ShmRingHeader* shm_open_or_create(const char* name, size_t size) {
    int fd = shm_open(name, O_CREAT | O_RDWR, 0666);
    if (fd < 0) return NULL;
    if (ftruncate(fd, (off_t)size) < 0) { close(fd); return NULL; }
    void* mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (mem == MAP_FAILED) return NULL;
    ShmRingHeader* h = (ShmRingHeader*)mem;
    if (h->magic != SHM_RING_MAGIC) {
        h->magic = SHM_RING_MAGIC;
        h->version = SHM_RING_VERSION;
        h->entry_size = sizeof(RingEntry);
        h->capacity = (uint32_t)((size - sizeof(ShmRingHeader)) / sizeof(RingEntry));
        if (h->capacity > SHM_RING_CAPACITY) h->capacity = SHM_RING_CAPACITY;
        h->write_seq = 0;
        h->read_seq = 0;
        h->committed_seq = 0;
        h->num_readers = 0;
        h->flags = 0;
        strncpy(h->name, name, sizeof(h->name) - 1);
    }
    return h;
}

static void shm_push_port(ShmRingHeader* h, uint32_t port, uint32_t ip, int is_open) {
    uint64_t slot = __sync_fetch_and_add(&h->write_seq, 1);
    RingEntry* e = &h->entries[slot % h->capacity];
    e->type = is_open ? 1 : 2;
    e->port = port;
    e->ip = ip;
    e->timestamp_ms = 0;
    e->data_len = 0;
    e->data[0] = 0;
    __sync_synchronize();
    while (__sync_val_compare_and_swap(&h->committed_seq, slot, slot + 1) != slot);
}

static int shm_pop_entry(ShmRingHeader* h, RingEntry* out) {
    if (h->committed_seq <= h->read_seq) return 0;
    uint64_t seq = __sync_fetch_and_add(&h->read_seq, 1);
    if (seq >= h->committed_seq) { __sync_fetch_and_sub(&h->read_seq, 1); return 0; }
    *out = h->entries[seq % h->capacity];
    return 1;
}
*/
import "C"
import (
	"fmt"
	"os"
	"sync"
	"unsafe"
)

type ShmRing struct {
	ptr  *C.ShmRingHeader
	size int64
	name string
	mu   sync.Mutex
}

func NewShmRing(name string, size int64) (*ShmRing, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	ptr := C.shm_open_or_create(cname, C.size_t(size))
	if ptr == nil {
		return nil, fmt.Errorf("shm_open_or_create failed for %s", name)
	}
	return &ShmRing{ptr: ptr, size: size, name: name}, nil
}

func (r *ShmRing) PushPort(port uint32, ip uint32, isOpen bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	status := 0
	if isOpen {
		status = 1
	}
	C.shm_push_port(r.ptr, C.uint32_t(port), C.uint32_t(ip), C.int(status))
}

func (r *ShmRing) PopEntry() (port uint32, ip uint32, isOpen bool, ok bool) {
	var entry C.RingEntry
	ret := C.shm_pop_entry(r.ptr, &entry)
	if ret == 0 {
		return 0, 0, false, false
	}
	return uint32(entry.port), uint32(entry.ip), entry._type == 1, true
}

func (r *ShmRing) Close() {
	C.munmap(unsafe.Pointer(r.ptr), C.size_t(r.size))
}

func init() {
	// Ensure /dev/shm is accessible
	os.MkdirAll("/dev/shm", 0777)
}
