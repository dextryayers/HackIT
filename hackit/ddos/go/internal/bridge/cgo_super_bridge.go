package bridge

/*
#cgo LDFLAGS: -L${SRCDIR}/../../c -lpacket_sakti -ldl
#include "../../../c/include/engine.h"
*/
import "C"

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

type PacketBuffer struct {
	data unsafe.Pointer
	size int
}

type SuperBridge struct {
	initialized bool
	mu          sync.Mutex
	configPtr   unsafe.Pointer
}

func InitBridge() error {
	rc := C.engine_init()
	if rc != 0 {
		return fmt.Errorf("engine_init failed with code %d", int(rc))
	}
	return nil
}

func ShutdownBridge() {
	C.engine_shutdown()
}

func AllocBuffer(size int) *PacketBuffer {
	ptr := C.malloc(C.size_t(size))
	if ptr == nil {
		return nil
	}
	return &PacketBuffer{
		data: ptr,
		size: size,
	}
}

func (b *PacketBuffer) Free() {
	if b.data != nil {
		C.free(b.data)
		b.data = nil
	}
}

func (b *PacketBuffer) AsSlice() []byte {
	if b.data == nil || b.size == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(b.data), b.size)
}

func StartAttack(configPtr unsafe.Pointer) int {
	defer runtime.KeepAlive(configPtr)
	return int(C.engine_start())
}

func StopAttack() int {
	return int(C.engine_stop())
}

func UpdateConfig(configPtr unsafe.Pointer) int {
	defer runtime.KeepAlive(configPtr)
	return int(C.engine_reload())
}

func GetStatus() (bool, uint64) {
	ret := C.engine_status()
	return ret != 0, uint64(ret)
}
