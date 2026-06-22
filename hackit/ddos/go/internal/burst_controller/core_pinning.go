package burst_controller

import (
	"fmt"
	"runtime"
	"sync"

	"golang.org/x/sys/unix"
)

type CPUManager struct {
	totalCores     int
	availableCores []int
	allocated      map[int]bool
	mu             sync.Mutex
}

func NewCPUManager() *CPUManager {
	n := runtime.NumCPU()
	cores := make([]int, n)
	for i := 0; i < n; i++ {
		cores[i] = i
	}
	return &CPUManager{
		totalCores:     n,
		availableCores: cores,
		allocated:      make(map[int]bool),
	}
}

func (m *CPUManager) PinToCore(coreID int) error {
	if coreID < 0 || coreID >= m.totalCores {
		return fmt.Errorf("core %d out of range (0-%d)", coreID, m.totalCores-1)
	}
	runtime.LockOSThread()
	var cpuSet unix.CPUSet
	cpuSet.Zero()
	cpuSet.Set(coreID)
	return unix.SchedSetaffinity(0, &cpuSet)
}

func (m *CPUManager) UnpinCurrent() {
	runtime.UnlockOSThread()
}

func (m *CPUManager) AllocateCore() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, core := range m.availableCores {
		if !m.allocated[core] {
			m.allocated[core] = true
			return core, nil
		}
	}
	return 0, fmt.Errorf("no available cores")
}

func (m *CPUManager) ReleaseCore(coreID int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.allocated, coreID)
}

func (m *CPUManager) PinWorkers(workerFn func(id int), count int) {
	for i := 0; i < count; i++ {
		coreID := i % m.totalCores
		go func(cid int) {
			if err := m.PinToCore(cid); err != nil {
				return
			}
			defer m.UnpinCurrent()
			workerFn(cid)
		}(coreID)
	}
}
