package protocol_switcher

import (
	"fmt"
	"sync/atomic"
	"time"
)

const (
	MethodSYN int = iota
	MethodUDP
	MethodACK
	MethodRST
	MethodICMP
	MethodDNS
	MethodNTP
	MethodHTTP
	MethodH2RapidReset
	MethodStatefulBypass
	MethodMorphFlood
)

var defaultMethodNames = map[int]string{
	MethodSYN:            "SYN",
	MethodUDP:            "UDP",
	MethodACK:            "ACK",
	MethodRST:            "RST",
	MethodICMP:           "ICMP",
	MethodDNS:            "DNS",
	MethodNTP:            "NTP",
	MethodHTTP:           "HTTP",
	MethodH2RapidReset:   "H2_RAPID_RESET",
	MethodStatefulBypass: "STATEFUL_BYPASS",
	MethodMorphFlood:     "MORPH_FLOOD",
}

type SwitchEngine struct {
	currentMethod    int32
	availableMethods []int
	methodNames      map[int]string
	switchCount      int64
	blockThreshold   time.Duration
	lastBlockTime    time.Time
}

func NewSwitchEngine(methods ...int) *SwitchEngine {
	if len(methods) == 0 {
		methods = []int{MethodSYN, MethodUDP, MethodHTTP, MethodICMP}
	}
	names := make(map[int]string, len(methods))
	for _, m := range methods {
		if n, ok := defaultMethodNames[m]; ok {
			names[m] = n
		} else {
			names[m] = fmt.Sprintf("UNKNOWN_%d", m)
		}
	}
	return &SwitchEngine{
		currentMethod:    int32(methods[0]),
		availableMethods: methods,
		methodNames:      names,
		blockThreshold:   5 * time.Second,
	}
}

func (s *SwitchEngine) Current() int {
	return int(atomic.LoadInt32(&s.currentMethod))
}

func (s *SwitchEngine) RecordBlock() {
	s.lastBlockTime = time.Now()
}

func (s *SwitchEngine) ShouldSwitch() bool {
	if len(s.availableMethods) <= 1 {
		return false
	}
	current := s.Current()
	lastMethod := s.availableMethods[len(s.availableMethods)-1]
	if current == lastMethod {
		return false
	}
	return time.Since(s.lastBlockTime) < s.blockThreshold
}

func (s *SwitchEngine) NextMethod() int {
	current := s.Current()
	nextIdx := 0
	for i, m := range s.availableMethods {
		if m == current {
			nextIdx = (i + 1) % len(s.availableMethods)
			break
		}
	}
	next := s.availableMethods[nextIdx]
	atomic.StoreInt32(&s.currentMethod, int32(next))
	atomic.AddInt64(&s.switchCount, 1)
	return next
}

func (s *SwitchEngine) MethodName(method int) string {
	if name, ok := s.methodNames[method]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN_%d", method)
}

func (s *SwitchEngine) Stats() map[string]interface{} {
	return map[string]interface{}{
		"current_method":    s.MethodName(s.Current()),
		"current_method_id": s.Current(),
		"available_methods": s.availableMethods,
		"switch_count":      atomic.LoadInt64(&s.switchCount),
	}
}
