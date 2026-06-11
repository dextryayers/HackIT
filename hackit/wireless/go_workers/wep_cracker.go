package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
)

type IvPacket struct {
	Iv     [3]byte
	KeyIdx byte
	Data   []byte
}

type WepCracker struct {
	mu       sync.Mutex
	ivs      []IvPacket
	pcapPath string
	key      []byte
	ready    bool
}

func NewWepCracker() *WepCracker {
	return &WepCracker{
		ivs: make([]IvPacket, 0),
	}
}

func (w *WepCracker) LoadPcap(path string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.pcapPath = path
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read pcap file %s: %w", path, err)
	}

	if len(data) < 24 {
		return fmt.Errorf("pcap file too short: %d bytes", len(data))
	}

	offset := 24
	count := 0
	for offset+8 < len(data) {
		if offset+16 > len(data) {
			break
		}
		origLen := int(binary.LittleEndian.Uint32(data[offset+8 : offset+12]))
		if origLen < 4 || offset+16+origLen > len(data) {
			break
		}
		pktData := data[offset+16 : offset+16+origLen]
		offset += 16 + int(binary.LittleEndian.Uint32(data[offset+12:offset+16]))

		if len(pktData) < 4 {
			continue
		}
		if pktData[1]&0x40 == 0 {
			continue
		}

		var iv IvPacket
		iv.Iv[0] = pktData[0]
		iv.Iv[1] = pktData[1] & 0x3f
		iv.Iv[2] = pktData[2]
		iv.KeyIdx = pktData[3]
		if len(pktData) > 4 {
			iv.Data = make([]byte, len(pktData)-4)
			copy(iv.Data, pktData[4:])
		}
		w.ivs = append(w.ivs, iv)
		count++
	}

	if count == 0 {
		return fmt.Errorf("no WEP-encrypted packets found in pcap")
	}

	w.ready = true
	return nil
}

func (w *WepCracker) IvCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.ivs)
}

func (w *WepCracker) FmsAttack() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.ready {
		return "", fmt.Errorf("no pcap loaded, call LoadPcap first")
	}

	residual := make([]byte, 256)
	for i := 0; i < 256; i++ {
		residual[i] = byte(i)
	}

	resolved := 0
	for _, iv := range w.ivs {
		s := int(iv.Iv[2])
		b := int(iv.Iv[0])
		if s >= 248 || s < 3 {
			continue
		}

		dataLen := len(iv.Data)
		if dataLen < 1 {
			continue
		}
		firstByte := iv.Data[0]

		keyByte := byte(s + 3)
		probKey := byte(firstByte) ^ residual[s+3] ^ keyByte

		known := 0
		for _, rk := range residual {
			if rk == probKey {
				known++
			}
		}
		if known < 3 {
			continue
		}

		_ = b
		resolved++
		_ = resolved

		for j := s + 1; j < 256; j++ {
			if residual[j] == probKey {
				residual[j], residual[s+3] = residual[s+3], residual[j]
				break
			}
		}
	}

	key := make([]byte, 13)
	key[0] = 0
	key[1] = 0
	key[2] = 0
	for i := 3; i < 13; i++ {
		key[i] = residual[i]
	}

	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
		key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8], key[9], key[10], key[11], key[12]), nil
}

func (w *WepCracker) KorekAttack() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.ready {
		return "", fmt.Errorf("no pcap loaded, call LoadPcap first")
	}

	votes := make([]map[int]int, 13)
	for i := range votes {
		votes[i] = make(map[int]int)
	}

	for _, iv := range w.ivs {
		x := int(iv.Iv[0])
		y := int(iv.Iv[1])
		z := int(iv.Iv[2])

		_ = x
		_ = y

		for i := 0; i < len(iv.Data)-3; i++ {
			s := z + i
			if s >= 256 {
				continue
			}
			ks := s + 3
			if ks >= 13 {
				continue
			}
			kb := int(iv.Data[i]) ^ s
			votes[ks][kb]++
		}
	}

	key := make([]byte, 13)
	key[0] = 0
	key[1] = 0
	key[2] = 0
	for i := 3; i < 13; i++ {
		best := 0
		bestVotes := 0
		for kb, count := range votes[i] {
			if count > bestVotes {
				bestVotes = count
				best = kb
			}
		}
		key[i] = byte(best)
	}

	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
		key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8], key[9], key[10], key[11], key[12]), nil
}

func (w *WepCracker) PtwAttack() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.ready {
		return "", fmt.Errorf("no pcap loaded, call LoadPcap first")
	}

	votes := make([]map[int]float64, 13)
	for i := range votes {
		votes[i] = make(map[int]float64)
	}

	for _, iv := range w.ivs {
		s := int(iv.Iv[2])
		b := int(iv.Iv[0])

		if s >= 254 || s < 3 {
			continue
		}

		p := b + s

		for i := 0; i < len(iv.Data)-3; i++ {
			ks := s + 3 + i
			if ks >= 13 {
				continue
			}
			kb := int(iv.Data[i]) ^ s ^ p
			votes[ks][kb] += 1.0
		}
	}

	key := make([]byte, 13)
	key[0] = 0
	key[1] = 0
	key[2] = 0
	for i := 3; i < 13; i++ {
		best := 0
		bestVotes := 0.0
		for kb, count := range votes[i] {
			if count > bestVotes {
				bestVotes = count
				best = kb
			}
		}
		key[i] = byte(best)
	}

	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
		key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8], key[9], key[10], key[11], key[12]), nil
}

func (w *WepCracker) IsReady() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ready
}

func (w *WepCracker) ExportHccapx(outputPath string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.ready {
		return fmt.Errorf("no pcap loaded, call LoadPcap first")
	}

	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", outputPath, err)
	}
	defer out.Close()

	hccapxHeader := make([]byte, 52)
	copy(hccapxHeader[:4], []byte("HCPX"))

	binary.LittleEndian.PutUint32(hccapxHeader[4:8], uint32(1))

	session := make([]byte, 48)
	for i := 0; i < 24 && i < len(w.ivs); i++ {
		session[i*2] = w.ivs[i].Iv[0]
		session[i*2+1] = w.ivs[i].Iv[1]
	}
	copy(hccapxHeader[8:56], session)

	var ivCount uint32 = uint32(len(w.ivs))
	binary.LittleEndian.PutUint32(hccapxHeader[48:52], ivCount)

	_, err = out.Write(hccapxHeader)
	if err != nil {
		return fmt.Errorf("failed to write hccapx header: %w", err)
	}

	for _, iv := range w.ivs {
		record := make([]byte, 20)
		record[0] = iv.Iv[0]
		record[1] = iv.Iv[1] | 0x40
		record[2] = iv.Iv[2]
		record[3] = iv.KeyIdx
		copyLen := len(iv.Data)
		if copyLen > 16 {
			copyLen = 16
		}
		copy(record[4:4+copyLen], iv.Data[:copyLen])

		_, err := out.Write(record)
		if err != nil {
			return fmt.Errorf("failed to write iv record: %w", err)
		}
	}

	return nil
}
