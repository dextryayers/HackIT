package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

func buildRadiotapHeader() []byte {
	header := make([]byte, 8)
	binary.LittleEndian.PutUint16(header[0:2], 0)

	binary.LittleEndian.PutUint16(header[2:4], 8)

	binary.LittleEndian.PutUint32(header[4:8], 0)
	return header
}

func BuildAuthFrame(bssid, sta []byte, algo, seq, status uint16) []byte {
	radiotap := buildRadiotapHeader()

	frame := make([]byte, 0, 26)
	frame = append(frame, 0xB0, 0x00)

	frame = binary.LittleEndian.AppendUint16(frame, 0)

	frame = append(frame, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}...)
	frame = append(frame, bssid...)
	frame = append(frame, sta...)

	payload := make([]byte, 0, 6)
	payload = binary.LittleEndian.AppendUint16(payload, algo)
	payload = binary.LittleEndian.AppendUint16(payload, seq)
	payload = binary.LittleEndian.AppendUint16(payload, status)

	result := make([]byte, 0, len(radiotap)+len(frame)+len(payload))
	result = append(result, radiotap...)
	result = append(result, frame...)
	result = append(result, payload...)
	return result
}

func BuildAssocReq(bssid, sta []byte, ssid string) []byte {
	radiotap := buildRadiotapHeader()

	frame := make([]byte, 0, 24)
	frame = append(frame, 0x00, 0x01)

	capInfo := []byte{0x04, 0x00}
	frame = append(frame, capInfo...)

	frame = append(frame, 0x00, 0x00)

	frame = append(frame, bssid...)
	frame = append(frame, bssid...)
	frame = append(frame, sta...)

	payload := make([]byte, 0, 2+len(ssid))
	payload = append(payload, 0x00)
	payload = append(payload, byte(len(ssid)))
	payload = append(payload, []byte(ssid)...)

	result := make([]byte, 0, len(radiotap)+len(frame)+len(payload))
	result = append(result, radiotap...)
	result = append(result, frame...)
	result = append(result, payload...)
	return result
}

func BuildProbeResp(bssid, sta []byte, ssid string, channel uint8) []byte {
	radiotap := buildRadiotapHeader()

	frame := make([]byte, 0, 24)
	frame = append(frame, 0x50, 0x00)

	timestamp := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestamp, 0)
	frame = append(frame, timestamp...)

	beaconInterval := []byte{0x64, 0x00}
	frame = append(frame, beaconInterval...)

	capInfo := []byte{0x04, 0x00}
	frame = append(frame, capInfo...)

	frame = append(frame, bssid...)
	frame = append(frame, bssid...)
	frame = append(frame, sta...)

	payload := make([]byte, 0)
	payload = append(payload, 0x00)
	payload = append(payload, byte(len(ssid)))
	payload = append(payload, []byte(ssid)...)

	payload = append(payload, 0x03)
	payload = append(payload, 0x01)
	payload = append(payload, channel)

	result := make([]byte, 0, len(radiotap)+len(frame)+len(payload))
	result = append(result, radiotap...)
	result = append(result, frame...)
	result = append(result, payload...)
	return result
}

func BuildNullData(bssid, sta []byte, powerSave bool) []byte {
	radiotap := buildRadiotapHeader()

	frame := make([]byte, 0, 24)
	fc := byte(0x48)
	if powerSave {
		fc = 0x48
	}
	frame = append(frame, fc, 0x02)

	frame = binary.LittleEndian.AppendUint16(frame, 0)

	frame = append(frame, bssid...)
	frame = append(frame, bssid...)
	frame = append(frame, sta...)

	result := make([]byte, 0, len(radiotap)+len(frame))
	result = append(result, radiotap...)
	result = append(result, frame...)
	return result
}

func SendFrame(iface string, frame []byte) error {
	pcapPath := fmt.Sprintf("frames_%s.pcap", iface)
	f, err := os.OpenFile(pcapPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open pcap file %s: %w", pcapPath, err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat pcap file: %w", err)
	}

	if stat.Size() == 0 {
		pcapHeader := make([]byte, 24)
		binary.LittleEndian.PutUint32(pcapHeader[0:4], 0xa1b2c3d4)
		binary.LittleEndian.PutUint16(pcapHeader[4:6], 2)
		binary.LittleEndian.PutUint16(pcapHeader[6:8], 4)
		binary.LittleEndian.PutUint32(pcapHeader[8:12], 0)
		binary.LittleEndian.PutUint32(pcapHeader[12:16], 0)
		binary.LittleEndian.PutUint32(pcapHeader[16:20], 0x40000)
		binary.LittleEndian.PutUint32(pcapHeader[20:24], 105)

		_, err := f.Write(pcapHeader)
		if err != nil {
			return fmt.Errorf("failed to write pcap header: %w", err)
		}
	}

	pktRecord := make([]byte, 16+len(frame))
	binary.LittleEndian.PutUint32(pktRecord[0:4], 0)
	binary.LittleEndian.PutUint32(pktRecord[4:8], 0)
	binary.LittleEndian.PutUint32(pktRecord[8:12], uint32(len(frame)))
	binary.LittleEndian.PutUint32(pktRecord[12:16], uint32(len(frame)))
	copy(pktRecord[16:], frame)

	_, err = f.Write(pktRecord)
	if err != nil {
		return fmt.Errorf("failed to write packet record: %w", err)
	}

	return nil
}
