//go:build syn

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type SYNResult struct {
	Port   int    `json:"port"`
	State  int    `json:"state"`
	TTL    int    `json:"ttl"`
	Window int    `json:"window"`
	Flags  string `json:"flags"`
}

type SYNConfig struct {
	Target    string
	Ports     []int
	TimeoutMs int
	BurstSize int
	Workers   int
	SourceIP  net.IP
	SrcPort   int
}

func resolveIP(host string) net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil
	}
	return ips[0]
}

func getSourceIP(dst net.IP) net.IP {
	conn, err := net.DialTimeout("udp", dst.String()+":80", time.Second)
	if err != nil {
		return net.IPv4(1, 1, 1, 1)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP
}

func tcpChecksum(iph *layers.IPv4, tcph *layers.TCP) uint16 {
	ph := make([]byte, 12)
	copy(ph[0:4], iph.SrcIP.To4())
	copy(ph[4:8], iph.DstIP.To4())
	ph[8] = 0
	ph[9] = 6
	payload := tcph.SerializeLayer()
	tcpLen := 20 + len(payload)
	ph[10] = byte(tcpLen >> 8)
	ph[11] = byte(tcpLen & 0xFF)
	buf := make([]byte, 0)
	buf = append(buf, ph...)
	tcpBytes := make([]byte, tcpLen)
	tcph.SerializeTo(tcpBytes)
	buf = append(buf, tcpBytes...)
	var sum uint32
	for i := 0; i+1 < len(buf); i += 2 {
		sum += uint32(buf[i])<<8 | uint32(buf[i+1])
	}
	if len(buf)%2 == 1 {
		sum += uint32(buf[len(buf)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildSYNPacket(srcIP, dstIP net.IP, srcPort, dstPort int, seq uint32) []byte {
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TOS:      0,
		Length:   40,
		Id:       uint16(time.Now().UnixNano() & 0xFFFF),
		Flags:    layers.IPv4DontFragment,
		FragOffset: 0,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		SYN:     true,
		Window:  65535,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp); err != nil {
		return nil
	}
	return buf.Bytes()
}

func listenForResponses(handle *pcap.Handle, ports map[int]bool, timeoutMs int) ([]SYNResult, []SYNResult) {
	var openPorts []SYNResult
	var closedPorts []SYNResult
	seen := make(map[int]bool)
	deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for time.Now().Before(deadline) {
		select {
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				continue
			}
			ip, _ := ipLayer.(*layers.IPv4)
			if ip == nil || ip.Protocol != layers.IPProtocolTCP {
				continue
			}
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				continue
			}
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp == nil {
				continue
			}
			dstPort := int(tcp.DstPort)
			if !ports[dstPort] || seen[dstPort] {
				continue
			}
			if tcp.SYN && tcp.ACK {
				seen[dstPort] = true
				openPorts = append(openPorts, SYNResult{
					Port:   dstPort,
					State:  1,
					TTL:    int(ip.TTL),
					Window: int(tcp.Window),
					Flags:  "SYN/ACK",
				})
			} else if tcp.RST {
				if ports[dstPort] && !seen[dstPort] {
					seen[dstPort] = true
					closedPorts = append(closedPorts, SYNResult{
						Port:   dstPort,
						State:  0,
						TTL:    int(ip.TTL),
						Window: int(tcp.Window),
						Flags:  "RST",
					})
				}
			}
		case <-time.After(10 * time.Millisecond):
			continue
		}
	}
	return openPorts, closedPorts
}

func runSYNScan(cfg SYNConfig) ([]SYNResult, error) {
	dstIP := resolveIP(cfg.Target)
	if dstIP == nil {
		return nil, fmt.Errorf("cannot resolve target")
	}
	if dstIP.To4() == nil {
		return nil, fmt.Errorf("IPv6 not supported")
	}
	srcIP := cfg.SourceIP
	if srcIP == nil {
		srcIP = getSourceIP(dstIP)
	}
	ifaceName := "eth0"
	ifaces, err := pcap.FindAllDevs()
	if err == nil {
		for _, iface := range ifaces {
			for _, addr := range iface.Addresses {
				if addr.IP.Equal(srcIP) {
					ifaceName = iface.Name
					break
				}
			}
		}
	}
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		filter := fmt.Sprintf("tcp and dst host %s", dstIP.String())
		if err := handle.SetBPFFilter(filter); err == nil {
			handle.SetBPFFilter(filter)
		}
	}
	if handle != nil {
		defer handle.Close()
	}
	var wg sync.WaitGroup
	var sentCount int32
	portMap := make(map[int]bool)
	for _, p := range cfg.Ports {
		portMap[p] = true
	}
	burstChan := make(chan int, cfg.BurstSize)
	for w := 0; w < cfg.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range burstChan {
				seq := uint32(time.Now().UnixNano() & 0xFFFFFFFF)
				srcPort := cfg.SrcPort
				if srcPort == 0 {
					srcPort = 10000 + int(time.Now().UnixNano()%55535)
				}
				pkt := buildSYNPacket(srcIP, dstIP, srcPort, port, seq)
				if handle != nil && pkt != nil {
					handle.WritePacketData(pkt)
				}
				atomic.AddInt32(&sentCount, 1)
			}
		}()
	}
	go func() {
		for _, port := range cfg.Ports {
			burstChan <- port
			time.Sleep(time.Duration(cfg.TimeoutMs/cfg.BurstSize) * time.Microsecond)
		}
		close(burstChan)
	}()
	wg.Wait()
	openPorts, closedPorts := listenForResponses(handle, portMap, cfg.TimeoutMs)
	allPorts := make(map[int]bool)
	for _, p := range cfg.Ports {
		allPorts[p] = true
	}
	for _, r := range openPorts {
		delete(allPorts, r.Port)
	}
	for _, r := range closedPorts {
		delete(allPorts, r.Port)
	}
	var results []SYNResult
	results = append(results, openPorts...)
	results = append(results, closedPorts...)
	return results, nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <target> <ports> [timeout_ms] [workers] [burst]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  ports: 22,80,443,1-1024,top100,all\n")
		fmt.Fprintf(os.Stderr, "Example: %s scanme.nmap.org 22,80,443 2000 4 5000\n", os.Args[0])
		os.Exit(1)
	}
	target := os.Args[1]
	portSpec := os.Args[2]
	timeoutMs := 2000
	workers := 4
	burstSize := 5000
	if len(os.Args) > 3 {
		fmt.Sscanf(os.Args[3], "%d", &timeoutMs)
	}
	if len(os.Args) > 4 {
		fmt.Sscanf(os.Args[4], "%d", &workers)
	}
	if len(os.Args) > 5 {
		fmt.Sscanf(os.Args[5], "%d", &burstSize)
	}
	ports := ParsePorts(portSpec)
	if len(ports) == 0 {
		fmt.Fprintf(os.Stderr, "No valid ports\n")
		os.Exit(1)
	}
	cfg := SYNConfig{
		Target:    target,
		Ports:     ports,
		TimeoutMs: timeoutMs,
		BurstSize: burstSize,
		Workers:   workers,
	}
	fmt.Fprintf(os.Stderr, "SYN_SCAN target=%s ports=%d timeout=%dms workers=%d burst=%d\n",
		target, len(ports), timeoutMs, workers, burstSize)
	start := time.Now()
	results, err := runSYNScan(cfg)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR:%s\n", err.Error())
		os.Exit(1)
	}
	for _, r := range results {
		if r.State == 1 {
			b, _ := json.Marshal(r)
			fmt.Printf("RESULT:%s\n", string(b))
		}
	}
	final := map[string]interface{}{
		"target":     target,
		"total":      len(ports),
		"open":       len(results),
		"elapsed_ms": elapsed,
	}
	fb, _ := json.Marshal(final)
	fmt.Fprintf(os.Stderr, "FINAL:%s\n", string(fb))
}
