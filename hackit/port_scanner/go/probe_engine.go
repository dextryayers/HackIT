package main

// probe_engine.go — protocol-accurate banner capture.
//
// The old grabber used one boolean switch: the first matching `case port == N`
// won, later duplicates were dead code, and every port got exactly one shot.
// This engine instead runs an ordered probe plan per port, accumulates reads
// until the peer goes quiet, and decodes the bytes with a protocol-specific
// decoder so the reported banner matches the port that produced it.
//
// Contract:
//   ProbePort returns a ProbeResult whose Protocol is the protocol actually
//   observed on the wire. Confidence is 0..1 and reflects evidence strength,
//   not the port number. A banner that contradicts its port lowers confidence
//   and is reported with a mismatch flag so callers can surface it.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────
// Public result shape
// ─────────────────────────────────────────────────────────────────

type ProbeResult struct {
	Banner     string  `json:"banner"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	Confidence float64 `json:"confidence"`
	Evidence   string  `json:"evidence"`
	Mismatch   bool    `json:"mismatch"`
}

// probeStage is one attempt: optional payload, then read.
type probeStage struct {
	Name    string
	Payload []byte
	// Greeting means "read before writing" — the service speaks first.
	Greeting bool
	// Settle is how long to wait for the first byte after the write.
	Settle time.Duration
}

const (
	bannerMaxBytes   = 16384
	greetWait        = 450 * time.Millisecond
	probeWait        = 900 * time.Millisecond
	idleGap          = 120 * time.Millisecond
	maxProbeStages   = 6
	genericHTTPSlugs = "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
)

// ─────────────────────────────────────────────────────────────────
// Entry points
// ─────────────────────────────────────────────────────────────────

// ProbePort opens its own connections and walks the full plan for a port.
// Each stage gets a fresh connection because a failed probe can leave the
// previous socket in an unusable state (half-closed, RST pending, TLS garbage).
func ProbePort(host string, port int, timeoutMs int) ProbeResult {
	deadline := time.Duration(timeoutMs) * time.Millisecond
	if deadline < 600*time.Millisecond {
		deadline = 600 * time.Millisecond
	}
	if deadline > 5*time.Second {
		deadline = 5 * time.Second
	}

	best := ProbeResult{}
	stages := buildProbePlan(port)
	for i, st := range stages {
		if i >= maxProbeStages {
			break
		}
		res := runStage(host, port, st, deadline)
		if res.Banner == "" && res.Protocol == "" {
			continue
		}
		if betterResult(res, best) {
			best = res
		}
		// A confident decode ends the hunt; weaker evidence keeps probing so a
		// port that greets with junk still gets its HTTP/TLS attempt.
		if res.Confidence >= 0.80 {
			break
		}
	}
	if best.Banner == "" && best.Protocol == "" {
		best = ProbeResult{Protocol: "", Confidence: 0, Evidence: "no-response"}
	}
	finalizeProbe(&best, port)
	return best
}

// ProbeConn runs the plan over an already-connected socket. Used by the scan
// path so a connect-scan does not pay for a second handshake.
func ProbeConn(conn net.Conn, timeoutMs int, port int, host string) ProbeResult {
	deadline := time.Duration(timeoutMs) * time.Millisecond
	if deadline < 600*time.Millisecond {
		deadline = 600 * time.Millisecond
	}
	if deadline > 5*time.Second {
		deadline = 5 * time.Second
	}

	best := ProbeResult{}
	stages := buildProbePlan(port)
	for i, st := range stages {
		if i >= maxProbeStages {
			break
		}
		var res ProbeResult
		if i == 0 {
			res = runStageOnConn(conn, st, deadline, host, port)
		} else {
			// Later stages need a clean socket; the caller's conn is spent.
			res = runStage(host, port, st, deadline)
		}
		if res.Banner == "" && res.Protocol == "" {
			continue
		}
		if betterResult(res, best) {
			best = res
		}
		if res.Confidence >= 0.80 {
			break
		}
	}
	if best.Banner == "" && best.Protocol == "" {
		best = ProbeResult{Protocol: "", Confidence: 0, Evidence: "no-response"}
	}
	finalizeProbe(&best, port)
	return best
}

// betterResult prefers higher confidence, then longer evidence.
func betterResult(a, b ProbeResult) bool {
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
	return len(a.Banner) > len(b.Banner)
}

func runStage(host string, port int, st probeStage, timeout time.Duration) ProbeResult {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := getDialer(timeout)
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return ProbeResult{}
	}
	defer conn.Close()
	return runStageOnConn(conn, st, timeout, host, port)
}

func runStageOnConn(conn net.Conn, st probeStage, timeout time.Duration, host string, port int) ProbeResult {
	conn.SetDeadline(time.Now().Add(timeout))

	var raw []byte
	if st.Greeting {
		raw = readUntilQuiet(conn, st.Settle, bannerMaxBytes)
	} else {
		if len(st.Payload) > 0 {
			if _, err := conn.Write(st.Payload); err != nil {
				return ProbeResult{}
			}
		}
		raw = readUntilQuiet(conn, st.Settle, bannerMaxBytes)
	}
	if len(raw) == 0 {
		return ProbeResult{}
	}
	return decodeBanner(port, raw, st.Name)
}

// readUntilQuiet accumulates until the peer pauses, closes, or the cap is hit.
// A single Read returns whatever the kernel had queued, which is why the old
// grabber produced truncated MySQL handshakes and half HTTP headers.
func readUntilQuiet(conn net.Conn, firstWait time.Duration, limit int) []byte {
	if firstWait <= 0 {
		firstWait = probeWait
	}
	buf := make([]byte, 4096)
	var out []byte

	// First read uses the caller's patience.
	conn.SetReadDeadline(time.Now().Add(firstWait))
	n, err := conn.Read(buf)
	if n > 0 {
		out = append(out, buf[:n]...)
	}
	if err != nil && n == 0 {
		return out
	}

	// Subsequent reads only need a short gap; a peer that is still talking
	// answers within milliseconds.
	for len(out) < limit {
		conn.SetReadDeadline(time.Now().Add(idleGap))
		n, err = conn.Read(buf)
		if n > 0 {
			remaining := limit - len(out)
			if n > remaining {
				n = remaining
			}
			out = append(out, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return out
}

// ─────────────────────────────────────────────────────────────────
// Probe plans — ordered, with fallbacks
// ─────────────────────────────────────────────────────────────────

func buildProbePlan(port int) []probeStage {
	plan := make([]probeStage, 0, 6)

	// 1. Greeting protocols speak first. Read before writing anything.
	if serviceGreets(port) {
		plan = append(plan, probeStage{Name: "greeting", Greeting: true, Settle: greetWait})
	}

	// 2. Port-specific probe(s).
	plan = append(plan, portProbeStages(port)...)

	// 3. HTTP is the single most common service on an unknown port.
	if !hasStage(plan, "http") && !isDefinitelyNotHTTP(port) {
		plan = append(plan, probeStage{
			Name:    "http",
			Payload: []byte(fmt.Sprintf(genericHTTPSlugs, "localhost", getRandomUA())),
			Settle:  probeWait,
		})
	}

	// 4. TLS. Certificates identify more services than any text probe.
	if !hasStage(plan, "tls") && !isDefinitelyNotTLS(port) {
		plan = append(plan, probeStage{Name: "tls", Settle: probeWait})
	}

	// 5. Last resort: a bare CRLF kick catches line-oriented daemons that
	//    ignore a full HTTP request but answer a newline.
	if !hasStage(plan, "crlf") {
		plan = append(plan, probeStage{
			Name:    "crlf",
			Payload: []byte("\r\n"),
			Settle:  400 * time.Millisecond,
		})
	}
	return plan
}

func hasStage(plan []probeStage, name string) bool {
	for _, st := range plan {
		if st.Name == name {
			return true
		}
	}
	return false
}

// serviceGreets lists ports whose daemon sends a banner on connect.
func serviceGreets(port int) bool {
	switch port {
	case 21, 990, // FTP
		22, 2222, 2223, 2224, 2225, 2226, 2227, 2228, 2229, 2230, // SSH
		25, 465, 587, 2525, // SMTP
		110, 995, // POP3
		143, 993, // IMAP
		119,                   // NNTP
		194, 6667, 6660, 6697, // IRC
		3306, 3307, 3308, 3309, 3310, 3311, 3312, // MySQL
		5432, 5433, 5434, 5435, 5436, 5437, 5438, 5439, 5440, // PostgreSQL
		6379, 6380, 6381, 6382, 6383, 6384, 6385, // Redis
		27017, 27018, 27019, 27020, 27021, 27022, 27023, 27024, 27025, // MongoDB
		5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909, 5910, // VNC
		1521, 1522, 1523, 1524, 1525, 1526, 1527, // Oracle TNS
		3389, 3390, 3391, 3392, // RDP
		23,         // Telnet
		873,        // rsync
		445,        // SMB
		111,        // portmapper (may answer)
		5000, 5001, // some DBs
		5672, 5671, // AMQP (server sends connection.start)
		11211,      // memcached does not greet, but tolerates bare read
		9042, 9160: // Cassandra
		return true
	}
	return false
}

func isDefinitelyNotHTTP(port int) bool {
	switch port {
	case 22, 2222, 23, 21, 990, 25, 465, 587, 110, 995, 143, 993,
		3306, 5432, 6379, 27017, 5900, 3389, 1521, 11211, 9042,
		5672, 5671, 1883, 8883, 5222, 5223, 6667, 25565:
		return true
	}
	return false
}

func isDefinitelyNotTLS(port int) bool {
	switch port {
	case 22, 23, 21, 25, 110, 143, 3306, 6379, 11211, 27017, 5672,
		1883, 5222, 6667, 25565:
		return true
	}
	return false
}

// portProbeStages is the port-aware half of the plan. Every entry is additive:
// a port can appear in several cases because Go allows duplicate boolean cases,
// and all matches run.
func portProbeStages(port int) []probeStage {
	host := "localhost"
	stages := make([]probeStage, 0, 3)

	add := func(name string, payload []byte, settle time.Duration) {
		stages = append(stages, probeStage{Name: name, Payload: payload, Settle: settle})
	}
	addText := func(name, payload string) { add(name, []byte(payload), probeWait) }

	switch {
	// ── Mail ────────────────────────────────────────────────────
	case port == 25 || port == 587 || port == 2525:
		addText("smtp", "EHLO hackit.local\r\n")
	case port == 465:
		addText("smtp", "EHLO hackit.local\r\n")
	case port == 110:
		addText("pop3", "CAPA\r\n")
	case port == 143:
		addText("imap", "a1 CAPABILITY\r\n")
	case port == 119:
		addText("nntp", "MODE READER\r\n")

	// ── FTP ─────────────────────────────────────────────────────
	case port == 21:
		addText("ftp", "FEAT\r\n")
		addText("ftp-tls", "AUTH TLS\r\n")

	// ── SSH: greeting is enough, but ask for the algorithm list ──
	case port == 22 || port == 2222:
		// nothing to add; SSH speaks first
	}

	switch {
	// ── HTTP family: full request with correct Host ──────────────
	case isHTTPPort(port) || port == 80 || port == 8080 || port == 8000 ||
		port == 8888 || port == 8008 || port == 3000 || port == 5000:
		addText("http", fmt.Sprintf(genericHTTPSlugs, fmt.Sprintf("%s:%d", host, port), getRandomUA()))
	}

	switch {
	// ── Databases ───────────────────────────────────────────────
	case port == 3306 || (port >= 3307 && port <= 3312):
		// MySQL greets; if the greeting was empty ask nothing more.
	case port == 5432 || (port >= 5433 && port <= 5440):
		add("postgres-ssl", []byte{0, 0, 0, 8, 4, 210, 22, 47}, probeWait)
		add("postgres-startup", buildPostgresStartup(), probeWait)
	case port == 6379 || (port >= 6380 && port <= 6385):
		addText("redis", "INFO server\r\n")
	case port == 16379:
		addText("redis-cluster", "CLUSTER INFO\r\n")
	case port == 27017 || (port >= 27018 && port <= 27025):
		add("mongodb", buildMongoIsMaster(), probeWait)
	case port == 1433:
		add("mssql", buildMSSQLPreLogin(), probeWait)
	case port == 1434:
		add("mssql-browser", []byte{0x02}, probeWait)
	case port == 1521 || (port >= 1522 && port <= 1527):
		add("oracle-tns", buildOracleConnect(), probeWait)
	case port == 50000:
		add("db2", []byte{0x00, 0x27, 0xd0, 0x11, 0x00, 0x00, 0x00, 0x00}, probeWait)
	case port == 9042 || port == 9043 || port == 9044:
		add("cassandra", buildCassandraStartup(4), probeWait)
	case port == 9160:
		add("cassandra-thrift", []byte{0x80, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}, probeWait)

	// ── Remote access ───────────────────────────────────────────
	case port == 5900 || (port >= 5901 && port <= 5910):
		addText("vnc", "RFB 003.008\n")
	case port == 3389 || port == 3390 || port == 3391 || port == 3392:
		add("rdp", buildRDPNegotiate(), probeWait)
	case port == 5985 || port == 5986:
		addText("winrm", fmt.Sprintf("POST /wsman HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", host))

	// ── Directory / auth ────────────────────────────────────────
	case port == 389 || port == 3268:
		add("ldap", buildLDAPBind(), probeWait)
	case port == 636 || port == 3269:
		add("tls", nil, probeWait)
	case port == 88:
		add("kerberos", []byte{0x6a, 0x81, 0x8b, 0x30, 0x81, 0x88, 0xa1, 0x03, 0x02, 0x01, 0x05}, probeWait)

	// ── Message brokers ─────────────────────────────────────────
	case port == 5672 || port == 5671:
		add("amqp", []byte("AMQP\x00\x00\x09\x01"), probeWait)
	case port == 1883 || port == 8883:
		add("mqtt", []byte{0x10, 0x0e, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, probeWait)
	case port == 9092 || (port >= 9093 && port <= 9097):
		add("kafka", buildKafkaAPIVersions(), probeWait)
	case port == 4222 || port == 6222:
		addText("nats", "CONNECT {\"verbose\":false}\r\nPING\r\n")
	case port == 61613 || port == 61614:
		add("stomp", []byte("CONNECT\naccept-version:1.2\nhost:test\n\n\x00"), probeWait)
	case port == 61616:
		addText("activemq", fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port))

	// ── Caches / search ─────────────────────────────────────────
	case port == 11211 || (port >= 11212 && port <= 11215):
		addText("memcached", "stats\r\n")
	case port == 9200 || port == 9300 || (port >= 9201 && port <= 9210):
		addText("elasticsearch", fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port))
	case port == 2181:
		addText("zookeeper", "srvr")
		addText("zookeeper-ruok", "ruok")

	// ── Infrastructure ──────────────────────────────────────────
	case port == 2375 || port == 2376 || port == 4243:
		addText("docker", fmt.Sprintf("GET /version HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port))
	case port == 6443 || port == 8001 || port == 6444:
		addText("kubernetes", fmt.Sprintf("GET /version HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port))
	case port == 10250 || port == 10255 || (port >= 10251 && port <= 10256):
		addText("kubelet", fmt.Sprintf("GET /pods HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port))
	case port == 8500 || (port >= 8501 && port <= 8504) || port == 8300 || port == 8301 || port == 8302 || port == 8400 || port == 8600:
		addText("consul", fmt.Sprintf("GET /v1/status/leader HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port))
	case port == 2379 || port == 2380 || port == 2381 || port == 2382:
		addText("etcd", fmt.Sprintf("GET /version HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port))
	case port == 8200 || port == 8201:
		addText("vault", fmt.Sprintf("GET /v1/sys/health HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port))
	case port == 4646 || port == 4647 || port == 4648:
		addText("nomad", fmt.Sprintf("GET /v1/status/leader HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port))
	case port == 5984:
		addText("couchdb", fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port))
	case port == 4369:
		add("epmd", []byte{0x00, 0x00}, probeWait)

	// ── Monitoring ──────────────────────────────────────────────
	case port == 9090 || port == 9091:
		addText("prometheus", fmt.Sprintf("GET /metrics HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port))
	case port == 3100 || port == 3101 || port == 3102:
		addText("loki", fmt.Sprintf("GET /ready HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port))
	case port == 15672:
		addText("rabbitmq-mgmt", fmt.Sprintf("GET /api/overview HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port))

	// ── Windows / SMB ───────────────────────────────────────────
	case port == 445:
		add("smb", buildSMBNegotiate(), probeWait)
	case port == 139:
		add("netbios", buildNetBIOSSessionRequest(), probeWait)

	// ── VoIP ────────────────────────────────────────────────────
	case port == 5060:
		addText("sip", "OPTIONS sip:probe@localhost SIP/2.0\r\nVia: SIP/2.0/TCP localhost\r\nFrom: <sip:probe@localhost>;tag=1\r\nTo: <sip:probe@localhost>\r\nCall-ID: 1@localhost\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n")
	case port == 5061:
		add("tls", nil, probeWait)

	// ── Streaming ───────────────────────────────────────────────
	case port == 554 || port == 8554:
		addText("rtsp", "OPTIONS rtsp://localhost RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: hackit\r\n\r\n")
	case port == 1935:
		add("rtmp", []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, probeWait)

	// ── Games ───────────────────────────────────────────────────
	case port == 25565:
		add("minecraft", buildMinecraftHandshake(host, port), probeWait)
	case port == 27015 || port == 27016:
		add("source", []byte{0xff, 0xff, 0xff, 0xff, 0x54, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x20, 0x51, 0x75, 0x65, 0x72, 0x79, 0x00}, probeWait)

	// ── Industrial ──────────────────────────────────────────────
	case port == 502:
		add("modbus", []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x04, 0x00, 0x00, 0x00, 0x0a}, probeWait)
	case port == 102:
		add("s7", []byte{0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc0, 0x01, 0x0a, 0xc2, 0x02, 0x03, 0x02, 0xc0, 0x01, 0x0a, 0x00}, probeWait)
	case port == 44818:
		add("ethernet-ip", buildEtherNetIPListIdentity(), probeWait)

	// ── Printing ────────────────────────────────────────────────
	case port == 631:
		addText("ipp", fmt.Sprintf("POST /ipp/print HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/ipp\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", host, port))

	// ── Misc line protocols ─────────────────────────────────────
	case port == 873:
		addText("rsync", "@RSYNCD: 31.0\n")
	case port == 111:
		add("portmapper", []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xa0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, probeWait)
	case port == 5222 || port == 5223:
		addText("xmpp", "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")
	case port == 6667 || port == 6660 || port == 6697:
		addText("irc", "NICK hackit\r\nUSER hackit 0 * :hackit\r\n")
	}

	return stages
}

// ─────────────────────────────────────────────────────────────────
// Payload builders
// ─────────────────────────────────────────────────────────────────

func buildPostgresStartup() []byte {
	// StartupMessage: length, protocol 3.0, user, database, terminator.
	params := []byte("user\x00hackit\x00database\x00postgres\x00\x00")
	body := make([]byte, 8+len(params))
	binary.BigEndian.PutUint32(body[0:4], uint32(len(body)))
	binary.BigEndian.PutUint32(body[4:8], 196608) // 3.0
	copy(body[8:], params)
	return body
}

func buildMongoIsMaster() []byte {
	// OP_QUERY admin.$cmd { isMaster: 1 }
	doc := []byte{
		0x13, 0x00, 0x00, 0x00, // doc length
		0x10, 'i', 's', 'm', 'a', 's', 't', 'e', 'r', 0x00,
		0x01, 0x00, 0x00, 0x00, // true
		0x00, // end
	}
	msg := make([]byte, 16+len(doc))
	binary.LittleEndian.PutUint32(msg[0:4], uint32(16+len(doc)))
	binary.LittleEndian.PutUint32(msg[4:8], 1)      // requestID
	binary.LittleEndian.PutUint32(msg[8:12], 0)     // responseTo
	binary.LittleEndian.PutUint32(msg[12:16], 2004) // OP_QUERY
	binary.LittleEndian.PutUint32(msg[16:20], 0)    // flags
	copy(msg[20:], []byte("admin.$cmd\x00"))
	// remaining 8 bytes of namespace padding
	msg = msg[:20]
	ns := append([]byte("admin.$cmd\x00"), 0, 0, 0, 0)
	msg = append(msg, ns...)
	msg = append(msg, 0, 0, 0, 0) // numberToSkip
	msg = append(msg, 0xff, 0xff, 0xff, 0xff)
	msg = append(msg, doc...)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
}

func buildMSSQLPreLogin() []byte {
	// TDS PreLogin with VERSION, ENCRYPTION, INSTOPT, THREADID, MARS options.
	return []byte{
		0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20,
		0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03,
		0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00,
		0x01, 0xff, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,
	}
}

func buildOracleConnect() []byte {
	// TNS CONNECT packet with a minimal descriptor.
	payload := []byte{
		0x01, 0x34, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x39, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00,
		0x7f, 0xff, 0x7f, 0x08, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x20, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00,
	}
	desc := []byte("(DESCRIPTION=(CONNECT_DATA=(COMMAND=version))(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521)))")
	pkt := append(payload, desc...)
	binary.BigEndian.PutUint16(pkt[0:2], uint16(len(pkt)))
	return pkt
}

func buildCassandraStartup(version byte) []byte {
	body := []byte{0x00, 0x01, 0x00, 0x0b}
	body = append(body, []byte("CQL_VERSION")...)
	body = append(body, 0x00, 0x05)
	body = append(body, []byte("3.0.0")...)
	header := []byte{version, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, byte(len(body))}
	return append(header, body...)
}

func buildRDPNegotiate() []byte {
	return []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
		0x00, 0x00, 0x00,
	}
}

func buildLDAPBind() []byte {
	// anonymous simple bind, messageID 1
	return []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}
}

func buildSMBNegotiate() []byte {
	// SMB2 NEGOTIATE with dialect 0x0210, 0x0300, 0x0302, 0x0311
	body := []byte{
		0x00, 0x00, 0x00, 0x00, // NetBIOS session header placeholder
		0xfe, 'S', 'M', 'B',
		0x40, 0x00, 0x00, 0x00, // StructureSize
		0x00, 0x00, // DialectCount
		0x01, 0x00, // SecurityMode
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Capabilities
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientGuid
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // ClientStartTime
		0x02, 0x02, // 0x0202
		0x10, 0x02, // 0x0210
		0x00, 0x03, // 0x0300
		0x02, 0x03, // 0x0302
		0x11, 0x03, // 0x0311
	}
	binary.BigEndian.PutUint32(body[0:4], uint32(len(body)-4))
	binary.BigEndian.PutUint16(body[12:14], 4) // DialectCount at offset 4 of header... corrected below
	// SMB2 header starts at 4: StructureSize(2) DialectCount(2) ...
	// DialectCount sits at absolute offset 4+4 = 8? SMB2 header: ProtocolId(4) StructureSize(2) DialectCount(2)
	binary.LittleEndian.PutUint16(body[6:8], 0x40) // StructureSize 64
	binary.LittleEndian.PutUint16(body[8:10], 4)   // DialectCount
	return body
}

func buildNetBIOSSessionRequest() []byte {
	return []byte{0x81, 0x00, 0x00, 0x44, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x00}
}

func buildKafkaAPIVersions() []byte {
	// ApiVersions v0 request: size, api_key=18, api_version=0, correlation=1, client_id
	body := []byte{
		0x00, 0x12, // api key 18
		0x00, 0x00, // api version 0
		0x00, 0x00, 0x00, 0x01, // correlation id
		0x00, 0x06, 'h', 'a', 'c', 'k', 'i', 't',
	}
	msg := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(msg[0:4], uint32(len(body)))
	copy(msg[4:], body)
	return msg
}

func buildMinecraftHandshake(host string, port int) []byte {
	hostBytes := []byte(host)
	var payload []byte
	payload = append(payload, 0x00) // packet id
	payload = append(payload, 0x04) // protocol version 4 (1.7.2)
	payload = append(payload, hostBytes...)
	payload = append(payload, byte(port>>8), byte(port))
	payload = append(payload, 0x01) // next state: status
	var out []byte
	out = append(out, byte(len(payload)))
	out = append(out, payload...)
	out = append(out, 0x01, 0x00) // status request
	return out
}

func buildEtherNetIPListIdentity() []byte {
	return []byte{
		0x63, 0x00, // command ListIdentity
		0x00, 0x00, // length (filled below)
		0x00, 0x00, 0x00, 0x00, // session
		0x00, 0x00, 0x00, 0x00, // status
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sender context
		0x00, 0x00, 0x00, 0x00, // options
	}
}

// ─────────────────────────────────────────────────────────────────
// Decoders — protocol-aware, binary-safe
// ─────────────────────────────────────────────────────────────────

var httpStatusRe = regexp.MustCompile(`(?i)^HTTP/\d\.\d\s+\d{3}`)
var httpServerRe = regexp.MustCompile(`(?i)^server:\s*(.+)$`)
var httpTitleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func decodeBanner(port int, raw []byte, stage string) ProbeResult {
	res := ProbeResult{Evidence: stage}

	// TLS first: a TLS record header is unmistakable.
	if isTLSRecord(raw) {
		return decodeTLSBytes(port, raw, stage)
	}

	// MySQL handshake: protocol version byte then NUL-terminated server version.
	if v, ok := decodeMySQL(raw); ok {
		res.Protocol = "mysql"
		res.Product = "MySQL"
		res.Version = v
		res.Banner = "MySQL " + v
		res.Confidence = 0.98
		return res
	}

	// SSH identification string.
	if strings.HasPrefix(string(raw), "SSH-") {
		line := firstLine(raw)
		res.Protocol = "ssh"
		res.Banner = line
		res.Product, res.Version = parseSSHLine(line)
		res.Confidence = 0.99
		return res
	}

	// VNC RFB greeting.
	if bytes.HasPrefix(raw, []byte("RFB ")) {
		line := firstLine(raw)
		res.Protocol = "vnc"
		res.Banner = line
		res.Product = "VNC"
		res.Version = strings.TrimSpace(strings.TrimPrefix(line, "RFB "))
		res.Confidence = 0.97
		return res
	}

	// Redis RESP: +, -, :, $, * prefixed replies.
	if isRedisRESP(raw) {
		info := parseRedisInfo(raw)
		res.Protocol = "redis"
		res.Product = "Redis"
		res.Version = info["redis_version"]
		res.Banner = "Redis " + res.Version
		if res.Version == "" {
			res.Banner = firstLine(raw)
		}
		res.Confidence = 0.95
		return res
	}

	// PostgreSQL: 'S' (SSL ok) or 'N' (no ssl) or 'E' error.
	if len(raw) >= 1 && (raw[0] == 'S' || raw[0] == 'N') && port >= 5432 && port <= 5440 {
		res.Protocol = "postgresql"
		res.Product = "PostgreSQL"
		res.Confidence = 0.90
		res.Banner = "PostgreSQL (SSL supported)"
		if raw[0] == 'N' {
			res.Banner = "PostgreSQL (SSL refused)"
		}
		return res
	}
	if len(raw) >= 5 && raw[0] == 'E' && isPrintableASCII(raw[1:5]) {
		if pg := parsePostgresError(raw); pg != "" {
			res.Protocol = "postgresql"
			res.Product = "PostgreSQL"
			res.Version = pg
			res.Banner = "PostgreSQL " + pg
			res.Confidence = 0.93
			return res
		}
	}

	// MongoDB wire protocol: 4-byte length then requestID then responseTo.
	if isMongoReply(raw) {
		res.Protocol = "mongodb"
		res.Product = "MongoDB"
		res.Version = scanBSONVersion(raw)
		res.Banner = "MongoDB"
		if res.Version != "" {
			res.Banner += " " + res.Version
		}
		res.Confidence = 0.93
		return res
	}

	// SMB2.
	if len(raw) > 8 && bytes.Contains(raw[:16], []byte("SMB")) {
		res.Protocol = "smb"
		res.Product = "SMB"
		res.Version = parseSMBDialect(raw)
		res.Banner = "SMB " + res.Version
		res.Confidence = 0.95
		return res
	}

	// RDP X.224 negotiation response.
	if len(raw) >= 11 && raw[0] == 0x03 && raw[1] == 0x00 {
		res.Protocol = "rdp"
		res.Product = "RDP"
		res.Banner = "RDP (X.224 negotiation)"
		res.Confidence = 0.88
		return res
	}

	// AMQP connection.start.
	if bytes.HasPrefix(raw, []byte("AMQP")) {
		res.Protocol = "amqp"
		res.Product = "RabbitMQ"
		res.Banner = "AMQP " + string(raw[4:8])
		res.Confidence = 0.95
		return res
	}

	// MQTT CONNACK: 0x20 0x02 ...
	if len(raw) >= 4 && raw[0] == 0x20 && raw[1] == 0x02 {
		res.Protocol = "mqtt"
		res.Product = "MQTT"
		res.Banner = "MQTT CONNACK"
		res.Confidence = 0.90
		return res
	}

	// Kafka ApiVersions response: correlation id then error code then array len.
	if len(raw) >= 8 && port >= 9092 && port <= 9097 {
		if isKafkaResponse(raw) {
			res.Protocol = "kafka"
			res.Product = "Kafka"
			res.Banner = "Kafka broker (ApiVersions)"
			res.Confidence = 0.88
			return res
		}
	}

	// HTTP: status line + Server header + title.
	if httpStatusRe.Match(raw) {
		return decodeHTTPBytes(raw, false)
	}

	// HTTP/2 server preface (SETTINGS frame).
	if len(raw) >= 9 && string(raw[:3]) == "PRI" {
		res.Protocol = "http/2"
		res.Product = "HTTP/2"
		res.Banner = "HTTP/2 server preface"
		res.Confidence = 0.90
		return res
	}

	// LDAP bind response: SEQUENCE with messageID and 0x61.
	if len(raw) >= 8 && raw[0] == 0x30 && bytes.Contains(raw[:minInt(len(raw), 16)], []byte{0x61}) {
		res.Protocol = "ldap"
		res.Product = "LDAP"
		res.Banner = "LDAP bind response"
		res.Confidence = 0.85
		return res
	}

	// Text protocols: keep the meaningful first lines.
	text := sanitizeText(raw)
	if text == "" {
		return res
	}

	if proto, product, version, conf := classifyText(port, text); proto != "" {
		res.Protocol = proto
		res.Product = product
		res.Version = version
		res.Confidence = conf
		res.Banner = summarizeText(text, proto)
		return res
	}

	// Unknown but real bytes.
	res.Protocol = "unknown"
	res.Banner = truncateClean(text, 220)
	res.Confidence = 0.30
	return res
}

func decodeHTTPBytes(raw []byte, tls bool) ProbeResult {
	res := ProbeResult{Protocol: "http", Product: "HTTP", Confidence: 0.90}
	if tls {
		res.Protocol = "https"
	}

	text := string(raw)
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	parts := make([]string, 0, 4)
	var server, powered string
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if httpStatusRe.MatchString(trimmed) {
			parts = append(parts, trimmed)
			continue
		}
		if m := httpServerRe.FindStringSubmatch(trimmed); m != nil {
			server = strings.TrimSpace(m[1])
			parts = append(parts, "Server: "+server)
			continue
		}
		low := strings.ToLower(trimmed)
		if strings.HasPrefix(low, "x-powered-by:") || strings.HasPrefix(low, "via:") ||
			strings.HasPrefix(low, "x-generator:") || strings.HasPrefix(low, "x-aspnet-version:") ||
			strings.HasPrefix(low, "x-application-context:") || strings.HasPrefix(low, "x-frame-options:") ||
			strings.HasPrefix(low, "content-type:") {
			parts = append(parts, trimmed)
			if strings.HasPrefix(low, "x-powered-by:") {
				powered = strings.TrimSpace(trimmed[len("x-powered-by:"):])
			}
		}
	}
	if m := httpTitleRe.FindStringSubmatch(text); m != nil {
		title := strings.TrimSpace(strings.Join(strings.Fields(m[1]), " "))
		if title != "" && len(title) < 120 {
			parts = append(parts, "Title: "+title)
		}
	}
	if len(parts) > 6 {
		parts = parts[:6]
	}
	res.Banner = strings.Join(parts, " | ")
	if res.Banner == "" {
		res.Banner = truncateClean(text, 160)
	}
	if server != "" {
		res.Product, res.Version = splitProductVersion(server)
		res.Confidence = 0.97
	} else if powered != "" {
		res.Product, res.Version = splitProductVersion(powered)
		res.Confidence = 0.92
	}
	if tls {
		res.Confidence = 0.99
	}
	return res
}

func decodeTLSBytes(port int, raw []byte, stage string) ProbeResult {
	res := ProbeResult{Protocol: "tls", Product: "TLS", Confidence: 0.85, Evidence: stage}
	info := summarizeTLSRecord(raw)
	if info != "" {
		res.Banner = info
		res.Confidence = 0.92
	}
	return res
}

// classifyText maps a sanitized text banner onto a protocol family.
func classifyText(port int, text string) (string, string, string, float64) {
	low := strings.ToLower(text)

	type rule struct {
		proto   string
		product string
		needles []string
		conf    float64
	}
	rules := []rule{
		{"ftp", "FTP", []string{" 220 ", "ftp", "vsftpd", "proftpd", "pure-ftpd", "filezilla"}, 0.92},
		{"smtp", "SMTP", []string{" 220 ", "esmtp", "smtp", "postfix", "exim", "sendmail", "mailgun"}, 0.90},
		{"pop3", "POP3", []string{"+ok", "pop3", "dovecot", "courier"}, 0.88},
		{"imap", "IMAP", []string{"* ok", "imap", "dovecot", "cyrus"}, 0.88},
		{"ssh", "SSH", []string{"ssh-"}, 0.99},
		{"telnet", "Telnet", []string{"login:", "password:", "telnet"}, 0.70},
		{"mysql", "MySQL", []string{"mysql", "mariadb"}, 0.90},
		{"redis", "Redis", []string{"redis_version", "-err", "+ok"}, 0.85},
		{"mongodb", "MongoDB", []string{"mongodb", "ismaster"}, 0.85},
		{"memcached", "Memcached", []string{"version ", "stats", "curr_items"}, 0.85},
		{"rsync", "rsync", []string{"@rsyncd"}, 0.97},
		{"irc", "IRC", []string{" irc ", "ircd", "notice auth"}, 0.85},
		{"nntp", "NNTP", []string{"200 ", "nntp", "inn "}, 0.80},
		{"sip", "SIP", []string{"sip/2.0"}, 0.92},
		{"rtsp", "RTSP", []string{"rtsp/1.0"}, 0.95},
		{"xmpp", "XMPP", []string{"stream:stream", "jabber"}, 0.90},
		{"zookeeper", "ZooKeeper", []string{"zookeeper", "imok", "mode:"}, 0.85},
		{"docker", "Docker", []string{"docker", "apiVersion"}, 0.85},
		{"elasticsearch", "Elasticsearch", []string{"you know, for search", "lucene_version"}, 0.95},
		{"prometheus", "Prometheus", []string{"# help", "# type", "go_gc_duration"}, 0.85},
		{"vnc", "VNC", []string{"rfb "}, 0.95},
	}

	for _, r := range rules {
		for _, needle := range r.needles {
			if strings.Contains(low, needle) {
				// A protocol claiming a port it does not belong to is still the
				// truth of the wire; confidence carries the doubt.
				conf := r.conf
				if !portIsExpected(r.proto, port) {
					conf -= 0.10
				}
				return r.proto, r.product, extractVersionFromText(r.proto, text), conf
			}
		}
	}
	return "", "", "", 0
}

// expectedPortsFor lists the ports a protocol normally binds to. A service on
// any other port is still real — the flag is informational, never a verdict.
func expectedPortsFor(proto string) []int {
	switch proto {
	case "ftp":
		return []int{21, 2100, 2121, 8021}
	case "ssh":
		return append([]int{22, 222, 2022}, rangeInts(2222, 2230)...)
	case "smtp":
		return []int{25, 465, 587, 2525}
	case "pop3":
		return []int{110, 995}
	case "imap":
		return []int{143, 993}
	case "mysql":
		return append([]int{33060}, rangeInts(3306, 3312)...)
	case "redis":
		return append([]int{16379, 26379}, rangeInts(6379, 6385)...)
	case "mongodb":
		return rangeInts(27017, 27025)
	case "memcached":
		return rangeInts(11211, 11215)
	case "rsync":
		return []int{873}
	case "vnc":
		return rangeInts(5900, 5910)
	}
	// http, https, tls and the generic decoders run anywhere by design.
	return nil
}

func rangeInts(lo, hi int) []int {
	out := make([]int, 0, hi-lo+1)
	for i := lo; i <= hi; i++ {
		out = append(out, i)
	}
	return out
}

func portIsExpected(proto string, port int) bool {
	ports := expectedPortsFor(proto)
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

func extractVersionFromText(proto, text string) string {
	patterns := map[string]*regexp.Regexp{
		"ftp":   regexp.MustCompile(`(?i)(?:vsftpd|proftpd|pure-ftpd|filezilla)\s*([\d.]+)?`),
		"smtp":  regexp.MustCompile(`(?i)(?:postfix|exim|sendmail|opensmtpd)[^\d]*([\d.]+)`),
		"pop3":  regexp.MustCompile(`(?i)(?:dovecot|courier)[^\d]*([\d.]+)`),
		"imap":  regexp.MustCompile(`(?i)(?:dovecot|cyrus)[^\d]*([\d.]+)`),
		"mysql": regexp.MustCompile(`(?i)(?:mysql|mariadb)[^\d]*([\d.]+)`),
		"redis": regexp.MustCompile(`(?i)redis_version:([\d.]+)`),
		"rsync": regexp.MustCompile(`(?i)@rsyncd:\s*([\d.]+)`),
		"nntp":  regexp.MustCompile(`(?i)inn\s*([\d.]+)`),
		"sip":   regexp.MustCompile(`(?i)server:\s*([^\r\n]+)`),
		"rtsp":  regexp.MustCompile(`(?i)server:\s*([^\r\n]+)`),
	}
	re, ok := patterns[proto]
	if !ok {
		return ""
	}
	if m := re.FindStringSubmatch(text); m != nil {
		if len(m) > 1 && m[1] != "" {
			return strings.TrimSpace(m[1])
		}
	}
	return ""
}

func summarizeText(text, proto string) string {
	lines := strings.Split(text, "\n")
	out := make([]string, 0, 3)
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		out = append(out, ln)
		if len(out) >= 2 {
			break
		}
	}
	if len(out) == 0 {
		return truncateClean(text, 160)
	}
	joined := strings.Join(out, " | ")
	return truncateClean(joined, 220)
}

// ─────────────────────────────────────────────────────────────────
// Binary helpers
// ─────────────────────────────────────────────────────────────────

func isTLSRecord(raw []byte) bool {
	if len(raw) < 5 {
		return false
	}
	// Handshake record, TLS 1.x major version 3.
	return raw[0] == 0x16 && raw[1] == 0x03 && raw[2] <= 0x04
}

func summarizeTLSRecord(raw []byte) string {
	if len(raw) < 11 {
		return "TLS handshake"
	}
	ver := "TLS"
	switch raw[2] {
	case 0x01:
		ver = "TLS 1.0"
	case 0x02:
		ver = "TLS 1.1"
	case 0x03:
		ver = "TLS 1.2"
	case 0x04:
		ver = "TLS 1.3"
	}
	return ver + " handshake"
}

func decodeMySQL(raw []byte) (string, bool) {
	if len(raw) < 6 {
		return "", false
	}
	// Packet: 3-byte length, 1-byte sequence, 1-byte protocol version (10).
	if raw[3] != 0x00 || raw[4] != 0x0a {
		return "", false
	}
	// Server version is NUL-terminated starting at offset 5.
	end := bytes.IndexByte(raw[5:], 0x00)
	if end <= 0 || end > 64 {
		return "", false
	}
	version := string(raw[5 : 5+end])
	if !looksLikeVersion(version) {
		return "", false
	}
	return version, true
}

func looksLikeVersion(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	hasDigit := false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '.' || r == '-' || r == '_' || r == '+' || r == '~':
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
		default:
			return false
		}
	}
	return hasDigit
}

func parseSSHLine(line string) (string, string) {
	// SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
	parts := strings.SplitN(line, "-", 3)
	if len(parts) < 3 {
		return "SSH", ""
	}
	software := parts[2]
	fields := strings.FieldsFunc(software, func(r rune) bool { return r == '_' || r == ' ' })
	if len(fields) == 0 {
		return "SSH", ""
	}
	product := fields[0]
	version := ""
	if len(fields) > 1 {
		version = fields[1]
	}
	return product, version
}

func isRedisRESP(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	switch raw[0] {
	case '+', '-', ':', '$', '*':
	default:
		return false
	}
	// Require a CRLF within the first chunk to avoid matching random text.
	return bytes.Contains(raw, []byte("\r\n"))
}

func parseRedisInfo(raw []byte) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "redis_version:") {
			out["redis_version"] = strings.TrimSpace(strings.TrimPrefix(line, "redis_version:"))
		}
		if strings.HasPrefix(line, "redis_mode:") {
			out["redis_mode"] = strings.TrimSpace(strings.TrimPrefix(line, "redis_mode:"))
		}
	}
	return out
}

func parsePostgresError(raw []byte) string {
	// ErrorResponse fields are type byte + NUL-terminated string.
	body := raw[5:]
	fields := bytes.Split(body, []byte{0x00})
	for _, f := range fields {
		if len(f) < 2 {
			continue
		}
		if f[0] == 'S' { // severity, not version
			continue
		}
	}
	// PostgreSQL does not send its version in an error; return empty so the
	// caller keeps the generic product name instead of inventing a number.
	return ""
}

func isMongoReply(raw []byte) bool {
	if len(raw) < 16 {
		return false
	}
	length := binary.LittleEndian.Uint32(raw[0:4])
	if int(length) != len(raw) && int(length) > len(raw) {
		return false
	}
	opCode := binary.LittleEndian.Uint32(raw[12:16])
	return opCode == 1 || opCode == 2013 || opCode == 2004
}

func scanBSONVersion(raw []byte) string {
	idx := bytes.Index(raw, []byte("version\x00"))
	if idx < 0 || idx+8+4 > len(raw) {
		return ""
	}
	// After the key comes a 4-byte string length then the bytes.
	start := idx + len("version\x00")
	if start+4 > len(raw) {
		return ""
	}
	n := int(binary.LittleEndian.Uint32(raw[start : start+4]))
	if n <= 1 || start+4+n > len(raw) || n > 32 {
		return ""
	}
	v := string(raw[start+4 : start+4+n-1])
	if looksLikeVersion(v) {
		return v
	}
	return ""
}

func parseSMBDialect(raw []byte) string {
	// SMB2 NEGOTIATE response: DialectRevision at offset 4+4.
	if len(raw) < 12 {
		return ""
	}
	d := binary.LittleEndian.Uint16(raw[8:10])
	switch d {
	case 0x0202:
		return "2.0.2"
	case 0x0210:
		return "2.1"
	case 0x0300:
		return "3.0"
	case 0x0302:
		return "3.0.2"
	case 0x0311:
		return "3.1.1"
	case 0x02ff:
		return "1.0 (wildcard)"
	}
	return "2.x"
}

func isKafkaResponse(raw []byte) bool {
	if len(raw) < 8 {
		return false
	}
	size := binary.BigEndian.Uint32(raw[0:4])
	return size > 0 && int(size) <= len(raw)-4
}

func firstLine(raw []byte) string {
	s := string(raw)
	if idx := strings.IndexAny(s, "\r\n"); idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

func sanitizeText(raw []byte) string {
	var b strings.Builder
	for _, r := range string(raw) {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteRune(r)
		case r >= 32 && r <= 126:
			b.WriteRune(r)
		case r >= 0x80 && r < 0x10000:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func truncateClean(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

func splitProductVersion(header string) (string, string) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", ""
	}
	// "nginx/1.25.3", "Apache/2.4.58 (Ubuntu)", "Microsoft-IIS/10.0"
	if idx := strings.Index(header, "/"); idx > 0 {
		product := header[:idx]
		rest := strings.TrimSpace(header[idx+1:])
		version := ""
		if f := strings.Fields(rest); len(f) > 0 {
			if looksLikeVersion(strings.TrimSuffix(f[0], ";")) {
				version = strings.TrimSuffix(f[0], ";")
			}
		}
		if version != "" {
			return product, version
		}
		return product, ""
	}
	fields := strings.Fields(header)
	product := fields[0]
	for _, f := range fields[1:] {
		if looksLikeVersion(f) {
			return product, strings.TrimSuffix(f, ";")
		}
	}
	return product, ""
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// finalizeProbe applies port expectations and strips control noise.
func finalizeProbe(res *ProbeResult, port int) {
	res.Banner = truncateClean(strings.TrimSpace(res.Banner), 260)
	if res.Protocol == "" {
		return
	}
	if !portIsExpected(res.Protocol, port) {
		// Real service, unconventional port. Flag it, nudge confidence down,
		// never pretend the wire lied — the banner is the evidence.
		res.Mismatch = true
		if res.Confidence > 0.55 {
			res.Confidence -= 0.05
		}
	}
	if res.Confidence == 0 && res.Banner != "" {
		res.Confidence = 0.4
	}
}

// sortedKeys is used by debug output paths.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var _ = bufio.NewReader
var _ = io.EOF
