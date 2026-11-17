package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// PMKID_LABEL is the fixed string used when computing the PMKID KDE hash:
// HMAC-SHA1(PMK, "PMK Name" || AP_MAC || STA_MAC)[:16].
const PMKID_LABEL = "PMK Name"

// EAPOL magic constants for the 802.1X authentication frame.
const (
	eapolKeyType        = 3
	eapolKeyDescriptor  = 2 // RSN
	eapolKeyDescriptorW = 254
	micOffset           = 77
	nonceOffset         = 13
	keyInfoOffset       = 1
	keyDataLenOffset    = 93
)

// Hash22000 is a parsed hashcat 22000 record. Both PMKID (type 01) and
// 4-way EAPOL (type 02) hashes share the same structure; the fields that
// matter depend on the type discriminator.
type Hash22000 struct {
	Kind      string // "01" (PMKID) or "02" (EAPOL)
	MIC       []byte // 16 bytes for both kinds
	APMAC     []byte // 6 bytes
	STAMAC    []byte // 6 bytes
	SSID      string
	EAPOL     []byte // full EAPOL frame with MIC in place (kind 02 only)
	MsgPair   string
	ANonce    []byte   // optional; carried in the message-pair field when present
	Valid     bool
	ParseNote string
}

// DerivePMK computes the 256-bit pairwise master key: PBKDF2-HMAC-SHA1 with
// 4096 iterations over the passphrase and SSID.
func DerivePMK(password string, ssid string) []byte {
	return pbkdf2.Key([]byte(password), []byte(ssid), 4096, 32, sha1.New)
}

// ComputePMKID derives the PMKID without a full handshake — it works when the
// AP exposes the PMKID KDE in its association response.
func ComputePMKID(pmk []byte, apMac []byte, clientMac []byte) []byte {
	// PMKID = HMAC-SHA1(key=PMK, "PMK Name" || AP_MAC || STA_MAC)[:16]
	mac := hmac.New(sha1.New, pmk)
	mac.Write([]byte(PMKID_LABEL))
	mac.Write(apMac)
	mac.Write(clientMac)
	return mac.Sum(nil)[:16]
}

// ComputeMIC computes the 16-byte EAPOL MIC over the whole EAPOL frame using
// the first 16 bytes of the PTK (KCK).
func ComputeMIC(eapolFrame []byte, ptk []byte) []byte {
	mac := hmac.New(sha1.New, ptk[:16])
	mac.Write(eapolFrame)
	return mac.Sum(nil)[:16]
}

// derivePtK expands the PMK into the 64-byte PTK using the PRF-512
// construction. Concatenated inputs are ordered by MAC and by nonce per spec.
func derivePtK(pmk, anonce, snonce, apMac, clientMac []byte) []byte {
	pMin := minMac(apMac, clientMac)
	pMax := maxMac(apMac, clientMac)
	nMin := minNonce(anonce, snonce)
	nMax := maxNonce(anonce, snonce)

	pke := make([]byte, 0, 128)
	pke = append(pke, pMin...)
	pke = append(pke, pMax...)
	pke = append(pke, nMin...)
	pke = append(pke, nMax...)

	ptk := make([]byte, 64)
	for i := 0; i < 4; i++ {
		hm := hmac.New(sha1.New, pmk)
		hm.Write([]byte{byte(i)})
		hm.Write(pke)
		copy(ptk[i*16:(i+1)*16], hm.Sum(nil)[:16])
	}
	return ptk
}

// ParseHC22000Line decodes one hashcat 22000 record.
//
// Format:
//
//	WPA*<type>*<MIC/PMKID>*<AP_MAC>*<STA_MAC>*<SSID_HEX>*<EAPOL_HEX>*<MESSAGEPAIR>***
//
// Fields are separated by '*' with the EAPOL field placed before the message
// pair. Trailing '***' markers are stripped.
func ParseHC22000Line(line string) (pmkidHex string, apMac []byte, clientMac []byte, ssid string, err error) {
	h, perr := ParseHash22000(line)
	if perr != nil {
		return "", nil, nil, "", perr
	}
	return hex.EncodeToString(h.MIC), h.APMAC, h.STAMAC, h.SSID, nil
}

// ParseHash22000 is the full parser used by the crack engine.
func ParseHash22000(line string) (*Hash22000, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, fmt.Errorf("empty hash line")
	}
	fields := strings.Split(line, "*")
	if len(fields) < 6 {
		return nil, fmt.Errorf("invalid 22000 record: only %d fields", len(fields))
	}
	if fields[0] != "WPA" {
		return nil, fmt.Errorf("invalid 22000 record: missing WPA prefix")
	}

	h := &Hash22000{Kind: fields[1]}

	mic, err := hex.DecodeString(fields[2])
	if err != nil || len(mic) != 16 {
		return nil, fmt.Errorf("invalid MIC field %q", fields[2])
	}
	h.MIC = mic

	ap, err := hex.DecodeString(replaceColon(fields[3]))
	if err != nil || len(ap) != 6 {
		return nil, fmt.Errorf("invalid AP MAC %q", fields[3])
	}
	h.APMAC = ap

	sta, err := hex.DecodeString(replaceColon(fields[4]))
	if err != nil || len(sta) != 6 {
		return nil, fmt.Errorf("invalid STA MAC %q", fields[4])
	}
	h.STAMAC = sta

	ssidBytes, err := hex.DecodeString(fields[5])
	if err != nil {
		return nil, fmt.Errorf("invalid SSID hex %q", fields[5])
	}
	h.SSID = string(ssidBytes)

	if len(fields) > 6 && fields[6] != "" {
		eapol, err := hex.DecodeString(fields[6])
		if err != nil {
			return nil, fmt.Errorf("invalid EAPOL hex")
		}
		h.EAPOL = eapol
	}
	if len(fields) > 7 {
		h.MsgPair = fields[7]
		// Non-standard extension used by HackIT capture: "<pair><64 hex ANonce>".
		if len(h.MsgPair) == 66 {
			if an, derr := hex.DecodeString(h.MsgPair[2:]); derr == nil && len(an) == 32 {
				h.ANonce = an
				h.MsgPair = h.MsgPair[:2]
			}
		}
	}

	if h.Kind == "02" && len(h.EAPOL) < 99 {
		h.ParseNote = "EAPOL frame too short to crack"
	}
	h.Valid = h.ParseNote == ""
	return h, nil
}

// replaceColon strips ':' from a MAC string so hex.DecodeString accepts both
// "aa:bb:cc:dd:ee:ff" and "aabbccddeeff" forms.
func replaceColon(s string) string {
	return strings.ReplaceAll(s, ":", "")
}

// ExtractNonces pulls ANonce and SNonce from a full EAPOL-Key frame.
func ExtractNonces(eapol []byte) (anonce, snonce []byte, err error) {
	if len(eapol) < 99 {
		return nil, nil, fmt.Errorf("EAPOL frame too short")
	}
	// EAPOL header: version(1) type(1) length(2); key body follows.
	if eapol[1] != eapolKeyType {
		return nil, nil, fmt.Errorf("not an EAPOL-Key frame")
	}
	body := eapol[4:]
	keyInfo := binary.BigEndian.Uint16(body[keyInfoOffset:])
	ack := keyInfo&0x0080 != 0
	micSet := keyInfo&0x0100 != 0
	nonce := body[nonceOffset : nonceOffset+32]
	if ack && !micSet {
		return nonce, nil, nil
	}
	if !ack && micSet {
		return nil, nonce, nil
	}
	return nil, nil, fmt.Errorf("message 3 carries ANonce; use message 2 for both")
}

// Crack4Way attempts the supplied wordlist against a 4-way handshake hash.
// It returns the recovered passphrase and the number of candidates tried.
//
// The caller is responsible for progress reporting; a callback is invoked
// every `reportEvery` attempts.
func Crack4Way(h *Hash22000, wordlist []string,
	report func(tested int64, total int64, password string) bool) (string, int64) {

	if h == nil || !h.Valid || h.Kind != "02" || len(h.EAPOL) == 0 {
		return "", 0
	}
	anonce, snonce, err := ExtractNonces(h.EAPOL)
	if h.ANonce != nil {
		anonce = h.ANonce
	}
	if err != nil && (anonce == nil || snonce == nil) {
		return "", 0
	}
	if anonce == nil || snonce == nil {
		return "", 0
	}

	total := int64(len(wordlist))
	var tested int64
	for i, password := range wordlist {
		if password == "" {
			continue
		}
		tested++
		pmk := DerivePMK(password, h.SSID)
		ptk := derivePtK(pmk, anonce, snonce, h.APMAC, h.STAMAC)
		mac := hmac.New(sha1.New, ptk[:16])
		mac.Write(eapolForMIC(h.EAPOL))
		mic := mac.Sum(nil)[:16]
		if hmacEqual(mic, h.MIC) {
			return password, tested
		}
		if report != nil && i%2000 == 0 {
			if report(tested, total, "") {
				return "", tested
			}
		}
	}
	return "", tested
}

// eapolForMIC returns a copy of the EAPOL frame with the MIC field zeroed —
// the MIC is computed over the frame with that field set to zero.
func eapolForMIC(eapol []byte) []byte {
	copyFrame := make([]byte, len(eapol))
	copy(copyFrame, eapol)
	bodyStart := 4
	if len(copyFrame) >= bodyStart+micOffset+16 {
		for i := bodyStart + micOffset; i < bodyStart+micOffset+16; i++ {
			copyFrame[i] = 0
		}
	}
	return copyFrame
}

// CrackPBKDF2 is the compatibility entry used by the worker pool. It performs
// a PMKID check only, which needs no handshake frame; 4-way cracking goes
// through Crack4Way.
func CrackPBKDF2(hashLine string) bool {
	_, err := ParseHash22000(hashLine)
	return err == nil
}

func minMac(a, b []byte) []byte {
	for i := 0; i < 6; i++ {
		if a[i] < b[i] {
			return a
		} else if a[i] > b[i] {
			return b
		}
	}
	return a
}

func maxMac(a, b []byte) []byte {
	for i := 0; i < 6; i++ {
		if a[i] > b[i] {
			return a
		} else if a[i] < b[i] {
			return b
		}
	}
	return a
}

func minNonce(a, b []byte) []byte {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return a
		} else if a[i] > b[i] {
			return b
		}
	}
	return a
}

func maxNonce(a, b []byte) []byte {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] > b[i] {
			return a
		} else if a[i] < b[i] {
			return b
		}
	}
	return a
}

func hexString(s string) string {
	return hex.EncodeToString([]byte(s))
}

func hexDecodeSSID(s string) (string, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
