package main

import (
	"crypto/tls"
	"net"
	"time"
)

type TLSRealInfo struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	Expiry  string `json:"expiry"`
}

func GetRealTLSInfo(domain string) *TLSRealInfo {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", domain+":443", conf)
	if err != nil {
		return &TLSRealInfo{Issuer: "Unknown (No HTTPS)", Expiry: "N/A"}
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	
	return &TLSRealInfo{
		Issuer:  cert.Issuer.CommonName,
		Subject: cert.Subject.CommonName,
		Expiry:  cert.NotAfter.Format("2006-01-02"),
	}
}
