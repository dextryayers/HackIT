package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

type OOBProvider struct {
	Type    string
	Server  string
	Token   string
	Domain  string
	Client  *http.Client
}

func NewOOBProvider(config *ScanConfig) *OOBProvider {
	oob := &OOBProvider{Client: NewHTTPClient(10)}
	if config.Interactsh {
		server := config.InteractshServer
		if server == "" { server = "https://interact.sh" }
		oob.Type = "interactsh"
		oob.Server = server
		oob.Token = config.InteractshToken
		oob.Domain = generateOOBSubdomain() + "." + extractDomain(server)
		return oob
	}
	if config.Ceye {
		oob.Type = "ceye"
		oob.Domain = config.CeyeDomain
		oob.Token = config.CeyeToken
		return oob
	}
	return nil
}

func (oob *OOBProvider) GetDomain() string {
	if oob == nil { return "" }
	return oob.Domain
}

func (oob *OOBProvider) GetPayload(template string) string {
	if oob == nil { return template }
	domain := oob.GetDomain()
	result := strings.ReplaceAll(template, "{{oob}}", domain)
	result = strings.ReplaceAll(result, "{{oob-domain}}", domain)
	result = strings.ReplaceAll(result, "{{oob-http}}", fmt.Sprintf("http://%s", domain))
	result = strings.ReplaceAll(result, "{{oob-dns}}", domain)
	result = strings.ReplaceAll(result, "{{oob-ldap}}", fmt.Sprintf("ldap://%s/a", domain))
	result = strings.ReplaceAll(result, "{{oob-rmi}}", fmt.Sprintf("rmi://%s/a", domain))
	return result
}

func (oob *OOBProvider) CheckInteraction() bool {
	if oob == nil { return false }
	switch oob.Type {
	case "interactsh":
		return oob.checkInteractsh()
	case "ceye":
		return oob.checkCeye()
	}
	return false
}

func (oob *OOBProvider) checkInteractsh() bool {
	url := fmt.Sprintf("%s/api/v1/events?id=%s", oob.Server, oob.Token)
	resp, err := SendRequest(oob.Client, url, "GET", "", nil)
	if err != nil { return false }
	return strings.Contains(resp.Body, oob.Domain)
}

func (oob *OOBProvider) checkCeye() bool {
	url := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=dns&filter=%s", oob.Token, oob.Domain)
	resp, err := SendRequest(oob.Client, url, "GET", "", nil)
	if err != nil { return false }
	return strings.Contains(resp.Body, "data")
}

func extractDomain(server string) string {
	server = strings.TrimPrefix(server, "https://")
	server = strings.TrimPrefix(server, "http://")
	parts := strings.Split(server, "/")
	if len(parts) > 0 { return parts[0] }
	return "interact.sh"
}

func generateOOBSubdomain() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[n.Int64()]
	}
	return string(b) + fmt.Sprintf("%x", time.Now().UnixNano()%99999)
}
