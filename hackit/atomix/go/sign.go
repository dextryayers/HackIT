package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type SignedTemplate struct {
	TemplateID  string `json:"template_id"`
	Checksum    string `json:"checksum"`
	Signature   string `json:"signature"`
	Signer      string `json:"signer,omitempty"`
	Timestamp   string `json:"timestamp"`
	Algorithm   string `json:"algorithm"`
}

const SignAlgorithm = "ed25519-sha256"

func GenerateSignKeyPair() (privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, err error) {
	publicKey, privateKey, err = ed25519.GenerateKey(rand.Reader)
	return
}

func SignTemplate(templateID, content string, privateKey ed25519.PrivateKey) (*SignedTemplate, error) {
	hash := sha256.Sum256([]byte(content))
	checksum := hex.EncodeToString(hash[:])

	sig := ed25519.Sign(privateKey, hash[:])

	return &SignedTemplate{
		TemplateID: templateID,
		Checksum:   checksum,
		Signature:  hex.EncodeToString(sig),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Algorithm:  SignAlgorithm,
	}, nil
}

func VerifyTemplateSignature(templateID, content string, sig *SignedTemplate, publicKey ed25519.PublicKey) (bool, error) {
	if sig.Algorithm != SignAlgorithm {
		return false, fmt.Errorf("unsupported algorithm: %s", sig.Algorithm)
	}

	expectedHash := sha256.Sum256([]byte(content))
	if hex.EncodeToString(expectedHash[:]) != sig.Checksum {
		return false, fmt.Errorf("content checksum mismatch (tampered)")
	}

	sigBytes, err := hex.DecodeString(sig.Signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}

	valid := ed25519.Verify(publicKey, expectedHash[:], sigBytes)
	if !valid {
		return false, fmt.Errorf("signature verification failed")
	}
	return true, nil
}

func HandleSignTemplate(cfg *ScanConfig) {
	if cfg.Sign == "" {
		return
	}

	content, err := os.ReadFile(cfg.Sign)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Read error: %v\n", SColor(ColorRed, "[!]"), err)
		return
	}

	var keyHex string
	if cfg.SignKey != "" {
		keyData, err := os.ReadFile(cfg.SignKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Key file error: %v\n", SColor(ColorRed, "[!]"), err)
			return
		}
		keyHex = strings.TrimSpace(string(keyData))
	} else {
		_, priv, _ := GenerateSignKeyPair()
		keyHex = hex.EncodeToString(priv)
	}

	privBytes, err := hex.DecodeString(keyHex)
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		fmt.Fprintf(os.Stderr, "%s Invalid private key\n", SColor(ColorRed, "[!]"))
		return
	}
	privateKey := ed25519.PrivateKey(privBytes)

	templateID := extractTemplateID(string(content))
	signed, err := SignTemplate(templateID, string(content), privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Sign error: %v\n", SColor(ColorRed, "[!]"), err)
		return
	}

	sigFile := cfg.Sign + ".sig"
	data, _ := json.MarshalIndent(signed, "", "  ")
	os.WriteFile(sigFile, data, 0644)

	fmt.Fprintf(os.Stderr, "%s Signed template: %s\n",
		SColor(ColorGreen, "[+]"), cfg.Sign)
	fmt.Fprintf(os.Stderr, "  Signature: %s\n", sigFile)
	fmt.Fprintf(os.Stderr, "  Algorithm: %s\n", SignAlgorithm)
	fmt.Printf("%s\n", string(data))
}

func HandleVerifyTemplate(cfg *ScanConfig) {
	if cfg.Verify == "" {
		return
	}

	content, err := os.ReadFile(cfg.Verify)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Read error: %v\n", SColor(ColorRed, "[!]"), err)
		return
	}

	sigFile := cfg.Verify + ".sig"
	sigData, err := os.ReadFile(sigFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Signature file not found: %s\n", SColor(ColorRed, "[!]"), sigFile)
		return
	}

	var sig SignedTemplate
	if err := json.Unmarshal(sigData, &sig); err != nil {
		fmt.Fprintf(os.Stderr, "%s Invalid signature: %v\n", SColor(ColorRed, "[!]"), err)
		return
	}

	var pubKey ed25519.PublicKey
	if cfg.VerifyKey != "" {
		keyData, err := os.ReadFile(cfg.VerifyKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Key file error: %v\n", SColor(ColorRed, "[!]"), err)
			return
		}
		keyHex := strings.TrimSpace(string(keyData))
		pubBytes, _ := hex.DecodeString(keyHex)
		pubKey = ed25519.PublicKey(pubBytes)
	} else {
		fmt.Fprintf(os.Stderr, "%s Need --verify-key for verification\n", SColor(ColorRed, "[!]"))
		return
	}

	valid, err := VerifyTemplateSignature(sig.TemplateID, string(content), &sig, pubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Verification failed: %v\n", SColor(ColorRed, "[!]"), err)
		return
	}

	if valid {
		fmt.Fprintf(os.Stderr, "%s Template verified: %s\n",
			SColor(ColorGreen, "[+]"), cfg.Verify)
		fmt.Fprintf(os.Stderr, "  Template ID: %s\n", sig.TemplateID)
		fmt.Fprintf(os.Stderr, "  Signed: %s\n", sig.Timestamp)
	} else {
		fmt.Fprintf(os.Stderr, "%s Signature INVALID for %s\n",
			SColor(ColorRed, "[!]"), cfg.Verify)
	}
}

func extractTemplateID(content string) string {
	idx := strings.Index(content, "id:")
	if idx == -1 {
		return "unknown"
	}
	line := content[idx:]
	eol := strings.Index(line, "\n")
	if eol > 0 {
		line = line[:eol]
	}
	parts := strings.Split(line, ":")
	if len(parts) >= 2 {
		return strings.TrimSpace(parts[1])
	}
	return "unknown"
}
