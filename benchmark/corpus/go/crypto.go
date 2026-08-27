package main

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// EXPECTED: RSA, vulnerable, public-key
func generateRSA() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// EXPECTED: ECDSA, vulnerable, signature
func generateECDSA() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// EXPECTED: AES-256, adequate, symmetric
func encryptAES(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	_ = block
	return nil, nil
}

// EXPECTED: SHA-256, adequate, hash
func hashSHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// EXPECTED: SHA-1, classical-weak, hash
func hashSHA1(data []byte) []byte {
	h := sha1.Sum(data)
	return h[:]
}

// EXPECTED: MD5, classical-weak, hash (critical severity)
func hashMD5(data []byte) []byte {
	h := md5.Sum(data)
	return h[:]
}

// EXPECTED: X.509 certificate parsing
func parseCert(certPEM []byte) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}
	fmt.Println(cert.Subject.CommonName)
}
