package pki

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestGenerateCAAndIssueCert(t *testing.T) {
	ca, err := GenerateCA("Test CA")
	if err != nil {
		t.Fatalf("GenerateCA misslyckades: %v", err)
	}
	if !strings.Contains(ca.CertPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("CA-certifikatet är inte giltig PEM")
	}

	client, err := IssueCert(ca.CertPEM, ca.KeyPEM, "client1", false)
	if err != nil {
		t.Fatalf("IssueCert (klient) misslyckades: %v", err)
	}

	// Verifiera att klientcertifikatet faktiskt är signerat av CA:n.
	caCertBlock, _ := pem.Decode([]byte(ca.CertPEM))
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		t.Fatalf("kunde inte tolka CA-cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	clientCertBlock, _ := pem.Decode([]byte(client.CertPEM))
	clientCert, err := x509.ParseCertificate(clientCertBlock.Bytes)
	if err != nil {
		t.Fatalf("kunde inte tolka klientcert: %v", err)
	}
	if _, err := clientCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("klientcertifikatet verifierades inte mot CA:n: %v", err)
	}

	if client.Serial == ca.Serial {
		t.Errorf("klientcertifikatet fick samma serienummer som CA:n")
	}
}

// TestGenerateCRLRevokesSerial skyddar mot en regression där en spärrad
// klients serienummer inte faktiskt hamnar i CRL:en — då skulle OpenVPN-
// serverns `crl-verify` aldrig neka den spärrade klienten.
func TestGenerateCRLRevokesSerial(t *testing.T) {
	ca, err := GenerateCA("Test CA")
	if err != nil {
		t.Fatalf("GenerateCA misslyckades: %v", err)
	}
	client, err := IssueCert(ca.CertPEM, ca.KeyPEM, "client1", false)
	if err != nil {
		t.Fatalf("IssueCert misslyckades: %v", err)
	}

	crlPEM, err := GenerateCRL(ca.CertPEM, ca.KeyPEM, []string{client.Serial})
	if err != nil {
		t.Fatalf("GenerateCRL misslyckades: %v", err)
	}

	block, _ := pem.Decode([]byte(crlPEM))
	if block == nil || block.Type != "X509 CRL" {
		t.Fatalf("CRL:en är inte giltig PEM")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("kunde inte tolka CRL: %v", err)
	}

	found := false
	for _, rc := range crl.RevokedCertificateEntries {
		if rc.SerialNumber.String() == client.Serial {
			found = true
		}
	}
	if !found {
		t.Errorf("klientens serienummer %q finns inte med i den genererade CRL:en", client.Serial)
	}
}
