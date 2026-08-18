package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
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

// TestGenerateSelfSignedServerCert skyddar mot att SAN-fälten (IP/DNS)
// saknas — utan dem ignorerar moderna webbläsare/Go:s TLS-klient
// CommonName helt (sedan Go 1.15) och avvisar certifikatet oavsett tillit,
// vilket skulle göra Management-API:ets HTTPS obrukbart.
func TestGenerateSelfSignedServerCert(t *testing.T) {
	ip := net.ParseIP("10.0.0.163")
	kp, err := GenerateSelfSignedServerCert("security-harbor", []net.IP{ip, net.ParseIP("127.0.0.1")}, []string{"localhost"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedServerCert misslyckades: %v", err)
	}

	block, _ := pem.Decode([]byte(kp.CertPEM))
	if block == nil {
		t.Fatalf("certifikatet är inte giltig PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("kunde inte tolka certifikatet: %v", err)
	}

	if cert.IsCA {
		t.Errorf("förväntade ett fristående leaf-certifikat (IsCA=false), fick IsCA=true")
	}

	foundIP := false
	for _, gotIP := range cert.IPAddresses {
		if gotIP.Equal(ip) {
			foundIP = true
		}
	}
	if !foundIP {
		t.Errorf("förväntade %v i certifikatets IPAddresses (SAN), fick %v", ip, cert.IPAddresses)
	}

	foundDNS := false
	for _, name := range cert.DNSNames {
		if name == "localhost" {
			foundDNS = true
		}
	}
	if !foundDNS {
		t.Errorf("förväntade \"localhost\" i certifikatets DNSNames (SAN), fick %v", cert.DNSNames)
	}

	// Verifiera att certifikatet faktiskt kan användas av Go:s TLS-stack
	// (tls.X509KeyPair), exakt som pkg/api/server.go gör vid Start().
	if _, err := tls.X509KeyPair([]byte(kp.CertPEM), []byte(kp.KeyPEM)); err != nil {
		t.Errorf("tls.X509KeyPair misslyckades tolka det genererade nyckelparet: %v", err)
	}
}
