// Package pki implementerar en minimal certifikatutfärdare (CA) för
// OpenVPN-serverns och klienternas certifikat (Fas 4). Detta ersätter
// easy-rsa med Go:s inbyggda crypto/x509 — inga externa binärer eller
// skalskript krävs, och nycklar hanteras aldrig som klartext på disk
// (se Store.EnsureOpenVPNCA/EnsureOpenVPNServerCert, som krypterar allt
// med samma CryptoHandler som WireGuard-nycklarna, Fas 3).
package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

const keyBits = 2048

// KeyPair är ett PEM-kodat nyckelpar + certifikat.
type KeyPair struct {
	CertPEM string
	KeyPEM  string
	Serial  string
}

// GenerateCA skapar ett nytt, självsignerat CA-nyckelpar för brandväggens
// OpenVPN-installation. Giltighet 10 år.
func GenerateCA(commonName string) (*KeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, fmt.Errorf("misslyckades generera CA-nyckel: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Security Harbor"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("misslyckades signera CA-certifikat: %w", err)
	}

	return &KeyPair{
		CertPEM: encodeCert(der),
		KeyPEM:  encodeKey(key),
		Serial:  serial.String(),
	}, nil
}

// IssueCert signerar ett nytt server- eller klientcertifikat med den givna
// CA:n. serverAuth avgör om certifikatet får ExtKeyUsageServerAuth (krävs av
// OpenVPN:s "remote-cert-tls server"-kontroll på klientsidan).
func IssueCert(caCertPEM, caKeyPEM, commonName string, serverAuth bool) (*KeyPair, error) {
	caCert, caKey, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, err
	}

	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, fmt.Errorf("misslyckades generera nyckel för %q: %w", commonName, err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if serverAuth {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"Security Harbor"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  extKeyUsage,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("misslyckades signera certifikat för %q: %w", commonName, err)
	}

	return &KeyPair{
		CertPEM: encodeCert(der),
		KeyPEM:  encodeKey(key),
		Serial:  serial.String(),
	}, nil
}

// GenerateSelfSignedServerCert skapar ett fristående (icke CA-signerat)
// server-leaf-certifikat med SAN-fält (IP/DNS), avsett för Management-
// API:ets HTTPS-lyssnare (Fas 8+). En enda LAN-appliance behöver ingen
// egen CA att signera mot — ett självsignerat leaf-certifikat räcker och
// ger en kortare (1 länk) kedja, vilket GUI:ts trust-on-first-use-
// fingeravtrycksjämförelse tjänar på. Utan DNSNames/IPAddresses ignorerar
// moderna webbläsare/Go:s TLS-klient CommonName helt (sedan Go 1.15) och
// skulle avvisa certifikatet oavsett tillit.
func GenerateSelfSignedServerCert(commonName string, ips []net.IP, dnsNames []string) (*KeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, fmt.Errorf("misslyckades generera nyckel: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"Security Harbor"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
		DNSNames:     dnsNames,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("misslyckades självsignera servercertifikat: %w", err)
	}

	return &KeyPair{
		CertPEM: encodeCert(der),
		KeyPEM:  encodeKey(key),
		Serial:  serial.String(),
	}, nil
}

// GenerateCRL bygger en Certificate Revocation List som innehåller de
// givna serienumren (som strängar, bas-10 — samma format som KeyPair.Serial).
// OpenVPN-servern pekas på denna fil via `crl-verify` i server.conf.
func GenerateCRL(caCertPEM, caKeyPEM string, revokedSerials []string) (string, error) {
	caCert, caKey, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return "", err
	}

	var revoked []pkix.RevokedCertificate
	for _, s := range revokedSerials {
		n := new(big.Int)
		if _, ok := n.SetString(s, 10); !ok {
			continue
		}
		revoked = append(revoked, pkix.RevokedCertificate{
			SerialNumber:   n,
			RevocationTime: time.Now(),
		})
	}

	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:              big.NewInt(time.Now().Unix()),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().AddDate(1, 0, 0),
		RevokedCertificates: revoked,
	}, caCert, caKey)
	if err != nil {
		return "", fmt.Errorf("misslyckades generera CRL: %w", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})), nil
}

func parseCA(caCertPEM, caKeyPEM string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certBlock, _ := pem.Decode([]byte(caCertPEM))
	if certBlock == nil {
		return nil, nil, fmt.Errorf("ogiltigt CA-certifikat (PEM)")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("misslyckades tolka CA-certifikat: %w", err)
	}

	keyBlock, _ := pem.Decode([]byte(caKeyPEM))
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("ogiltig CA-nyckel (PEM)")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("misslyckades tolka CA-nyckel: %w", err)
	}

	return caCert, caKey, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("misslyckades generera serienummer: %w", err)
	}
	return serial, nil
}

func encodeCert(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func encodeKey(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}
