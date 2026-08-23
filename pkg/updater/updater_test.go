package updater

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// privKeyForPublicKeyB64 är den privata motparten till PublicKeyB64, bara för
// tester (den skarpa privata nyckeln finns aldrig i repot). Genererad
// tillsammans med PublicKeyB64.
const testPrivKeyB64 = "+C8SwTYcaBoVaG6qPmLcHCOHf82rWt/iQ9BjuYZ3bOn762a9PMFrNXH/uDYxxn6ynHDDWKYql1Qz+JgoVUftKg=="

func sign(t *testing.T, data []byte) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(testPrivKeyB64)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		t.Fatalf("ogiltig testnyckel")
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(raw), data))
}

func TestVerifyEd25519AcceptsValidSignature(t *testing.T) {
	data := []byte("security-harbor release tarball innehåll")
	if err := VerifyEd25519(data, sign(t, data)); err != nil {
		t.Fatalf("giltig signatur underkändes: %v", err)
	}
}

func TestVerifyEd25519RejectsTamperedData(t *testing.T) {
	data := []byte("original bunt")
	sig := sign(t, data)
	if err := VerifyEd25519([]byte("manipulerad bunt"), sig); err == nil {
		t.Fatal("förväntade fel för manipulerad data, fick nil")
	}
}

func TestVerifyEd25519RejectsGarbageSignature(t *testing.T) {
	if err := VerifyEd25519([]byte("data"), "inte-base64!!"); err == nil {
		t.Fatal("förväntade fel för trasig signatur, fick nil")
	}
	if err := VerifyEd25519([]byte("data"), base64.StdEncoding.EncodeToString([]byte("för kort"))); err == nil {
		t.Fatal("förväntade fel för fel signaturlängd, fick nil")
	}
}

func TestIsNewer(t *testing.T) {
	cases := []struct {
		available, current string
		want               bool
	}{
		{"0.16.0", "0.15.0", true},
		{"0.15.1", "0.15.0", true},
		{"1.0.0", "0.16.0", true},
		{"0.15.0", "0.15.0", false},
		{"0.15.0", "0.16.0", false},
		{"0.15.0", "0.15.1", false},
		{"v0.16.0", "0.15.0", true}, // v-prefix hanteras
	}
	for _, c := range cases {
		if got := IsNewer(c.available, c.current); got != c.want {
			t.Errorf("IsNewer(%q,%q)=%v, vill ha %v", c.available, c.current, got, c.want)
		}
	}
}
