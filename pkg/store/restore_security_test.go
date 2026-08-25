package store

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Bygger en GILTIG (korrekt krypterad/signerad) backup-fil vars tar-arkiv
// innehåller en post med en traversal-sökväg. Regression för den "Zip-Slip"
// som lät en preparerad backup skriva utanför datakatalogen — t.ex. till
// /etc/rsyslog.d, som ligger i agentens ReadWritePaths och där en
// omprog-konfiguration ger kodexekvering som root.
func craftBackupWithName(t *testing.T, passphrase, entryName string) []byte {
	t.Helper()

	var tarBuf bytes.Buffer
	gz := gzip.NewWriter(&tarBuf)
	tw := tar.NewWriter(gz)
	payload := []byte("$ModLoad omprog\n")
	if err := tw.WriteHeader(&tar.Header{
		Name: entryName, Mode: 0600, Size: int64(len(payload)), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		t.Fatal(err)
	}
	key, err := deriveBackupKey(passphrase, salt)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}
	ct := gcm.Seal(nil, nonce, tarBuf.Bytes(), nil)

	out := []byte(backupMagic)
	out = append(out, backupVersion)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out
}

func TestRestoreRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir, "")
	if err != nil {
		t.Fatal(err)
	}

	const pass = "en-tillrackligt-lang-fras"
	for _, name := range []string{
		"../../etc/rsyslog.d/evil.conf",
		"../outside.json",
		"/etc/rsyslog.d/evil.conf",
		"subdir/running.json",
		"okand-fil.json",
	} {
		backup := craftBackupWithName(t, pass, name)
		err := s.Restore(backup, pass)
		if err == nil {
			t.Fatalf("Restore accepterade en otillåten arkivpost: %q", name)
		}
		if !strings.Contains(err.Error(), "oväntad fil") {
			t.Fatalf("fel av oväntat slag för %q: %v", name, err)
		}
	}

	// Inget ska ha skrivits utanför datakatalogen.
	if _, err := os.Stat(filepath.Join(dir, "..", "outside.json")); err == nil {
		t.Fatal("en fil skrevs UTANFÖR datakatalogen")
	}
}

func TestBackupRequiresStrongPassphrase(t *testing.T) {
	s, err := NewStore(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Backup("kort"); err == nil {
		t.Fatal("Backup accepterade en för kort lösenfras")
	}
}
