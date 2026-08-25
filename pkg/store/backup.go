// Backup/återställning av hela persistenslagret (Fas 10). En backup är en
// fristående, lösenfras-krypterad blob — oberoende av den (idag
// hårdkodade) master-nyckeln agenten körs med, så en backup går att
// återställa på ett annat system/en annan binärversion utan att
// master-nyckeln behöver matcha. De krypterade *.enc-filerna dekrypteras
// därför till klartext innan de läggs i arkivet, och krypteras om under
// DEN KÖRANDE instansens master-nyckel vid återställning.
package store

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// backupFiles listar exakt vilka filer i baseDir som ingår i en backup.
// dns_blocklist_*.txt (stora, regenererbara cache-filer) och audit.log
// (historik, inte tillstånd) är MEDVETET exkluderade — se paket-kommentaren
// i backup_test.go för resonemanget.
var backupFiles = []string{
	"running.json",
	"candidate.json",
	"users.enc",
	"wireguard_server.key.enc",
	"management_tls.key.enc",
	"openvpn_ca.key.enc",
	"openvpn_server.key.enc",
}

// minBackupPassphrase är minsta längd på lösenfrasen till en backup.
const minBackupPassphrase = 12

// maxRestoreFileBytes är taket per fil vid återställning. Skyddar mot en
// "gzip-bomb": arkivet packas upp i minnet, och utan tak kan en liten
// backup-fil expandera till godtyckligt mycket RAM.
const maxRestoreFileBytes = 16 << 20 // 16 MiB per fil, med god marginal

// isBackupFileName avgör om ett filnamn ur ett tar-arkiv är en av de filer
// en backup faktiskt får innehålla. Jämförelsen är exakt — inga sökvägar,
// inga separatorer, inget "..".
func isBackupFileName(name string) bool {
	for _, f := range backupFiles {
		if name == f {
			return true
		}
	}
	return false
}

// encryptedBackupFile avgör om en fil i backupFiles är krypterad på disk
// (allt utom *.json) och därför ska dekrypteras innan den läggs i arkivet
// / krypteras om efter att den packats upp.
func encryptedBackupFile(name string) bool {
	return filepath.Ext(name) == ".enc"
}

const (
	backupMagic   = "SHBK"
	backupVersion = 1
	scryptN       = 1 << 15 // ~32 MiB, rimligt för en interaktiv admin-åtgärd
	scryptR       = 8
	scryptP       = 1
	saltSize      = 16
)

func deriveBackupKey(passphrase string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, 32)
}

// Backup bygger en tar.gz av backupFiles (de krypterade filerna dekrypterade
// till klartext först) och AES-256-GCM-krypterar hela arkivet under en
// nyckel härledd ur passphrase via scrypt. Saknade filer (t.ex. OpenVPN
// aldrig konfigurerat, så *_ca.key.enc finns inte) hoppas tyst över — en
// backup ska spegla vad som FAKTISKT finns, inte kräva att allt är
// konfigurerat.
func (s *Store) Backup(passphrase string) ([]byte, error) {
	// Backupen innehåller ALLA nycklar och certifikat i klartext inuti det
	// krypterade arkivet — lösenfrasen är det enda som skyddar dem, och
	// filen hamnar typiskt utanför brandväggen (urklipp, molnlagring).
	// scrypt gör offline-knäckning dyrt, men inte mot en fyra teckens fras
	// (kodgranskning 2026-08-25).
	if len(passphrase) < minBackupPassphrase {
		return nil, fmt.Errorf("lösenfrasen måste vara minst %d tecken — den är det enda som skyddar nycklarna i backupen", minBackupPassphrase)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var tarBuf bytes.Buffer
	gz := gzip.NewWriter(&tarBuf)
	tw := tar.NewWriter(gz)

	for _, name := range backupFiles {
		data, err := os.ReadFile(filepath.Join(s.baseDir, name))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("kunde inte läsa %s: %w", name, err)
		}
		if encryptedBackupFile(name) {
			plain, decErr := s.crypto.Decrypt(data)
			if decErr != nil {
				return nil, fmt.Errorf("kunde inte dekryptera %s för backup: %w", name, decErr)
			}
			data = plain
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(data)), Mode: 0600}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key, err := deriveBackupKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, tarBuf.Bytes(), nil)

	out := make([]byte, 0, len(backupMagic)+1+len(salt)+len(nonce)+len(ciphertext))
	out = append(out, []byte(backupMagic)...)
	out = append(out, backupVersion)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// Restore packar upp en backup skapad av Backup och skriver om filerna i
// baseDir — de tidigare krypterade filerna krypteras om under DEN HÄR
// instansens master-nyckel (s.crypto), inte backupens ursprungliga, så en
// backup går att flytta till ett system med en annan master-nyckel. Skriver
// atomärt (.tmp + rename) precis som saveConfigLocked.
func (s *Store) Restore(data []byte, passphrase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(data) < len(backupMagic)+1+saltSize {
		return fmt.Errorf("ogiltig eller korrupt backup-fil")
	}
	if string(data[:len(backupMagic)]) != backupMagic {
		return fmt.Errorf("ogiltig backup-fil (fel filformat)")
	}
	offset := len(backupMagic)
	version := data[offset]
	offset++
	if version != backupVersion {
		return fmt.Errorf("okänd backup-version %d", version)
	}
	salt := data[offset : offset+saltSize]
	offset += saltSize

	key, err := deriveBackupKey(passphrase, salt)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < offset+nonceSize {
		return fmt.Errorf("ogiltig eller korrupt backup-fil")
	}
	nonce := data[offset : offset+nonceSize]
	offset += nonceSize
	ciphertext := data[offset:]

	tarGz, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("fel lösenfras eller korrupt backup-fil")
	}

	gz, err := gzip.NewReader(bytes.NewReader(tarGz))
	if err != nil {
		return fmt.Errorf("korrupt backup-arkiv: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	type restoredFile struct {
		name string
		data []byte
	}
	var files []restoredFile
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("korrupt backup-arkiv: %w", err)
		}
		// Filnamnet i arkivet är ANGRIPARKONTROLLERAT — en backup-fil är
		// bara en blob som klistras in i GUI:t, och den som skapade den
		// väljer själv lösenfrasen. Utan den här kontrollen användes
		// hdr.Name direkt i filepath.Join(baseDir, ...) nedan, vilket
		// släppte igenom "../../etc/rsyslog.d/x.conf" och gav skrivning
		// utanför datakatalogen — inom agentens ReadWritePaths finns bl.a.
		// /etc/rsyslog.d, där en omprog-konfiguration ger kodexekvering som
		// root (upptäckt vid kodgranskning 2026-08-25, klassisk "Zip-Slip").
		//
		// Backupen innehåller per definition bara filerna i backupFiles, så
		// allowlistan är den snävaste möjliga kontrollen: allt annat avvisas
		// hellre än saneras.
		if !isBackupFileName(hdr.Name) {
			return fmt.Errorf("backup-arkivet innehåller en oväntad fil (%q) — avbryter återställningen", hdr.Name)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return fmt.Errorf("backup-arkivet innehåller en post som inte är en vanlig fil (%q)", hdr.Name)
		}
		content, err := io.ReadAll(io.LimitReader(tr, maxRestoreFileBytes))
		if err != nil {
			return fmt.Errorf("korrupt backup-arkiv: %w", err)
		}
		if encryptedBackupFile(hdr.Name) {
			enc, encErr := s.crypto.Encrypt(content)
			if encErr != nil {
				return fmt.Errorf("kunde inte kryptera %s vid återställning: %w", hdr.Name, encErr)
			}
			content = enc
		}
		files = append(files, restoredFile{name: hdr.Name, data: content})
	}

	for _, f := range files {
		path := filepath.Join(s.baseDir, f.name)
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, f.data, 0600); err != nil {
			return fmt.Errorf("kunde inte skriva %s: %w", f.name, err)
		}
		if err := os.Rename(tmp, path); err != nil {
			return fmt.Errorf("kunde inte skriva %s: %w", f.name, err)
		}
	}
	return nil
}

// FactoryReset tar bort running.json, candidate.json, alla *.enc-filer och
// alla dns_blocklist_*.txt-cachefiler ur baseDir — audit.log lämnas kvar
// (revisionshistoriken är poängen med en logg, den ska överleva en reset).
// Efter detta beter sig nästa uppstart precis som en helt ny installation
// (loadOrInit/UserStore seedar om defaults) — ingen särskild
// återställningskod behövs utöver att ta bort filerna.
func (s *Store) FactoryReset() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		return fmt.Errorf("kunde inte läsa %s: %w", s.baseDir, err)
	}

	remove := func(name string) error {
		err := os.Remove(filepath.Join(s.baseDir, name))
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("kunde inte ta bort %s: %w", name, err)
		}
		return nil
	}

	for _, name := range backupFiles {
		if err := remove(name); err != nil {
			return err
		}
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "dns_blocklist_") && strings.HasSuffix(name, ".txt") {
			if err := remove(name); err != nil {
				return err
			}
		}
	}
	return nil
}
