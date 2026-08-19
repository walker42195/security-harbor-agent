// Master-nyckeln för kryptering at-rest (AES-256-GCM, se crypto.go).
// Genereras SLUMPMÄSSIGT per installation och sparas lokalt i baseDir —
// ersätter en tidigare hårdkodad, delad nyckel i källkoden (samma sträng
// i alla installationer, synlig för vem som helst med koden). Filen är
// INTE i sig krypterad — det finns inget att kryptera den under, den ÄR
// nyckeln — skyddet kommer från filsystemsrättigheter (0600, ägd av
// security-harbor-kontot) och systemd-sandboxningen
// (ProtectSystem=strict m.m., se systemd/security-harbor-agent.service).
// Se SECURITY.md för en ärlig diskussion av den kvarvarande begränsningen
// jämfört med en riktig HSM/TPM/Vault-lösning.
package store

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

const masterKeyFilename = "master.key"

func loadOrCreateMasterKey(baseDir string) ([]byte, error) {
	path := filepath.Join(baseDir, masterKeyFilename)

	if data, err := os.ReadFile(path); err == nil {
		if len(data) != 32 {
			return nil, fmt.Errorf("%s har fel längd (%d bytes, förväntade 32) — korrupt fil", masterKeyFilename, len(data))
		}
		return data, nil
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("misslyckades generera master-nyckel: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, key, 0600); err != nil {
		return nil, fmt.Errorf("misslyckades skriva %s: %w", masterKeyFilename, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, fmt.Errorf("misslyckades skriva %s: %w", masterKeyFilename, err)
	}
	return key, nil
}
