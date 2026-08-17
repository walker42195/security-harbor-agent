package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/wireguard"
	"github.com/walker42195/security-harbor-agent/pkg/config"
)

type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	User      string    `json:"user"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
}

type Store struct {
	mu           sync.RWMutex
	baseDir      string
	runningCfg   *config.Config
	candidateCfg *config.Config
	crypto       *CryptoHandler
}

func NewStore(baseDir string, masterKey []byte) (*Store, error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("misslyckades skapa store-katalog %s: %w", baseDir, err)
	}

	crypto, err := NewCryptoHandler(masterKey)
	if err != nil {
		return nil, fmt.Errorf("misslyckades skapa crypto-handler: %w", err)
	}

	s := &Store{
		baseDir: baseDir,
		crypto:  crypto,
	}

	// Ladda eller skapa standardkonfiguration
	if err := s.loadOrInit(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Store) loadOrInit() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	runningPath := filepath.Join(s.baseDir, "running.json")
	if _, err := os.Stat(runningPath); os.IsNotExist(err) {
		// Skapa default initial konfiguration
		defaultCfg := &config.Config{
			Version:   1,
			Revision:  1,
			UpdatedAt: time.Now(),
			Interfaces: []config.Interface{
				{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
				{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.163/24"},
			},
			Zones: []config.Zone{
				{Name: "WAN", Description: "Utsida / Internet"},
				{Name: "LAN", Description: "Internt nätverk"},
				{Name: "SERVERS", Description: "Serverzon"},
				{Name: "IOT", Description: "IoT-enheter"},
				{Name: "VPN", Description: "VPN-klienter"},
			},
			Policies: []config.Policy{
				{
					ID:          "sys-ssh-lan",
					Name:        "Tillåt SSH till brandväggen (LAN)",
					Enabled:     true,
					Priority:    1,
					SourceZone:  "LAN",
					DestZone:    "SELF",
					Service:     "22",
					Action:      config.ActionAccept,
					Local:       true,
					Critical:    true,
					Description: "Tillåter SSH-inloggning till brandväggen själv från det interna nätverket. Om du inaktiverar denna behöver du en annan väg in (t.ex. tangentbord och skärm, eller seriekonsol) för att kunna administrera brandväggen.",
				},
			},
			Settings: config.Settings{
				HostName:           "security-harbor",
				APIPort:            8443,
				RollbackTimeoutSec: 30,
			},
		}
		s.runningCfg = defaultCfg
		s.candidateCfg = defaultCfg
		return s.saveConfigLocked(runningPath, defaultCfg)
	}

	data, err := os.ReadFile(runningPath)
	if err != nil {
		return fmt.Errorf("misslyckades läsa %s: %w", runningPath, err)
	}

	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("misslyckades tolka running config: %w", err)
	}

	s.runningCfg = &cfg
	s.candidateCfg = &cfg
	return nil
}

func (s *Store) saveConfigLocked(path string, cfg *config.Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}

func (s *Store) GetRunningConfig() *config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.runningCfg
}

func (s *Store) GetCandidateConfig() *config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.candidateCfg
}

func (s *Store) SetCandidateConfig(cfg *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg.Revision = s.runningCfg.Revision + 1
	cfg.UpdatedAt = time.Now()

	s.candidateCfg = cfg
	candidatePath := filepath.Join(s.baseDir, "candidate.json")
	return s.saveConfigLocked(candidatePath, cfg)
}

func (s *Store) CommitCandidate() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.runningCfg = s.candidateCfg
	runningPath := filepath.Join(s.baseDir, "running.json")
	return s.saveConfigLocked(runningPath, s.runningCfg)
}

// wgServerKeys är den okrypterade formen som encrypteras som en blob innan
// den skrivs till disk (se EnsureWireGuardServerKeys).
type wgServerKeys struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// EnsureWireGuardServerKeys returnerar brandväggens egna WireGuard-nyckelpar,
// och genererar+krypterar (AES-256-GCM via Store.crypto, Fas 0 steg 0.5) ett
// nytt par vid första anropet. Den privata nyckeln lämnar aldrig disk okrypterad
// och exponeras aldrig via Management-API:t (endast publika nyckeln görs det).
func (s *Store) EnsureWireGuardServerKeys() (privateKey, publicKey string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keyPath := filepath.Join(s.baseDir, "wireguard_server.key.enc")

	if data, readErr := os.ReadFile(keyPath); readErr == nil {
		plain, decErr := s.crypto.Decrypt(data)
		if decErr != nil {
			return "", "", fmt.Errorf("misslyckades dekryptera WireGuard-serverns nyckelpar: %w", decErr)
		}
		var keys wgServerKeys
		if jsonErr := json.Unmarshal(plain, &keys); jsonErr != nil {
			return "", "", fmt.Errorf("korrupt WireGuard-nyckelfil: %w", jsonErr)
		}
		return keys.PrivateKey, keys.PublicKey, nil
	}

	priv, pub, genErr := wireguard.GenerateKeypair()
	if genErr != nil {
		return "", "", fmt.Errorf("misslyckades generera WireGuard-serverns nyckelpar: %w", genErr)
	}

	plain, jsonErr := json.Marshal(wgServerKeys{PrivateKey: priv, PublicKey: pub})
	if jsonErr != nil {
		return "", "", jsonErr
	}
	cipherBytes, encErr := s.crypto.Encrypt(plain)
	if encErr != nil {
		return "", "", fmt.Errorf("misslyckades kryptera WireGuard-serverns nyckelpar: %w", encErr)
	}
	if writeErr := os.WriteFile(keyPath, cipherBytes, 0600); writeErr != nil {
		return "", "", fmt.Errorf("misslyckades skriva %s: %w", keyPath, writeErr)
	}

	return priv, pub, nil
}

func (s *Store) LogAudit(user, action, details string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := AuditEntry{
		Timestamp: time.Now(),
		User:      user,
		Action:    action,
		Details:   details,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	auditPath := filepath.Join(s.baseDir, "audit.log")
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(data)
	return err
}
