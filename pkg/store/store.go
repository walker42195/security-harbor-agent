package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

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
