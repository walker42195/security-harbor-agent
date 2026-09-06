package store

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func (s *Store) notificationsPath() string {
	return filepath.Join(s.baseDir, "notifications.enc")
}

// LoadNotificationConfig läser den krypterade notifieringskonfigurationen.
// Returnerar en tom (avstängd) config om filen inte finns.
func (s *Store) LoadNotificationConfig() (*config.NotificationConfig, error) {
	data, err := os.ReadFile(s.notificationsPath())
	if os.IsNotExist(err) {
		return &config.NotificationConfig{SMTPPort: 587, Security: "starttls", NotifyServiceFailure: true, NotifyAutoBlock: true}, nil
	}
	if err != nil {
		return nil, err
	}
	plain, err := s.crypto.Decrypt(data)
	if err != nil {
		return nil, err
	}
	var cfg config.NotificationConfig
	if err := json.Unmarshal(plain, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SaveNotificationConfig sparar konfigurationen krypterat (0600).
func (s *Store) SaveNotificationConfig(cfg *config.NotificationConfig) error {
	plain, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	cipherBytes, err := s.crypto.Encrypt(plain)
	if err != nil {
		return err
	}
	return os.WriteFile(s.notificationsPath(), cipherBytes, 0600)
}
