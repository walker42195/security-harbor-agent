// Package syslog vidarebefordrar brandväggens systemloggar (inklusive
// SH-ACCEPT/SH-DENY-raderna från nftables, se pkg/adapter/nftables) till en
// central syslog-mottagare, utöver den lokala journald-lagringen som alltid
// finns kvar oavsett den här inställningen (Fas 8).
package syslog

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

type Adapter struct {
	// dir är katalogen där rsyslog-vidarebefordringsfilen skrivs, normalt
	// /etc/rsyslog.d. De flesta distros rsyslog.conf inkluderar redan
	// `/etc/rsyslog.d/*.conf` från paketet, så att skriva hit kräver ingen
	// ändring av systemets bas-rsyslog.conf.
	dir string
}

const defaultDir = "/etc/rsyslog.d"
const confFilename = "60-security-harbor.conf"

func NewAdapter(dir string) *Adapter {
	if dir == "" {
		dir = defaultDir
	}
	return &Adapter{dir: dir}
}

// GenerateConfig renderar rsyslog-vidarebefordringsregeln. "@host:port" är
// UDP, "@@host:port" är TCP — se rsyslog.conf(5).
func GenerateConfig(cfg *config.Config) (string, error) {
	if cfg.Syslog == nil || !cfg.Syslog.Enabled {
		return "", nil
	}
	s := cfg.Syslog
	if s.Host == "" {
		return "", fmt.Errorf("syslog: host saknas")
	}
	port := s.Port
	if port == 0 {
		port = 514
	}
	prefix := "@"
	if s.Protocol == "tcp" {
		prefix = "@@"
	}
	return fmt.Sprintf(
		"# Genererad av Security Harbor — vidarebefordra samtliga loggar\n"+
			"# (inklusive nftables SH-ACCEPT/SH-DENY-raderna) till en central mottagare.\n"+
			"*.* %s%s:%d\n",
		prefix, s.Host, port,
	), nil
}

// ApplyConfig skriver/tar bort rsyslog.d-filen och laddar om rsyslog.service
// därefter. Precis som DNS-/WireGuard-/OpenVPN-adaptrarna anropas
// `systemctl reload-or-restart` direkt (D-Bus-anropet exekveras av systemd/
// PID1 med systemds egna rättigheter — det kräver ingen egen
// privilegiehöjning i agentprocessen, bara polkit-auktorisation, se
// systemd/10-security-harbor-rsyslog-reload.rules).
func (a *Adapter) ApplyConfig(ctx context.Context, cfg *config.Config, dryRun bool) error {
	path := filepath.Join(a.dir, confFilename)

	conf, err := GenerateConfig(cfg)
	if err != nil {
		return err
	}

	if dryRun {
		return nil
	}

	if conf == "" {
		// Avstängt (eller inte konfigurerat): ta bort en ev. tidigare
		// vidarebefordringsregel och ladda om, så gammal config inte blir
		// kvar aktiv.
		if _, statErr := os.Stat(path); statErr == nil {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("misslyckades ta bort %s: %w", path, err)
			}
		} else {
			return nil
		}
	} else {
		if err := os.MkdirAll(a.dir, 0755); err != nil {
			return fmt.Errorf("misslyckades skapa katalog %s: %w", a.dir, err)
		}
		if err := os.WriteFile(path, []byte(conf), 0644); err != nil {
			return fmt.Errorf("misslyckades skriva %s: %w", confFilename, err)
		}
	}

	if out, err := exec.CommandContext(ctx, "systemctl", "reload-or-restart", "rsyslog.service").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl reload-or-restart rsyslog.service misslyckades: %w - output: %s", err, string(out))
	}
	return nil
}
