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

	// Samma resonemang som suricata-adapterns checkWritable: /etc/rsyslog.d
	// ägs av root, agenten kör som security-harbor, och systemd-enhetens
	// ReadWritePaths tar bara bort systemds egen spärr — inte de vanliga
	// fil-rättigheterna. Utan den här dry-run-kontrollen upptäcktes
	// problemet först mitt i ett skarpt apply, efter att nftables redan
	// ändrats.
	if conf != "" {
		// rsyslog är en VALFRI komponent: den finns inte i Arch officiella
		// paketrepon (bara i AUR), och installern hoppar därför över den i
		// stället för att fälla hela installationen (2026-08-30). Utan den
		// här kontrollen upptäcktes det först vid `systemctl
		// reload-or-restart rsyslog.service` längst ner, med ett
		// felmeddelande som inte sa något om vad som faktiskt saknades.
		if err := checkRsyslogInstalled(); err != nil {
			return err
		}
		if err := checkDirWritable(a.dir); err != nil {
			return err
		}
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

// checkRsyslogInstalled verifierar att rsyslog över huvud taget finns på
// maskinen. All LOKAL loggning sköts av journald oavsett — rsyslog behövs
// bara för att vidarebefordra loggarna till en central mottagare.
func checkRsyslogInstalled() error {
	if _, err := exec.LookPath("rsyslogd"); err != nil {
		return fmt.Errorf("syslog-vidarebefordran kan inte aktiveras: rsyslog är inte installerat på den här maskinen. " +
			"Lokal loggning i journald påverkas inte. Installera rsyslog (Debian/Ubuntu: apt install rsyslog, " +
			"Arch: finns bara i AUR, t.ex. yay -S rsyslog) och kör om installern")
	}
	return nil
}

// checkDirWritable verifierar att agenten faktiskt får skapa filer i
// katalogen, med ett felmeddelande som säger vad man ska göra åt det.
func checkDirWritable(dir string) error {
	probe := filepath.Join(dir, ".security-harbor-write-test")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("syslog-vidarebefordran kan inte aktiveras: agenten saknar skrivrätt i %s. Kör på brandväggen: sudo chgrp security-harbor %s && sudo chmod g+ws %s", dir, dir, dir)
		}
		return fmt.Errorf("syslog-vidarebefordran kan inte aktiveras: %s går inte att skriva i: %w", dir, err)
	}
	_ = f.Close()
	_ = os.Remove(probe)
	return nil
}

// fwlogFilename ligger LÅGT (05-) så regeln körs FÖRE distributionens default-
// regler (50-default.conf) som annars skriver kärnloggen till /var/log/syslog
// och /var/log/kern.log.
const fwlogFilename = "05-security-harbor-fwlog.conf"

const fwlogConf = `# Genererad av Security Harbor — rör inte.
# Brandväggens nftables-loggrader (SH-ACCEPT-*/SH-DENY-*) finns redan i journald
# (SystemMaxUse=512M, se journald-security-harbor.conf) och läses därifrån av
# GUI:ts loggvy. Att rsyslog DESSUTOM skriver dem till /var/log/syslog +
# /var/log/kern.log är dubbellagrat, och under en flod/pentest växer de
# traditionella filerna OBEGRÄNSAT (uppmätt 20 GB -> full disk 2026-09-06,
# journald klarade sig tack vare sitt tak). Kasta dem därför här, före
# default-reglerna. journald behåller dem (capped), så GUI:ts loggvy påverkas
# inte. OBS: de vidarebefordras då inte heller till en central syslog-mottagare.
if ($msg contains "SH-ACCEPT-") or ($msg contains "SH-DENY-") then { stop }
`

// EnsureFwlogSuppression skriver rsyslog-regeln som hindrar brandväggens
// nft-loggar från att fylla /var/log lokalt. Idempotent; no-op om rsyslog inte
// är installerat. Anropas vid agentens uppstart.
func (a *Adapter) EnsureFwlogSuppression(ctx context.Context) error {
	if err := checkRsyslogInstalled(); err != nil {
		return nil // rsyslog saknas (t.ex. Arch utan AUR) — inget att göra.
	}
	if err := checkDirWritable(a.dir); err != nil {
		return nil
	}
	path := filepath.Join(a.dir, fwlogFilename)
	if existing, err := os.ReadFile(path); err == nil && string(existing) == fwlogConf {
		return nil // redan på plats och oförändrad.
	}
	if err := os.WriteFile(path, []byte(fwlogConf), 0644); err != nil {
		return fmt.Errorf("misslyckades skriva %s: %w", fwlogFilename, err)
	}
	if out, err := exec.CommandContext(ctx, "systemctl", "reload-or-restart", "rsyslog.service").CombinedOutput(); err != nil {
		return fmt.Errorf("kunde inte ladda om rsyslog: %v (%s)", err, out)
	}
	return nil
}
