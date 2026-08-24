// Package suricata konfigurerar och läser larm från Suricata i passivt
// IDS-läge (af-packet-sniffing, INTE inline/NFQUEUE) — Fas 9. Suricata
// paketeras och sköter sin egen fullständiga suricata.yaml/regeluppsättning
// (installeras separat via apt + suricata-update, se
// systemd/security-harbor-suricata-update.service/.timer) — agenten rör
// ENDAST vilket gränssnitt som sniffas (af-packet-sektionen) och
// start/stopp av tjänsten, samma minimala-touch-princip som
// pkg/adapter/dns använder mot Unbound.
package suricata

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

type Adapter struct {
	yamlPath string
	evePath  string
}

const (
	defaultYamlPath = "/etc/suricata/suricata.yaml"
	defaultEvePath  = "/var/log/suricata/eve.json"
	unit            = "suricata.service"
)

func NewAdapter(yamlPath, evePath string) *Adapter {
	if yamlPath == "" {
		yamlPath = defaultYamlPath
	}
	if evePath == "" {
		evePath = defaultEvePath
	}
	return &Adapter{yamlPath: yamlPath, evePath: evePath}
}

// afPacketInterfaceRe matchar ENDAST det första listobjektets interface-rad
// direkt under den top-level "af-packet:"-nyckeln (paketets suricata.yaml
// har fler "- interface:"-rader längre ner i samma sektion för ev.
// ytterligare kort, men vi rör bara det första/primära kortet — precis
// tillräckligt för en enkel LAN/WAN-brandvägg med ett sniffat gränssnitt).
var afPacketInterfaceRe = regexp.MustCompile(`(?m)^(af-packet:\n\s*- interface: )\S+`)

// SetInterface skriver om af-packet-sektionens FÖRSTA interface-rad i en
// redan installerad suricata.yaml. Resten av filen (regler, output-format,
// trådning m.m.) rörs inte — det är paketets/suricata-updates ansvar.
func SetInterface(yamlContent []byte, iface string) ([]byte, error) {
	if !afPacketInterfaceRe.Match(yamlContent) {
		return nil, fmt.Errorf("hittade inte af-packet-sektionen i suricata.yaml")
	}
	return afPacketInterfaceRe.ReplaceAll(yamlContent, []byte("${1}"+iface)), nil
}

// ApplyConfig aktiverar/stänger av Suricata och pekar om af-packet-sniffing
// mot det konfigurerade gränssnittet. Precis som DNS-/WireGuard-/OpenVPN-
// adaptrarna anropas `systemctl` direkt (D-Bus-anropet exekveras av
// systemd/PID1 med systemds egna rättigheter, ingen egen
// privilegiehöjning krävs i agentprocessen) — se
// systemd/10-security-harbor-suricata.rules för polkit-auktorisationen.
func (a *Adapter) ApplyConfig(ctx context.Context, cfg *config.Config, dryRun bool) error {
	// Om det gränssnitt IDS ska sniffa är AVSTÄNGT (Interface.Enabled=false,
	// t.ex. en administratör som stängde av WAN som en nödåtgärd), behandlas
	// det som "ingen IDS" i stället för att försöka starta om Suricata mot
	// ett nedstängt kort — af-packet-bindning mot ett kort utan LOWER_UP
	// misslyckas då med ett obegripligt "exit status 1", vilket dessutom
	// (upptäckt 2026-08-24) kunde få HELA Safe Apply att fastna: både
	// själva applyn OCH efterföljande rollback-försök körde samma
	// omstart och misslyckades likadant, tills gränssnittet manuellt togs
	// upp igen. En administratör som stänger av ett gränssnitt förväntar
	// sig att DET lyckas, inte att IDS-konfigurationen ska blockera det.
	ifaceDisabled := false
	if cfg.IDS != nil {
		for _, iface := range cfg.Interfaces {
			if iface.Device == cfg.IDS.Interface && !iface.Enabled {
				ifaceDisabled = true
				break
			}
		}
	}
	if cfg.IDS == nil || !cfg.IDS.Enabled || cfg.IDS.Interface == "" || ifaceDisabled {
		if dryRun {
			return nil
		}
		_ = exec.CommandContext(ctx, "systemctl", "stop", unit).Run()
		return nil
	}

	// Dry-run kontrollerar att vi FAKTISKT kan skriva konfigurationsfilen
	// innan något appliceras skarpt. Utan det upptäcktes ett rättighets-
	// problem först mitt i apply-flödet, efter att nftables redan ändrats
	// (se ApplyCandidate i pkg/engine). Felmeddelandet pekar ut åtgärden,
	// eftersom orsaken annars är svårgissad: systemd-enhetens
	// ReadWritePaths tillåter katalogen, men filen ägs av root och agenten
	// kör som security-harbor.
	if err := a.checkWritable(); err != nil {
		return err
	}
	if dryRun {
		return nil
	}

	orig, err := os.ReadFile(a.yamlPath)
	if err != nil {
		return fmt.Errorf("kunde inte läsa %s: %w", a.yamlPath, err)
	}
	updated, err := SetInterface(orig, cfg.IDS.Interface)
	if err != nil {
		return err
	}
	if !bytes.Equal(orig, updated) {
		if err := os.WriteFile(a.yamlPath, updated, 0644); err != nil {
			return fmt.Errorf("misslyckades skriva %s: %w", a.yamlPath, err)
		}
	}

	if out, err := exec.CommandContext(ctx, "systemctl", "restart", unit).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart %s misslyckades: %w - output: %s", unit, err, string(out))
	}
	return nil
}

// checkWritable verifierar att suricata.yaml finns och är skrivbar för
// agentens användare, med ett felmeddelande som säger vad man ska göra.
func (a *Adapter) checkWritable() error {
	f, err := os.OpenFile(a.yamlPath, os.O_WRONLY, 0)
	if err == nil {
		return f.Close()
	}
	if os.IsNotExist(err) {
		return fmt.Errorf("IDS kan inte aktiveras: %s saknas — är paketet suricata installerat? (apt install suricata suricata-update)", a.yamlPath)
	}
	if os.IsPermission(err) {
		return fmt.Errorf("IDS kan inte aktiveras: agenten saknar skrivrätt på %s. Kör på brandväggen: sudo chgrp security-harbor %s && sudo chmod g+w %s", a.yamlPath, a.yamlPath, a.yamlPath)
	}
	return fmt.Errorf("IDS kan inte aktiveras: %s går inte att öppna för skrivning: %w", a.yamlPath, err)
}

// eveAlert är de fälten vi bryr oss om i en eve.json-rad av typen "alert".
// Suricatas eve.json har MÅNGA fler fält (flow, http, tls, ...) som vi
// medvetet ignorerar här — vi vill bara visa larmet, inte hela
// protokollmetadatan.
type eveAlert struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	Alert     struct {
		Signature string `json:"signature"`
		Category  string `json:"category"`
		Severity  int    `json:"severity"`
	} `json:"alert"`
}

// ReadRecentAlerts läser de sista maxLines raderna av eve.json (INTE hela
// filen — den kan bli mycket stor) och returnerar de som är larm
// ("event_type":"alert"), äldst-till-nyast liksom filen själv.
func ReadRecentAlerts(evePath string, maxLines int) ([]config.SecurityEvent, error) {
	f, err := os.Open(evePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []config.SecurityEvent{}, nil
		}
		return nil, err
	}
	defer f.Close()

	lines := make([]string, 0, maxLines)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > maxLines {
			lines = lines[1:]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	events := make([]config.SecurityEvent, 0, len(lines))
	for _, line := range lines {
		var a eveAlert
		if err := json.Unmarshal([]byte(line), &a); err != nil || a.EventType != "alert" {
			continue
		}
		events = append(events, config.SecurityEvent{
			Timestamp: a.Timestamp,
			Severity:  a.Alert.Severity,
			Signature: a.Alert.Signature,
			Category:  a.Alert.Category,
			SrcIP:     a.SrcIP,
			SrcPort:   a.SrcPort,
			DstIP:     a.DestIP,
			DstPort:   a.DestPort,
			Protocol:  a.Proto,
		})
	}
	return events, nil
}

// EvePath returnerar sökvägen till eve.json (används av Engine för
// auto-block-bevakningen, som behöver samma fil men sin egen
// "sedan senast"-vattenmärkning).
func (a *Adapter) EvePath() string { return a.evePath }
