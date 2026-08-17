package wireguard

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

const InterfaceName = "wg0"

type Adapter struct {
	// configPath är en informativ kopia av den applicerade wg-syntax-
	// konfigurationen (för felsökning/audit) — den läses inte av `wg`
	// eller `ip`, som styrs direkt via subcommands nedan.
	configPath string
}

func NewAdapter(configPath string) *Adapter {
	if configPath == "" {
		configPath = "/etc/wireguard/" + InterfaceName + ".conf"
	}
	return &Adapter{configPath: configPath}
}

// GenerateKeypair skapar ett nytt WireGuard-nyckelpar via `wg genkey`/`wg pubkey`.
// Används både för serverns egen identitet (Store.EnsureWireGuardServerKeys)
// och för att generera engångsnycklar åt en ny klient/peer i GUI:t.
func GenerateKeypair() (privateKey, publicKey string, err error) {
	privOut, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", "", fmt.Errorf("wg genkey misslyckades: %w", err)
	}
	privateKey = strings.TrimSpace(string(privOut))

	pubCmd := exec.Command("wg", "pubkey")
	pubCmd.Stdin = strings.NewReader(privateKey)
	pubOut, err := pubCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("wg pubkey misslyckades: %w", err)
	}
	publicKey = strings.TrimSpace(string(pubOut))

	return privateKey, publicKey, nil
}

// GenerateConfig renderar en STRIKT wg-syntax-fil (bara det `wg setconf`
// förstår: [Interface] PrivateKey/ListenPort, [Peer] PublicKey/AllowedIPs).
// Address hör till wg-quick-varianten och sätts separat via `ip address`,
// se ApplyConfig — annars avvisar `wg setconf` filen.
func GenerateConfig(cfg *config.Config, serverPrivateKey string) (string, error) {
	if cfg.WireGuard == nil || !cfg.WireGuard.Enabled {
		return "", nil
	}
	wg := cfg.WireGuard

	var b bytes.Buffer
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", serverPrivateKey)
	fmt.Fprintf(&b, "ListenPort = %d\n", wg.ListenPort)

	for _, peer := range wg.Peers {
		if !peer.Enabled || peer.PublicKey == "" {
			continue
		}
		fmt.Fprintf(&b, "\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", peer.PublicKey)
		fmt.Fprintf(&b, "AllowedIPs = %s\n", peer.AllowedIPs)
	}

	return b.String(), nil
}

// ApplyConfig sätter upp/river ner wg0 direkt via `ip` och `wg` istället för
// `wg-quick`. Detta är MEDVETET, inte en stilfråga: `wg-quick` är ett
// bash-skript som hårdkodar `[[ $UID == 0 ]] || exec sudo ...` och därmed
// aldrig fungerar under agentens icke-root systemd-sandbox (Steg 0.3,
// CAP_NET_ADMIN/CAP_NET_RAW via AmbientCapabilities) — upptäckt vid skarp
// testning mot brandväggsservern 2026-08-17. `ip link add type wireguard`
// och `wg`/`wg setconf` kräver bara CAP_NET_ADMIN, som processen redan har,
// och är samma mönster nftables-adaptern redan använder (prata direkt med
// kärnan, inte via en root-krävande wrapper).
func (a *Adapter) ApplyConfig(ctx context.Context, cfg *config.Config, serverPrivateKey string, dryRun bool) error {
	if cfg.WireGuard == nil || !cfg.WireGuard.Enabled {
		if dryRun {
			return nil
		}
		_ = exec.CommandContext(ctx, "ip", "link", "delete", "dev", InterfaceName).Run()
		return nil
	}

	data, err := GenerateConfig(cfg, serverPrivateKey)
	if err != nil {
		return fmt.Errorf("misslyckades generera WireGuard-konfiguration: %w", err)
	}

	if dryRun {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(a.configPath), 0700); err != nil {
		return fmt.Errorf("misslyckades skapa katalog för %s: %w", a.configPath, err)
	}
	if err := os.WriteFile(a.configPath, []byte(data), 0600); err != nil {
		return fmt.Errorf("misslyckades skriva %s: %w", a.configPath, err)
	}

	// Riv ner ett ev. tidigare gränssnitt för idempotent omapplicering
	// (ignorerar fel om det inte fanns sedan tidigare).
	_ = exec.CommandContext(ctx, "ip", "link", "delete", "dev", InterfaceName).Run()

	if out, err := exec.CommandContext(ctx, "ip", "link", "add", "dev", InterfaceName, "type", "wireguard").CombinedOutput(); err != nil {
		return fmt.Errorf("ip link add misslyckades: %w - output: %s", err, string(out))
	}
	if out, err := exec.CommandContext(ctx, "wg", "setconf", InterfaceName, a.configPath).CombinedOutput(); err != nil {
		return fmt.Errorf("wg setconf misslyckades: %w - output: %s", err, string(out))
	}
	if out, err := exec.CommandContext(ctx, "ip", "address", "add", cfg.WireGuard.Address, "dev", InterfaceName).CombinedOutput(); err != nil {
		return fmt.Errorf("ip address add misslyckades: %w - output: %s", err, string(out))
	}
	if out, err := exec.CommandContext(ctx, "ip", "link", "set", "up", "dev", InterfaceName).CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set up misslyckades: %w - output: %s", err, string(out))
	}

	return nil
}
