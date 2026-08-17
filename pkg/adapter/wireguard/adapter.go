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

// GenerateConfig renderar innehållet i wg0.conf. serverPrivateKey hämtas av
// anroparen (Store.EnsureWireGuardServerKeys) — adaptern håller aldrig
// nycklar i minnet längre än nödvändigt för att rendera filen.
func GenerateConfig(cfg *config.Config, serverPrivateKey string) (string, error) {
	if cfg.WireGuard == nil || !cfg.WireGuard.Enabled {
		return "", nil
	}
	wg := cfg.WireGuard

	var b bytes.Buffer
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", serverPrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", wg.Address)
	fmt.Fprintf(&b, "ListenPort = %d\n", wg.ListenPort)

	for _, peer := range wg.Peers {
		if !peer.Enabled || peer.PublicKey == "" {
			continue
		}
		fmt.Fprintf(&b, "\n# %s\n", peer.Name)
		fmt.Fprintf(&b, "[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", peer.PublicKey)
		fmt.Fprintf(&b, "AllowedIPs = %s\n", peer.AllowedIPs)
	}

	return b.String(), nil
}

// ApplyConfig skriver wg0.conf och (om aktiverat) laddar om gränssnittet med
// wg-quick. Om WireGuard är inaktiverat i cfg tas gränssnittet ner istället.
func (a *Adapter) ApplyConfig(ctx context.Context, cfg *config.Config, serverPrivateKey string, dryRun bool) error {
	if cfg.WireGuard == nil || !cfg.WireGuard.Enabled {
		if dryRun {
			return nil
		}
		// Säkerställ att gränssnittet inte är kvar uppe om det stängts av.
		_ = exec.CommandContext(ctx, "wg-quick", "down", InterfaceName).Run()
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

	// wg-quick down/up är enklast och tillräckligt robust för detta projekt;
	// `wg syncconf` (utan tunneln nere) vore snyggare men kräver striplogik
	// vi inte behöver ännu i Fas 3.
	_ = exec.CommandContext(ctx, "wg-quick", "down", InterfaceName).Run()
	out, err := exec.CommandContext(ctx, "wg-quick", "up", InterfaceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg-quick up misslyckades: %w - output: %s", err, string(out))
	}

	return nil
}
