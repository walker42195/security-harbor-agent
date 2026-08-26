// security-harbor-network-runner — privilegierad tillämpare av
// nätverkskonfiguration.
//
// Körs som root av security-harbor-network-apply.service (oneshot), som i sin
// tur triggas av den oprivilegierade agenten via `systemctl start --wait`.
// Läser en DEKLARATIV förfrågan (gränssnittskonfiguration — aldrig kommandon)
// från /run/security-harbor/network-apply.json, skriver ner konfigurationen i
// det lager som äger nätverket (netplan/NetworkManager/systemd-networkd) och
// tillämpar den på de kort som behöver det.
//
// Samma isolering som update-/rollback-runnern: privilegiehöjningen begränsas
// till den här minimala engångskörningen, och den härdade daemon-processen
// (ProtectSystem=strict, NoNewPrivileges) rör aldrig /etc/netplan eller
// networkctl själv.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/network"
)

func main() {
	// Något kortare än enhetens TimeoutStartSec=90s, så vi hinner skriva ett
	// begripligt resultat till agenten innan systemd dödar oss.
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()

	result := run(ctx)

	data, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sh-network] kunde inte serialisera resultat: %v\n", err)
		os.Exit(1)
	}
	// 0644: agenten kör som ett annat (oprivilegierat) konto och måste kunna
	// läsa svaret.
	if err := os.WriteFile(network.ApplyResultPath, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "[sh-network] kunde inte skriva resultat: %v\n", err)
		os.Exit(1)
	}

	// Förfrågan är förbrukad. Lämnas den kvar skulle en senare, misslyckad
	// start kunna tillämpa en gammal konfiguration om.
	_ = os.Remove(network.ApplyRequestPath)

	if result.Error != "" {
		fmt.Fprintf(os.Stderr, "[sh-network] %s\n", result.Error)
		// Avsluta med 0 ändå: felet är REDAN rapporterat i resultatfilen, och
		// agenten läser det därifrån. En nollskild kod hade bara gjort att
		// `systemctl start --wait` returnerade ett generiskt fel och dolde
		// det begripliga meddelandet.
	}
	fmt.Printf("[sh-network] backend=%s ändrad=%v\n", result.Backend, result.Changed)
}

func run(ctx context.Context) network.ApplyResult {
	data, err := os.ReadFile(network.ApplyRequestPath)
	if err != nil {
		return network.ApplyResult{Error: fmt.Sprintf("kunde inte läsa förfrågan: %v", err)}
	}
	var req network.ApplyRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return network.ApplyResult{Error: fmt.Sprintf("ogiltig förfrågan: %v", err)}
	}
	if len(req.Interfaces) == 0 && len(req.Renew) == 0 {
		return network.ApplyResult{Error: "förfrågan innehåller varken gränssnitt eller förnyelse"}
	}
	return network.RunApplyRequest(ctx, req)
}
