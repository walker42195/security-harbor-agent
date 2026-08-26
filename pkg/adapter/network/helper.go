package network

// Privilegierad tillämpning via hjälptjänst.
//
// Att skriva nätverkskonfigurationen kräver root: netplan generate skriver i
// root-ägda /run/systemd/network, och `networkctl reload/reconfigure`,
// `netplan generate` och nmcli nekas alla av polkit för det oprivilegierade
// tjänstekontot ("Access denied ... requires interactive authentication").
// Agenten kör med ProtectSystem=strict och NoNewPrivileges och ska inte ha
// den behörigheten.
//
// Därför samma mönster som repot redan använder för självuppdatering,
// rollback, nmap och tcpdump: agenten skriver en förfrågan i sin
// RuntimeDirectory och startar en minimal root-oneshot
// (security-harbor-network-apply.service) som gör jobbet.
//
// Förfrågan är DEKLARATIV — den innehåller gränssnittskonfigurationen, aldrig
// kommandon att köra. Det är avgörande för att privilegiehöjningen ska vara
// meningsfull: kunde agenten skicka argv till root vore root-oneshoten bara
// ett sätt för en komprometterad agent att köra godtyckliga kommandon. Nu kan
// den på sin höjd be om en nätverkskonfiguration, vilket är precis vad den
// redan är betrodd att göra.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

const (
	ApplyRequestPath = "/run/security-harbor/network-apply.json"
	ApplyResultPath  = "/run/security-harbor/network-apply-result.json"
	ApplyUnit        = "security-harbor-network-apply.service"
)

// ApplyRequest är kontraktet mellan agenten och root-hjälparen.
type ApplyRequest struct {
	// Interfaces är HELA gränssnittskonfigurationen. Persistenslagren är
	// deklarativa och behöver hela bilden för att kunna städa bort det som
	// inte längre finns.
	Interfaces []config.Interface `json:"interfaces"`
	// Reconfigure är de kort som ska tillämpas om. Bara de som faktiskt
	// behöver det — en ändring på ett gränssnitt ska aldrig bryta länken på
	// de andra.
	Reconfigure []string `json:"reconfigure,omitempty"`
	// Renew är kort som ska begära en ny DHCP-lease ("Förnya IP" i GUI:t).
	Renew []string `json:"renew,omitempty"`
}

// ApplyResult är hjälparens svar.
type ApplyResult struct {
	Backend string `json:"backend"`
	Changed bool   `json:"changed"`
	Error   string `json:"error,omitempty"`
}

// applyHelperMu serialiserar anrop till den delade request-/resultatfilen.
// Samma icke-templatade unit används för alla anrop, så två samtidiga
// appliceringar hade annars kunnat kapplöpa om filerna och få varandras svar
// (skarpt bekräftat för nmap-hjälparen vid säkerhetsgranskningen 2026-08-19).
var applyHelperMu sync.Mutex

// ApplyPersistent ber root-hjälparen skriva ner konfigurationen på OS-nivå
// och tillämpa den på de angivna korten.
func ApplyPersistent(ctx context.Context, req ApplyRequest) (ApplyResult, error) {
	applyHelperMu.Lock()
	defer applyHelperMu.Unlock()

	// Rensa ett ev. gammalt resultat FÖRST, så ett tyst misslyckande i
	// hjälptjänsten inte råkar returnera en tidigare körnings svar.
	_ = os.Remove(ApplyResultPath)

	data, err := json.Marshal(req)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := os.WriteFile(ApplyRequestPath, data, 0o600); err != nil {
		return ApplyResult{}, fmt.Errorf("kunde inte skriva request-fil: %w", err)
	}

	if out, err := exec.CommandContext(ctx, "systemctl", "start", "--wait", ApplyUnit).CombinedOutput(); err != nil {
		return ApplyResult{}, fmt.Errorf("kunde inte starta %s: %w — %s", ApplyUnit, err, strings.TrimSpace(string(out)))
	}

	resultData, err := os.ReadFile(ApplyResultPath)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("hjälptjänsten skrev inget resultat: %w", err)
	}
	var result ApplyResult
	if err := json.Unmarshal(resultData, &result); err != nil {
		return ApplyResult{}, fmt.Errorf("ogiltigt resultat från hjälptjänsten: %w", err)
	}
	if result.Error != "" {
		return result, fmt.Errorf("%s", result.Error)
	}
	return result, nil
}

// RunApplyRequest utför en förfrågan. Körs av root-hjälparen
// (cmd/security-harbor-network-runner), aldrig i agentprocessen.
func RunApplyRequest(ctx context.Context, req ApplyRequest) ApplyResult {
	backend := DetectPersistBackend()
	if backend == nil {
		return ApplyResult{Error: "hittade varken netplan, NetworkManager eller systemd-networkd"}
	}

	result := ApplyResult{Backend: backend.Name()}
	// En ren "förnya IP"-förfrågan skickar inga gränssnitt — då ska den
	// sparade konfigurationen inte röras, bara leasen förnyas.
	if len(req.Interfaces) > 0 {
		changed, err := backend.Write(ctx, req.Interfaces)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Changed = changed
	}

	byDevice := map[string]config.Interface{}
	for _, iface := range req.Interfaces {
		byDevice[deviceNameFor(iface)] = iface
	}
	for _, device := range req.Reconfigure {
		if err := backend.Reconfigure(ctx, device); err != nil {
			result.Error = err.Error()
			return result
		}
		// Vänta tills adressen faktiskt sitter på kortet innan vi säger att
		// appliceringen är klar — anroparen startar om adressbundna tjänster
		// direkt efteråt.
		if iface, ok := byDevice[device]; ok {
			if err := waitForAddress(ctx, iface, device); err != nil {
				result.Error = err.Error()
				return result
			}
		}
	}
	for _, device := range req.Renew {
		if err := backend.Renew(ctx, device); err != nil {
			result.Error = err.Error()
			return result
		}
	}
	return result
}

// Hur länge vi väntar på att en adress faktiskt ska dyka upp på kortet efter
// en omkonfigurering. Statiska adresser sätts i praktiken direkt; en
// DHCP-förhandling tar längre tid och kan aldrig lyckas alls (ingen server på
// den VLAN:en), därför olika budget och olika stränghet nedan.
const (
	staticAddressTimeout = 10 * time.Second
	dhcpAddressTimeout   = 10 * time.Second
)

// waitForAddress blockerar tills kortet FAKTISKT har den konfigurerade
// adressen.
//
// `networkctl reconfigure` (och nmcli) är ASYNKRONA: de begär en
// omkonfigurering och returnerar direkt — man-sidan lovar ingenting om när
// den är klar, och systemd har ett separat systemd-networkd-wait-online just
// därför. Den imperativa `ip addr add`-vägen som backendarna ersatte var
// synkron, så adressen fanns när anropet returnerade.
//
// Utan den här väntan uppstår ett kapplöpningsfel: applyInterfaces returnerar,
// applyBackends startar omedelbart om tjänster som binder till LAN-adresserna,
// och unbound (som medvetet binder specifika LAN-IP:n, inte 0.0.0.0) dör med
// "can't bind socket: Cannot assign requested address". Skarpt 2026-08-26 när
// LAN-adressen byttes från 10.0.0.9 till 10.0.0.1 — både appliceringen och den
// automatiska återställningen föll på samma sak, och lådan blev
// "halvapplicerad".
func waitForAddress(ctx context.Context, iface config.Interface, device string) error {
	if !iface.Enabled || device == "" {
		return nil
	}

	static := iface.AddressType == "static" && iface.IPv4 != ""
	timeout := dhcpAddressTimeout
	if static {
		timeout = staticAddressTimeout
	}

	deadline := time.Now().Add(timeout)
	for {
		permanent, dynamic := deviceAddresses(device)
		if static {
			for _, addr := range permanent {
				if addr == iface.IPv4 {
					return nil
				}
			}
		} else if len(dynamic) > 0 {
			return nil
		}

		if time.Now().After(deadline) {
			if static {
				return fmt.Errorf("%s fick aldrig adressen %s (väntade %s) — "+
					"tjänster som binder till den kommer inte att starta", device, iface.IPv4, timeout)
			}
			// Ingen DHCP-lease är inget fel i sig: det kan helt enkelt inte
			// finnas någon DHCP-server på det nätet. Tjänster binder inte till
			// en adress vi inte känner, så appliceringen kan fortsätta.
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
