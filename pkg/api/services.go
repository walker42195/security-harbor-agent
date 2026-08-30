package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// managedService beskriver EN systemd-tjänst som agenten själv startar/
// stoppar/startar om via de vanliga adaptrarna (pkg/adapter/*). Listan här
// är en ALLOWLIST — restart-endpointen accepterar ALDRIG ett godtyckligt
// enhetsnamn från klienten, bara ett ID ur den här listan, för att inte
// öppna en generell "kör systemctl mot vad som helst"-primitiv.
//
// Tillkom 2026-08-24 efter en live-incident: en administratör som stängde
// av WAN-gränssnittet fick Suricata att fastna i ett trasigt läge (se
// pkg/adapter/suricata/adapter.go och pkg/engine/engine.go, applyInterfaces-
// fixen i rollback) — administratören hade då ingen egen väg att bara
// starta om den enskilda tjänsten för att se/åtgärda det, utan var
// beroende av att felsöka på serverns kommandorad.
type managedService struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Unit        string `json:"unit"`
}

var managedServices = []managedService{
	{ID: "agent", Name: "Security Harbor Agent", Description: "Själva administrations-API:t/GUI:t — en omstart kopplar ner din session.", Unit: "security-harbor-agent.service"},
	{ID: "dns", Name: "DNS-resolver (Unbound)", Description: "Lokal DNS-resolver och domänblockering.", Unit: "unbound.service"},
	{ID: "dhcp", Name: "DHCP-server (Kea)", Description: "Tilldelar IP-adresser till klienter på LAN/VLAN.", Unit: "kea-dhcp4-server.service"},
	{ID: "ids", Name: "IDS (Suricata)", Description: "Passiv intrångsdetektering.", Unit: "suricata.service"},
	{ID: "sni", Name: "SNI-routning (HAProxy)", Description: "Namnbaserad TLS-passthrough-routning.", Unit: "haproxy.service"},
	{ID: "openvpn", Name: "OpenVPN", Description: "OpenVPN-server för fjärranslutna klienter.", Unit: "openvpn@sh-server.service"},
	{ID: "syslog", Name: "Syslog-vidarebefordran (rsyslog)", Description: "Vidarebefordrar brandväggens loggar till en central syslog-mottagare.", Unit: "rsyslog.service"},
}

func findManagedService(id string) (managedService, bool) {
	for _, s := range managedServices {
		if s.ID == id {
			return s, true
		}
	}
	return managedService{}, false
}

type serviceStatus struct {
	managedService
	Active string `json:"active"` // ActiveState: active, inactive, failed, activating, ...
	Sub    string `json:"sub"`    // SubState: running, dead, exited, ...
	// Configured säger om FUNKTIONEN är påslagen i brandväggens
	// konfiguration — till skillnad från Active, som bara speglar systemds
	// syn på enheten.
	//
	// Rapporterat 2026-08-25: Tjänstepanelen visade "rsyslog igång" trots att
	// syslog-vidarebefordran var AVSTÄNGD i inställningarna. rsyslog är
	// systemets ordinarie logghanterare på Debian/Ubuntu och körs alltid,
	// oavsett om vi vidarebefordrar något. Utan det här fältet gick det inte
	// att skilja "tjänsten lever" från "funktionen är aktiverad".
	Configured bool `json:"configured"`
}

// serviceConfigured avgör om funktionen bakom en tjänst är påslagen i
// konfigurationen. Agenten själv är alltid "konfigurerad".
func serviceConfigured(id string, cfg *config.Config) bool {
	if id == "agent" {
		return true
	}
	if cfg == nil {
		return false
	}
	switch id {
	case "dns":
		return cfg.DNS != nil && cfg.DNS.Enabled
	case "ids":
		return cfg.IDS != nil && cfg.IDS.Enabled
	case "syslog":
		return cfg.Syslog != nil && cfg.Syslog.Enabled
	case "openvpn":
		return cfg.OpenVPN != nil && cfg.OpenVPN.Enabled
	case "dhcp":
		for _, iface := range cfg.Interfaces {
			if iface.Enabled && iface.DHCP != nil && iface.DHCP.Enabled {
				return true
			}
		}
		return false
	case "sni":
		for _, r := range cfg.SNIRoutes {
			if r.Enabled {
				return true
			}
		}
		return false
	}
	return false
}

// queryUnitState läser ActiveState/SubState för EN systemd-enhet via
// `systemctl show` — fungerar även för enheter som aldrig startats (då
// LoadState=not-found, ActiveState=inactive), så listan alltid går att visa
// oavsett om t.ex. OpenVPN eller Suricata ens är konfigurerat.
func queryUnitState(ctx context.Context, unit string) (active, sub string) {
	out, err := exec.CommandContext(ctx, "systemctl", "show", unit, "--no-page", "--property=ActiveState", "--property=SubState").Output()
	if err != nil {
		return "unknown", "unknown"
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		k, v, found := strings.Cut(line, "=")
		if found {
			values[k] = v
		}
	}
	active = values["ActiveState"]
	sub = values["SubState"]
	if active == "" {
		active = "unknown"
	}
	if sub == "" {
		sub = "unknown"
	}
	return active, sub
}

// handleServicesStatus listar samtliga tjänster agenten hanterar och deras
// aktuella systemd-status — läsbar för både viewer och admin (samma som
// övriga statusvyer), bara omstarten (nedan) kräver admin.
func (s *Server) handleServicesStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	cfg := s.engine.GetRunningConfig()
	out := make([]serviceStatus, 0, len(managedServices))
	for _, svc := range managedServices {
		active, sub := queryUnitState(ctx, svc.Unit)
		out = append(out, serviceStatus{
			managedService: svc,
			Active:         active,
			Sub:            sub,
			Configured:     serviceConfigured(svc.ID, cfg),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// handleServiceRestart startar om EN tjänst ur managedServices (matchad på
// ID, ALDRIG ett fritt enhetsnamn från klienten). Kräver admin-roll (satt i
// route-registreringen i Start()).
func (s *Server) handleServiceRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	svc, ok := findManagedService(req.ID)
	if !ok {
		http.Error(w, "Okänd tjänst", http.StatusBadRequest)
		return
	}
	cfg := s.engine.GetRunningConfig()

	// Agentens EGEN omstart får ett eget, kort svar innan processen dör —
	// annars hinner klienten aldrig se ett svar alls (anslutningen bryts
	// när processen avslutas). systemd startar om agenten enligt
	// Restart=always i security-harbor-agent.service.
	if svc.ID == "agent" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "restarting"})
		go func() {
			time.Sleep(300 * time.Millisecond)
			_ = exec.Command("systemctl", "restart", svc.Unit).Start()
		}()
		return
	}

	// Vägra starta en tjänst vars FUNKTION är avstängd i konfigurationen.
	//
	// Agenten äger start/stopp av de här tjänsterna — den stoppar dem när
	// funktionen slås av. En omstart härifrån startar dem igen, och då säger
	// konfigurationen en sak medan maskinen gör en annan, utan att något
	// senare rättar till det förrän nästa applicering.
	//
	// Rapporterat 2026-08-30 på en skarp gateway: IDS var avstängt i
	// konfigurationen men suricata.service kördes, eftersom någon tryckt
	// "starta om" på tjänsten. Panelen visade den då som aktiv, vilket såg ut
	// som att IDS var påslaget.
	if !serviceConfigured(svc.ID, cfg) {
		http.Error(w,
			"Tjänsten "+svc.Name+" kan inte startas om eftersom funktionen är avstängd i konfigurationen. "+
				"Slå på den först, så startar agenten tjänsten själv.",
			http.StatusConflict)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "restart", svc.Unit).CombinedOutput()
	if err != nil {
		http.Error(w, "systemctl restart "+svc.Unit+" misslyckades: "+err.Error()+" - "+string(out), http.StatusInternalServerError)
		return
	}
	active, sub := queryUnitState(context.Background(), svc.Unit)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(serviceStatus{
		managedService: svc,
		Active:         active,
		Sub:            sub,
		Configured:     serviceConfigured(svc.ID, s.engine.GetRunningConfig()),
	})
}
