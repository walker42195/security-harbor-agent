package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"time"
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

	out := make([]serviceStatus, 0, len(managedServices))
	for _, svc := range managedServices {
		active, sub := queryUnitState(ctx, svc.Unit)
		out = append(out, serviceStatus{managedService: svc, Active: active, Sub: sub})
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

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "restart", svc.Unit).CombinedOutput()
	if err != nil {
		http.Error(w, "systemctl restart "+svc.Unit+" misslyckades: "+err.Error()+" - "+string(out), http.StatusInternalServerError)
		return
	}
	active, sub := queryUnitState(context.Background(), svc.Unit)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(serviceStatus{managedService: svc, Active: active, Sub: sub})
}
