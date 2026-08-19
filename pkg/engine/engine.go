package engine

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/dhcp"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/dns"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/nftables"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/openvpn"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/suricata"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/syslog"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/wireguard"
	"github.com/walker42195/security-harbor-agent/pkg/config"
	"github.com/walker42195/security-harbor-agent/pkg/pki"
	"github.com/walker42195/security-harbor-agent/pkg/store"
	"github.com/walker42195/security-harbor-agent/pkg/threatfeed"
)

type State string

const (
	StateIdle        State = "idle"
	StateUnconfirmed State = "unconfirmed"
)

type Engine struct {
	mu             sync.Mutex
	store          *store.Store
	nftAdapter     *nftables.Adapter
	dhcpAdapter    *dhcp.Adapter
	wgAdapter      *wireguard.Adapter
	ovpnAdapter    *openvpn.Adapter
	dnsAdapter      *dns.Adapter
	syslogAdapter   *syslog.Adapter
	suricataAdapter *suricata.Adapter
	state           State
	confirmTimer    *time.Timer
	unconfirmedCfg  *config.Config

	// idsLastAlertTS håller den senaste larm-tidsstämpeln vi redan hanterat
	// för auto-block (Fas 9), så samma larm inte blockeras om och om igen.
	// Rensas vid omstart (samma lättviktiga i-minnet-approach som resten av
	// engine-tillståndet) — värsta fallet efter en omstart är att de senast
	// hanterade larmen bedöms på nytt, inte att något missas.
	idsLastAlertTS string
}

func NewEngine(st *store.Store, nftAdapter *nftables.Adapter, dhcpAdapter *dhcp.Adapter, wgAdapter *wireguard.Adapter, ovpnAdapter *openvpn.Adapter, dnsAdapter *dns.Adapter, syslogAdapter *syslog.Adapter, suricataAdapter *suricata.Adapter) *Engine {
	return &Engine{
		store:           st,
		nftAdapter:      nftAdapter,
		dhcpAdapter:     dhcpAdapter,
		wgAdapter:       wgAdapter,
		ovpnAdapter:     ovpnAdapter,
		dnsAdapter:      dnsAdapter,
		syslogAdapter:   syslogAdapter,
		suricataAdapter: suricataAdapter,
		state:           StateIdle,
	}
}

// applyBackends applicerar samtliga systembackends (nftables, Kea DHCP,
// WireGuard) för en given konfiguration. Delas mellan ApplyCandidate och
// rollback så att en rollback verkligen återställer DHCP/VPN, inte bara
// brandväggsreglerna.
func (e *Engine) applyBackends(ctx context.Context, cfg *config.Config, dryRun bool) error {
	if _, err := e.nftAdapter.ApplyConfig(ctx, cfg, dryRun); err != nil {
		return fmt.Errorf("nftables: %w", err)
	}

	// DHCP och Suricata är gateway-/router-specifika roller (DHCP-server
	// och IDS-sniffing hör inte hemma på en enkortsdator, Fas 13) — rör
	// aldrig kea-dhcp4-server/suricata i host-läge, oavsett vad running-
	// configen råkar innehålla (ett host-läges-install har dem inte ens
	// installerade, se install.sh).
	if !cfg.IsHostMode() {
		if err := e.dhcpAdapter.ApplyConfig(ctx, cfg, dryRun); err != nil {
			return fmt.Errorf("dhcp: %w", err)
		}
	}
	if cfg.WireGuard != nil && cfg.WireGuard.Enabled {
		privKey, _, err := e.store.EnsureWireGuardServerKeys()
		if err != nil {
			return fmt.Errorf("wireguard: kunde inte hämta serverns nyckelpar: %w", err)
		}
		if err := e.wgAdapter.ApplyConfig(ctx, cfg, privKey, dryRun); err != nil {
			return fmt.Errorf("wireguard: %w", err)
		}
	} else if err := e.wgAdapter.ApplyConfig(ctx, cfg, "", dryRun); err != nil {
		return fmt.Errorf("wireguard: %w", err)
	}

	if cfg.OpenVPN != nil && cfg.OpenVPN.Enabled {
		ca, err := e.store.EnsureOpenVPNCA()
		if err != nil {
			return fmt.Errorf("openvpn: kunde inte hämta CA: %w", err)
		}
		serverCert, err := e.store.EnsureOpenVPNServerCert()
		if err != nil {
			return fmt.Errorf("openvpn: kunde inte hämta servercertifikat: %w", err)
		}

		var revoked []string
		for _, c := range cfg.OpenVPN.Clients {
			if c.Revoked && c.CertSerial != "" {
				revoked = append(revoked, c.CertSerial)
			}
		}
		crl, err := pki.GenerateCRL(ca.CertPEM, ca.KeyPEM, revoked)
		if err != nil {
			return fmt.Errorf("openvpn: kunde inte generera CRL: %w", err)
		}

		if err := e.ovpnAdapter.ApplyConfig(ctx, cfg, ca.CertPEM, serverCert.CertPEM, serverCert.KeyPEM, crl, dryRun); err != nil {
			return fmt.Errorf("openvpn: %w", err)
		}
	} else if err := e.ovpnAdapter.ApplyConfig(ctx, cfg, "", "", "", "", dryRun); err != nil {
		return fmt.Errorf("openvpn: %w", err)
	}

	if cfg.DNS != nil && cfg.DNS.Enabled {
		domains, err := e.store.LoadAllEnabledDNSBlocklistDomains(cfg.DNS.Blocklists)
		if err != nil {
			return fmt.Errorf("dns: kunde inte läsa cachade blocklistor: %w", err)
		}
		if err := e.dnsAdapter.ApplyConfig(ctx, cfg, domains, e.loadDHCPLeases(cfg), dryRun); err != nil {
			return fmt.Errorf("dns: %w", err)
		}
	} else if err := e.dnsAdapter.ApplyConfig(ctx, cfg, nil, nil, dryRun); err != nil {
		return fmt.Errorf("dns: %w", err)
	}

	if err := e.syslogAdapter.ApplyConfig(ctx, cfg, dryRun); err != nil {
		return fmt.Errorf("syslog: %w", err)
	}

	if !cfg.IsHostMode() {
		if err := e.suricataAdapter.ApplyConfig(ctx, cfg, dryRun); err != nil {
			return fmt.Errorf("suricata: %w", err)
		}
	}

	return nil
}

// loadDHCPLeases läser Kea:s lease-databas för att registrera
// DHCP-tilldelade värdnamn i den lokala DNS-zonen (se DNSConfig.
// DHCPHostnameRegistration). Ett fel här (t.ex. filen finns inte än
// eftersom DHCP-servern precis startats) ska aldrig blockera hela
// Apply-flödet — loggas bara och behandlas som "inga leases ännu".
func (e *Engine) loadDHCPLeases(cfg *config.Config) []dhcp.Lease {
	if cfg.DNS == nil || !cfg.DNS.DHCPHostnameRegistration {
		return nil
	}
	leases, err := dhcp.ParseLeaseFile(e.dhcpAdapter.LeaseDatabasePath())
	if err != nil {
		log.Printf("[DNS] Kunde inte läsa DHCP-leases för DNS-registrering: %v", err)
		return nil
	}
	return leases
}

// ApplyRunningConfigAtBoot laddar den senast committade konfigurationen i
// samtliga backends vid agentstart (kallas från main.go innan API-servern
// startar). Går inte via Safe Apply/rollback-timern — det är bara att
// återskapa det tillstånd som redan var bekräftat innan omstarten.
func (e *Engine) ApplyRunningConfigAtBoot(ctx context.Context) error {
	return e.applyBackends(ctx, e.store.GetRunningConfig(), false)
}

func (e *Engine) GetRunningConfig() *config.Config {
	return e.store.GetRunningConfig()
}

func (e *Engine) GetCandidateConfig() *config.Config {
	return e.store.GetCandidateConfig()
}

func (e *Engine) UpdateCandidate(cfg *config.Config) error {
	return e.store.SetCandidateConfig(cfg)
}

// ValidateCandidate validerar en candidate-konfiguration utan att ändra systemet.
func (e *Engine) ValidateCandidate(ctx context.Context, cfg *config.Config) error {
	// 1. Kör dry-run validering av samtliga backends
	if err := e.applyBackends(ctx, cfg, true); err != nil {
		return fmt.Errorf("validering misslyckades: %w", err)
	}

	// 2. Validera IP-överlapp och logiska fel
	if len(cfg.Interfaces) == 0 {
		return fmt.Errorf("konfigurationen måste ha minst ett gränssnitt")
	}

	// 3. Validera att varje policys zon-val faktiskt matchar något
	// konfigurerat gränssnitt — annars hoppar nftables-adaptern (se
	// zoneMatchExpr, pkg/adapter/nftables) tyst över regeln (samma skydd
	// mot "matcha allt" som redan finns för tomma objekt-listor), vilket
	// utan denna kontroll bara syns som "regeln gör aldrig något",
	// obegripligt för en administratör som skrivit fel zonnamn.
	// DNAT-policyer undantas: de matchas av NAT.ExternalPort/InternalIP,
	// inte av SourceZone/DestZone (nftables-adaptern läser aldrig zon-
	// fälten för DNAT-regler) — att ändå kräva giltiga zoner där gav
	// falska valideringsfel för DNAT-regler skapade innan den här
	// kontrollen fanns (upptäckt skarpt 2026-08-19, samma dag kontrollen
	// lades till).
	for _, pol := range cfg.Policies {
		if !pol.Enabled || pol.Local || pol.Action == config.ActionDNAT {
			continue
		}
		if err := validatePolicyZone(cfg, pol.Name, "källzonen", pol.SourceZone); err != nil {
			return err
		}
		if err := validatePolicyZone(cfg, pol.Name, "målzonen", pol.DestZone); err != nil {
			return err
		}
	}

	return nil
}

// validatePolicyZone kontrollerar att varje kommaseparerad del av en
// policys SourceZone/DestZone antingen är "ANY"/tom, en av GUI:ts två
// syntetiska specialsträngar ("Any-External (WAN)"/"Any-Trusted (LAN)"),
// eller matchar minst ett AKTIVERAT gränssnitts Zone-fält — samma
// tolkning som zoneMatchExpr i pkg/adapter/nftables använder vid
// regelgenerering, bara för validering istället för rendering.
func validatePolicyZone(cfg *config.Config, policyName, label, zoneSpec string) error {
	trimmed := strings.TrimSpace(zoneSpec)
	if trimmed == "" || strings.EqualFold(trimmed, "ANY") {
		return nil
	}
	parts := strings.Split(trimmed, ",")
	// "ANY" NÅGONSTANS i en kommaseparerad lista (t.ex. "10.0.0.5, ANY" —
	// GUI:t lägger till ANY som standardval, en administratör som sedan
	// lägger till ett eget värde utan att ta bort ANY ska inte straffas
	// för det) betyder "ingen begränsning", precis som om HELA fältet
	// vore "ANY" — samma tolkning som zoneMatchExpr använder.
	for _, part := range parts {
		if strings.EqualFold(strings.TrimSpace(part), "ANY") {
			return nil
		}
	}
	for _, part := range parts {
		zoneName := strings.TrimSpace(part)
		if zoneName == "" || zoneName == "Any-External (WAN)" || zoneName == "Any-Trusted (LAN)" {
			continue
		}
		matched := false
		for _, iface := range cfg.Interfaces {
			if iface.Enabled && iface.Zone == zoneName {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("policy %q: %s %q matchar inget konfigurerat och aktiverat gränssnitt", policyName, label, zoneName)
		}
	}
	return nil
}

// ApplyCandidate applicerar candidate-konfigurationen och startar 30-sekunders rollback-timern.
func (e *Engine) ApplyCandidate(ctx context.Context, user string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	candidate := e.store.GetCandidateConfig()

	// Validera först
	if err := e.ValidateCandidate(ctx, candidate); err != nil {
		return fmt.Errorf("kan inte applicera ogiltig konfiguration: %w", err)
	}

	// Applicera skarpt mot Linux-kärnan (nftables, Kea DHCP, WireGuard)
	if err := e.applyBackends(ctx, candidate, false); err != nil {
		return fmt.Errorf("misslyckades applicera konfiguration: %w", err)
	}

	e.state = StateUnconfirmed
	e.unconfirmedCfg = candidate

	// Om det redan finns en timer igång, stoppa den
	if e.confirmTimer != nil {
		e.confirmTimer.Stop()
	}

	timeout := time.Duration(candidate.Settings.RollbackTimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Starta automatisk rollback timer ifall confirmation uteblir
	e.confirmTimer = time.AfterFunc(timeout, func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.state == StateUnconfirmed {
			fmt.Printf("[SAFE APPLY] ingen confirm mottagen inom %v -> utlöser AUTOMATISK ROLLBACK!\n", timeout)
			e.rollbackLocked(context.Background(), "SYSTEM_ROLLBACK_TIMEOUT")
		}
	})

	_ = e.store.LogAudit(user, "APPLY_CANDIDATE", fmt.Sprintf("Applicerade revision %d, väntar på bekräftelse (timeout %v)", candidate.Revision, timeout))
	return nil
}

// ConfirmConfig bekräftar den nya konfigurationen (avbryter rollback-timern och gör commit).
func (e *Engine) ConfirmConfig(ctx context.Context, user string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.state != StateUnconfirmed {
		return fmt.Errorf("ingen obekräftad konfiguration att bekräfta")
	}

	if e.confirmTimer != nil {
		e.confirmTimer.Stop()
		e.confirmTimer = nil
	}

	if err := e.store.CommitCandidate(); err != nil {
		return fmt.Errorf("misslyckades göra commit av konfiguration: %w", err)
	}

	e.state = StateIdle
	e.unconfirmedCfg = nil

	_ = e.store.LogAudit(user, "CONFIRM_CONFIG", "Konfiguration bekräftad och committad till running.json")
	return nil
}

// RollbackConfig återställer konfigurationen manuellt eller vid fel.
func (e *Engine) RollbackConfig(ctx context.Context, user string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.rollbackLocked(ctx, user)
}

func (e *Engine) rollbackLocked(ctx context.Context, user string) error {
	if e.confirmTimer != nil {
		e.confirmTimer.Stop()
		e.confirmTimer = nil
	}

	running := e.store.GetRunningConfig()
	if err := e.applyBackends(ctx, running, false); err != nil {
		fmt.Printf("[SAFE APPLY] fel vid återställning till running config: %v\n", err)
	}

	e.state = StateIdle
	_ = e.store.SetCandidateConfig(running)
	e.unconfirmedCfg = nil

	_ = e.store.LogAudit(user, "ROLLBACK_CONFIG", "Konfiguration återställd till senast kända säkra running config")
	return nil
}

// GetWireGuardServerPublicKey returnerar (och vid behov genererar) brandväggens
// egna WireGuard-publika nyckel. Den privata nyckeln lämnar aldrig denna funktion.
func (e *Engine) GetWireGuardServerPublicKey() (string, error) {
	_, pub, err := e.store.EnsureWireGuardServerKeys()
	return pub, err
}

// RefreshObjectSource hämtar om ett enskilt Object med automatisk källa
// (Fas 5 — hot-lista/GeoIP) via pkg/threatfeed, skriver om Values via
// Store.UpdateObjectValues och applicerar sedan om nftables (bara nftables,
// se ReapplyNftablesOnly) så att ändringen faktiskt slår igenom direkt.
// Ett fetch-fel sparas i objektets Source.LastError (synligt i GUI:t) men
// stoppar INTE resten av flödet eller ersätter en fungerande lista med tom
// data (pkg/threatfeed.Fetch vägrar redan returnera en tom lista som "OK").
func (e *Engine) RefreshObjectSource(ctx context.Context, objID string) error {
	// Sök candidate FÖRE running: ett nyss skapat hot-lista/GeoIP-objekt
	// finns bara i candidate tills det appliceras+bekräftas, men GUI:t
	// triggar ändå en direkt hämtning vid skapandet för att visa en
	// förhandsvisning av listans innehåll innan användaren väljer att
	// applicera — det påverkar inte brandväggen (ReapplyNftablesOnly
	// applicerar bara running, se nedan).
	var src *config.ObjectSource
	for _, cfg := range []*config.Config{e.store.GetCandidateConfig(), e.store.GetRunningConfig()} {
		if cfg == nil || src != nil {
			continue
		}
		for _, obj := range cfg.Objects {
			if obj.ID == objID {
				src = obj.Source
				break
			}
		}
	}
	if src == nil {
		return fmt.Errorf("objekt %q saknar en automatisk källa", objID)
	}

	values, fetchErr := threatfeed.Fetch(src.Kind, src.URL, src.CountryCode)
	if updErr := e.store.UpdateObjectValues(objID, values, fetchErr); updErr != nil {
		return updErr
	}
	if fetchErr != nil {
		return fetchErr
	}
	return e.ReapplyNftablesOnly(ctx)
}

// RefreshDueObjectSources går igenom alla Object med automatisk källa i
// running-konfigurationen och uppdaterar dem vars RefreshHours har passerat
// sedan LastUpdated (eller som aldrig hämtats än). Kallas periodiskt från en
// bakgrundsgoroutine i main.go. Returnerar antalet objekt som faktiskt
// uppdaterades (för loggning).
func (e *Engine) RefreshDueObjectSources(ctx context.Context) int {
	cfg := e.store.GetRunningConfig()
	if cfg == nil {
		return 0
	}

	refreshed := 0
	for _, obj := range cfg.Objects {
		if obj.Source == nil {
			continue
		}
		hours := obj.Source.RefreshHours
		if hours <= 0 {
			hours = 24
		}
		due := true
		if obj.Source.LastUpdated != "" {
			if t, err := time.Parse(time.RFC3339, obj.Source.LastUpdated); err == nil {
				due = time.Since(t) >= time.Duration(hours)*time.Hour
			}
		}
		if !due {
			continue
		}
		if err := e.RefreshObjectSource(ctx, obj.ID); err != nil {
			log.Printf("[THREATFEED] misslyckades uppdatera objekt %q (%s): %v", obj.Name, obj.Source.Kind, err)
			continue
		}
		refreshed++
	}
	return refreshed
}

// RefreshDNSBlocklist hämtar om EN DNS-domänblocklista (Fas 6, matchad på
// DNSBlocklistSource.ID — flera källor kan vara aktiva samtidigt) via
// pkg/threatfeed, cachar den till disk (Store.SaveDNSBlocklistDomains —
// ALDRIG i running/candidate.json, se den funktionens kommentar) och
// applicerar om Unbound (ReapplyDNSOnly, som slår ihop ALLA aktiverade
// källor) så att ändringen slår igenom direkt. Söker candidate FÖRE
// running av samma anledning som RefreshObjectSource (Fas 5) — en nyss
// tillagd blocklista ska kunna förhandsvisas innan den är applicerad.
// GetDNSBlocklistDomains returnerar den cachade domänlistan för EN
// blocklist-källa, så att GUI:t kan visa (inte bara räkna) vad som
// faktiskt är blockerat.
func (e *Engine) GetDNSBlocklistDomains(blocklistID string) ([]string, error) {
	return e.store.LoadDNSBlocklistDomains(blocklistID)
}

func (e *Engine) RefreshDNSBlocklist(ctx context.Context, blocklistID string) error {
	var src *config.DNSBlocklistSource
	for _, cfg := range []*config.Config{e.store.GetCandidateConfig(), e.store.GetRunningConfig()} {
		if cfg == nil || cfg.DNS == nil || src != nil {
			continue
		}
		for i := range cfg.DNS.Blocklists {
			if cfg.DNS.Blocklists[i].ID == blocklistID {
				src = &cfg.DNS.Blocklists[i]
				break
			}
		}
	}
	if src == nil {
		return fmt.Errorf("DNS-blocklista %q hittades inte", blocklistID)
	}

	domains, fetchErr := threatfeed.FetchDomains(src.Kind, src.URL)
	if fetchErr == nil {
		if err := e.store.SaveDNSBlocklistDomains(blocklistID, domains); err != nil {
			return err
		}
	}
	if err := e.store.UpdateDNSBlocklistStatus(blocklistID, len(domains), fetchErr); err != nil {
		return err
	}
	if fetchErr != nil {
		return fetchErr
	}
	return e.ReapplyDNSOnly(ctx)
}

// RefreshDueDNSBlocklists går igenom alla DNS-blocklist-källor i running-
// konfigurationen och uppdaterar dem vars RefreshHours har passerat sedan
// LastUpdated (eller som aldrig hämtats än). Kallas periodiskt från
// main.go, samma mönster som RefreshDueObjectSources (Fas 5). Returnerar
// antalet källor som faktiskt uppdaterades.
func (e *Engine) RefreshDueDNSBlocklists(ctx context.Context) int {
	cfg := e.store.GetRunningConfig()
	if cfg == nil || cfg.DNS == nil {
		return 0
	}

	refreshed := 0
	for _, src := range cfg.DNS.Blocklists {
		if !src.Enabled {
			continue
		}
		hours := src.RefreshHours
		if hours <= 0 {
			hours = 24
		}
		due := true
		if src.LastUpdated != "" {
			if t, err := time.Parse(time.RFC3339, src.LastUpdated); err == nil {
				due = time.Since(t) >= time.Duration(hours)*time.Hour
			}
		}
		if !due {
			continue
		}
		if err := e.RefreshDNSBlocklist(ctx, src.ID); err != nil {
			log.Printf("[THREATFEED] misslyckades uppdatera DNS-blocklistan %q (%s): %v", src.Name, src.Kind, err)
			continue
		}
		refreshed++
	}
	return refreshed
}

// ReapplyDNSOnly appliceras efter en bakgrundsuppdatering av en DNS-
// blocklista — medvetet begränsat till DNS-adaptern (inte hela
// applyBackends) av samma anledning som ReapplyNftablesOnly.
func (e *Engine) ReapplyDNSOnly(ctx context.Context) error {
	cfg := e.store.GetRunningConfig()
	if cfg.DNS == nil || !cfg.DNS.Enabled {
		return nil
	}
	domains, err := e.store.LoadAllEnabledDNSBlocklistDomains(cfg.DNS.Blocklists)
	if err != nil {
		return fmt.Errorf("dns: kunde inte läsa cachade blocklistor: %w", err)
	}
	if err := e.dnsAdapter.ApplyConfig(ctx, cfg, domains, e.loadDHCPLeases(cfg), false); err != nil {
		return fmt.Errorf("dns: %w", err)
	}
	return nil
}

// ReapplyNftablesOnly appliceras efter en bakgrundsuppdatering av en
// hot-lista/GeoIP-objekts Values (Fas 5, pkg/threatfeed) — medvetet begränsat
// till nftables (inte hela applyBackends) eftersom en periodisk listuppdatering
// annars skulle starta om DHCP/WireGuard/OpenVPN i onödan (t.ex. tappa
// aktiva VPN-tunnlar) för en ändring som bara påverkar IP-mängder.
func (e *Engine) ReapplyNftablesOnly(ctx context.Context) error {
	cfg := e.store.GetRunningConfig()
	if _, err := e.nftAdapter.ApplyConfig(ctx, cfg, false); err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	return nil
}

// GetSecurityEvents returnerar de senaste Suricata-larmen (Fas 9), läst
// direkt ur eve.json vid varje anrop — samma "ingen egen lagring, läs om
// vid behov"-princip som parseFirewallLog använder mot journald.
func (e *Engine) GetSecurityEvents(maxLines int) ([]config.SecurityEvent, error) {
	return suricata.ReadRecentAlerts(e.suricataAdapter.EvePath(), maxLines)
}

// ProcessIDSAutoBlock läser larm sedan senast (idsLastAlertTS) och lägger
// nya käll-IP:n med severity <= AutoBlockSeverity till det Object
// (AutoBlockObjectID) användaren själv pekat ut i IDS-inställningarna —
// samma "skriv direkt i running/candidate, applicera bara om nftables"-
// mönster som hotlist-uppdatering (Fas 5, se RefreshObjectSource). Skapar
// ALDRIG objektet eller en policy själv. Kallas periodiskt från en
// bakgrundsgoroutine i main.go.
func (e *Engine) ProcessIDSAutoBlock(ctx context.Context) error {
	cfg := e.store.GetRunningConfig()
	if cfg == nil || cfg.IDS == nil || !cfg.IDS.Enabled || !cfg.IDS.AutoBlock || cfg.IDS.AutoBlockObjectID == "" {
		return nil
	}

	events, err := e.GetSecurityEvents(2000)
	if err != nil {
		return fmt.Errorf("ids: kunde inte läsa larm: %w", err)
	}

	var obj *config.Object
	for i := range cfg.Objects {
		if cfg.Objects[i].ID == cfg.IDS.AutoBlockObjectID {
			obj = &cfg.Objects[i]
			break
		}
	}
	if obj == nil {
		return fmt.Errorf("ids: auto-block-objektet %q finns inte", cfg.IDS.AutoBlockObjectID)
	}

	blocked := map[string]bool{}
	for _, ip := range obj.Values {
		blocked[ip] = true
	}

	newestSeen := e.idsLastAlertTS
	added := false
	for _, ev := range events {
		if e.idsLastAlertTS != "" && ev.Timestamp <= e.idsLastAlertTS {
			continue
		}
		if ev.Timestamp > newestSeen {
			newestSeen = ev.Timestamp
		}
		if ev.Severity == 0 || ev.Severity > cfg.IDS.AutoBlockSeverity || ev.SrcIP == "" {
			continue
		}
		if !blocked[ev.SrcIP] {
			blocked[ev.SrcIP] = true
			obj.Values = append(obj.Values, ev.SrcIP)
			added = true
		}
	}
	e.idsLastAlertTS = newestSeen

	if !added {
		return nil
	}

	if err := e.store.UpdateObjectValuesDirect(obj.ID, obj.Values); err != nil {
		return fmt.Errorf("ids: kunde inte spara auto-block-objektet: %w", err)
	}
	return e.ReapplyNftablesOnly(ctx)
}

// GetOpenVPNCACertPEM returnerar (och vid behov genererar) brandväggens
// OpenVPN-CA-certifikat i publik PEM-form. CA-nyckeln lämnar aldrig denna
// funktion.
func (e *Engine) GetOpenVPNCACertPEM() (string, error) {
	ca, err := e.store.EnsureOpenVPNCA()
	if err != nil {
		return "", err
	}
	return ca.CertPEM, nil
}

// IssueOpenVPNClient signerar ett nytt klientcertifikat med brandväggens CA.
// Klientens privata nyckel returneras EN gång och sparas aldrig av agenten —
// anroparen (API-lagret) ansvarar för att bara spara certPEM/serial i
// candidate-konfigurationen.
func (e *Engine) IssueOpenVPNClient(commonName string) (clientCertPEM, clientKeyPEM, serial string, err error) {
	ca, err := e.store.EnsureOpenVPNCA()
	if err != nil {
		return "", "", "", fmt.Errorf("openvpn: kunde inte hämta CA: %w", err)
	}
	kp, err := pki.IssueCert(ca.CertPEM, ca.KeyPEM, commonName, false)
	if err != nil {
		return "", "", "", err
	}
	return kp.CertPEM, kp.KeyPEM, kp.Serial, nil
}

func (e *Engine) GetState() State {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state
}

// --- Fas 8: Flera administrationsanvändare & roller ---
// Tunna passthrough-metoder till store.Users, för att hålla samma
// lagerarkitektur (API -> Engine -> Store) som resten av agenten.

// Backup skapar en lösenfras-krypterad backup av hela persistenslagret
// (Fas 10, se pkg/store/backup.go). Tunn passthrough, inget engine-
// specifikt tillstånd inblandat.
func (e *Engine) Backup(passphrase string) ([]byte, error) {
	return e.store.Backup(passphrase)
}

// Restore skriver tillbaka en backup skapad av Backup. Anroparen (API-
// handlern) ansvarar för att sedan starta om processen (systemd
// Restart=always tar hand om det) — Restore i sig försöker INTE hot-
// swappa engine-tillståndet, se pkg/store/backup.go.
func (e *Engine) Restore(data []byte, passphrase string) error {
	return e.store.Restore(data, passphrase)
}

// FactoryReset tar bort ALL config-/nyckeldata i baseDir (utom
// audit.log — revisionshistoriken ska överleva en reset) så att nästa
// uppstart återgår till samma första-start-seedning som en helt ny
// installation (loadOrInit/UserStore, se pkg/store/store.go respektive
// users.go). Anroparen ansvarar för att verifiera lösenordet FÖRE detta
// anropas (se handleFactoryReset) — den här funktionen litar blint på att
// den redan är auktoriserad.
func (e *Engine) FactoryReset() error {
	return e.store.FactoryReset()
}

func (e *Engine) VerifyUserCredentials(username, password string) (*store.PublicUser, error) {
	return e.store.Users.VerifyCredentials(username, password)
}

func (e *Engine) ListUsers() []store.PublicUser {
	return e.store.Users.ListUsers()
}

func (e *Engine) CreateUser(username, password string, role store.Role) (*store.PublicUser, error) {
	return e.store.Users.CreateUser(username, password, role)
}

func (e *Engine) DeleteUser(id string) error {
	return e.store.Users.DeleteUser(id)
}

// ChangeOwnPassword byter en användares lösenord, men kräver att det
// NUVARANDE lösenordet anges och stämmer — så en inloggad session inte kan
// byta lösenord utan att faktiskt känna till det befintliga (t.ex. om
// någon lämnar en session olåst).
func (e *Engine) ChangeOwnPassword(userID, currentPassword, newPassword string) error {
	if err := e.store.Users.VerifyPasswordByID(userID, currentPassword); err != nil {
		return err
	}
	return e.store.Users.ChangePassword(userID, newPassword)
}

// AdminResetPassword sätter ett nytt lösenord för en ANNAN användare utan
// att känna till dennes nuvarande lösenord — bara admin-roller kan nå
// denna via API:t (se authMiddlewareAdmin).
func (e *Engine) AdminResetPassword(userID, newPassword string) error {
	return e.store.Users.ChangePassword(userID, newPassword)
}

func (e *Engine) FindUserByUsername(username string) (*store.PublicUser, error) {
	return e.store.Users.FindByUsername(username)
}
