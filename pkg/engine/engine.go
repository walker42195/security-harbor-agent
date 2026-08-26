package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/dhcp"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/dns"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/haproxy"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/network"
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
	mu              sync.Mutex
	store           *store.Store
	nftAdapter      *nftables.Adapter
	dhcpAdapter     *dhcp.Adapter
	wgAdapter       *wireguard.Adapter
	ovpnAdapter     *openvpn.Adapter
	dnsAdapter      *dns.Adapter
	syslogAdapter   *syslog.Adapter
	suricataAdapter *suricata.Adapter
	haproxyAdapter  *haproxy.Adapter
	state           State
	confirmTimer    *time.Timer
	unconfirmedCfg  *config.Config

	// idsLastAlertTS håller den senaste larm-tidsstämpeln vi redan hanterat
	// för auto-block (Fas 9), så samma larm inte blockeras om och om igen.
	// Rensas vid omstart (samma lättviktiga i-minnet-approach som resten av
	// engine-tillståndet) — värsta fallet efter en omstart är att de senast
	// hanterade larmen bedöms på nytt, inte att något missas.
	idsLastAlertTS string

	// degradedBackends håller icke-blockerande fel från senaste applyBackends
	// (t.ex. att Suricata inte kunde starta). Se applyBackends för
	// resonemanget kring vilka backends som får faila utan att fälla hela
	// appliceringen. Läses av API:t och visas som en varning i GUI:t.
	degradedBackends []BackendWarning

	// interfaceWarnings håller icke-blockerande fel från applyInterfaces
	// (t.ex. att ingen persistent nätverkskonfiguration kunde skrivas).
	// Egen field, inte degradedBackends: applyBackends NOLLSTÄLLER den
	// listan via defer vid varje applicering, och applyInterfaces körs
	// FÖRE applyBackends — delade de fält hade gränssnittsvarningarna
	// tystnat i samma ögonblick som de skrevs.
	interfaceWarnings []BackendWarning
}

// BackendWarning beskriver en backend som inte kunde appliceras men som inte
// är trafikstyrande — appliceringen fortsätter, men administratören ska se
// att funktionen inte är igång.
type BackendWarning struct {
	Backend string `json:"backend"`
	Message string `json:"message"`
}

// DegradedBackends returnerar varningarna från den senaste appliceringen.
func (e *Engine) DegradedBackends() []BackendWarning {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]BackendWarning, 0, len(e.degradedBackends)+len(e.interfaceWarnings))
	out = append(out, e.interfaceWarnings...)
	out = append(out, e.degradedBackends...)
	return out
}

func NewEngine(st *store.Store, nftAdapter *nftables.Adapter, dhcpAdapter *dhcp.Adapter, wgAdapter *wireguard.Adapter, ovpnAdapter *openvpn.Adapter, dnsAdapter *dns.Adapter, syslogAdapter *syslog.Adapter, suricataAdapter *suricata.Adapter, haproxyAdapter *haproxy.Adapter) *Engine {
	return &Engine{
		store:           st,
		nftAdapter:      nftAdapter,
		dhcpAdapter:     dhcpAdapter,
		wgAdapter:       wgAdapter,
		ovpnAdapter:     ovpnAdapter,
		dnsAdapter:      dnsAdapter,
		syslogAdapter:   syslogAdapter,
		suricataAdapter: suricataAdapter,
		haproxyAdapter:  haproxyAdapter,
		state:           StateIdle,
	}
}

// applyBackends applicerar samtliga systembackends (nftables, Kea DHCP,
// WireGuard) för en given konfiguration. Delas mellan ApplyCandidate och
// rollback så att en rollback verkligen återställer DHCP/VPN, inte bara
// brandväggsreglerna.
func (e *Engine) applyBackends(ctx context.Context, cfg *config.Config, dryRun bool) error {
	// warnings samlar icke-blockerande fel (se IDS-blocket längre ned).
	var warnings []BackendWarning
	if !dryRun {
		defer func() { e.degradedBackends = warnings }()
	}

	if _, err := e.nftAdapter.ApplyConfig(ctx, cfg, dryRun); err != nil {
		return fmt.Errorf("nftables: %w", err)
	}

	// Kärnans IPv4-forwarding MÅSTE vara på i gateway-läge, annars
	// forwardar brandväggen INGEN trafik alls — LAN→WAN, inter-VLAN och
	// all DNAT/port-forwarding är död oavsett hur korrekta nftables-
	// reglerna är. Upptäckt 2026-08-20 vid ett WAN→LAN-genomströmningstest
	// från utsidan: en SYN nådde WAN-interfacet, DNAT-regeln fanns, men
	// paketet forwardades aldrig ut på LAN-sidan eftersom
	// net.ipv4.ip_forward stod på kärnans default 0. Host-läge sätter
	// tvärtom 0 (en enkortsdator ska inte routa mellan nät). Sätts vid
	// varje apply OCH vid boot (ApplyRunningConfigAtBoot anropar denna),
	// så inställningen överlever omstart utan en separat sysctl.d-fil.
	if !dryRun {
		if err := setIPForwarding(!cfg.IsHostMode()); err != nil {
			return fmt.Errorf("ip-forwarding: %w", err)
		}
		// ARP-härdning: gör så att varje kort BARA svarar på ARP för de IP:n som
		// faktiskt sitter på det kortet (arp_ignore=1) och alltid annonserar
		// avsändar-IP från rätt kort (arp_announce=2). Utan detta svarar Linux
		// på ARP för valfri lokal IP från valfritt kort ("ARP flux"): om WAN och
		// LAN hamnar på samma L2-segment (t.ex. ett platt testnät) kan WAN-kortet
		// då svara på ARP för LAN:s management-IP, varpå administratörens trafik
		// går in på WAN-kortet och träffar HARD WAN DROP → man låser ut sig helt
		// (upptäckt på .166 2026-08-23: lådan verkade hängd, ARP svarade men all
		// IP-trafik nekades). Ofarligt i en korrekt topologi (WAN/LAN på olika
		// nät). Sätts vid varje apply och vid boot, så det överlever omstart.
		if err := setARPHardening(); err != nil {
			// Inte fatalt — logga och fortsätt (en gammal kärna utan just dessa
			// knappar ska inte stoppa hela appliceringen).
			log.Printf("[NET] kunde inte sätta ARP-härdning: %v", err)
		}
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

	// IDS (Suricata) är PASSIV övervakning — den styr ingen trafik. Att den
	// inte startar får därför inte fälla hela appliceringen.
	//
	// Live-incident 2026-08-25 (10.0.0.9): Proxmox-värden var överbokad och
	// ballongdrivrutinen hade krympt brandvägg-VM:en till ~535 MB användbart
	// minne. Suricata hann inte ladda ET Open-regelsetet (~68 500 regler)
	// inom systemds TimeoutStartSec=90s, dödades, startades om av
	// Restart=on-failure, och loopade. Varje Apply blockerade då 90 sekunder
	// på `systemctl restart suricata` och FAILADE sedan — varpå den
	// automatiska rollbacken körde exakt samma anrop och failade likadant.
	// Resultatet blev "systemet kan vara halvapplicerat" trots att nftables
	// (det enda som faktiskt filtrerar trafik) hade applicerats korrekt.
	//
	// Nu registreras felet som en varning i stället. Trafikstyrande backends
	// (nftables, ip-forwarding, DHCP, VPN, DNS, SNI) failar fortfarande hårt.
	if !cfg.IsHostMode() {
		if err := e.suricataAdapter.ApplyConfig(ctx, cfg, dryRun); err != nil {
			log.Printf("[APPLY] VARNING: IDS (Suricata) kunde inte appliceras: %v — appliceringen fortsätter, IDS är AVSTÄNGD tills detta åtgärdats", err)
			warnings = append(warnings, BackendWarning{
				Backend: "ids",
				Message: fmt.Sprintf("IDS (Suricata) kunde inte startas: %v. Brandväggsreglerna är applicerade, men intrångsdetekteringen är inte igång. Vanligaste orsaken är för lite minne för regelsetet.", err),
			})
		}
	}

	// HAProxy (SNI-routning) körs i båda lägen — adaptern stoppar tjänsten
	// när inga aktiva rutter finns, likt syslog.
	if err := e.haproxyAdapter.ApplyConfig(ctx, cfg, dryRun); err != nil {
		return fmt.Errorf("haproxy: %w", err)
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

// applyInterfaces tillämpar gränssnittskonfiguration på Linux och skriver
// ner den så att den ÖVERLEVER en omstart.
//
// Två lager, i den ordningen:
//
//  1. Persistent OS-konfiguration via det lager som äger nätverket på
//     maskinen — netplan, NetworkManager eller systemd-networkd (se
//     pkg/adapter/network/persist.go). Det är det som gör att en adress satt
//     i GUI:t gäller på OS-nivå, precis som om den satts med nmcli/nmtui.
//     Skrivningen kräver root och görs därför av en minimal root-oneshot,
//     inte i den härdade daemon-processen (se network/helper.go).
//  2. Den imperativa `ip`-vägen som FALLBACK, om inget känt persistenslager
//     finns eller om hjälparen misslyckades.
//
// Funktionen går i två pass: först avgörs vilka kort som behöver röras, sedan
// skickas hela konfigurationen + listan på de korten i ETT anrop till
// hjälparen. Uppdelningen finns för att varje anrop är en egen
// root-oneshot — ett per kort vore både långsamt och onödigt.
//
// Bara gränssnitt som faktiskt BEHÖVER röras rörs — precis det användaren
// begärde 2026-08-20: en ändring på ETT gränssnitt ska aldrig påverka de
// andra. Ett kort behöver röras om det ändrats jämfört med prevCfg, om det
// är en VLAN som saknas på systemet, eller om det GLIDIT IFRÅN sin
// konfiguration.
//
// Just drift-kontrollen är ny (2026-08-26). Tidigare betydde prevCfg == nil
// (boot) "rör ingenting alls", vilket lät ett kort ligga kvar i fel läge hur
// länge som helst: brandväggen på 10.0.0.9 tappade sin statiska
// management-IP till en DHCP-lease vid varje omstart av agenten, och
// eftersom det inte fanns någon prevCfg att jämföra med rättades det aldrig.
// Nu avgör systemets faktiska tillstånd i stället (MatchesSystemState), så
// ett kort som redan stämmer lämnas fortfarande helt orört — ingen flush,
// ingen bruten session — medan ett kort som glidit rättas.
func (e *Engine) applyInterfaces(ctx context.Context, newCfg, prevCfg *config.Config) {
	if newCfg == nil {
		return
	}
	netAdapter := network.NewAdapter()
	// Varningarna skrivs UTAN att ta e.mu — anroparna (ApplyCandidate,
	// rollbackLocked) håller redan låset, och sync.Mutex är inte reentrant.
	// Samma konvention som applyBackends följer för degradedBackends.
	var warnings []BackendWarning
	defer func() { e.interfaceWarnings = warnings }()

	warnings = append(warnings, lanDHCPWarnings(newCfg)...)

	prevByID := map[string]config.Interface{}
	if prevCfg != nil {
		for _, iface := range prevCfg.Interfaces {
			prevByID[iface.ID] = iface
		}
	}

	// FÖRSTA PASSET: avgör vilka kort som behöver röras. Inget tillämpas här —
	// persistenslagret vill ha hela listan i ETT anrop (det är en root-oneshot
	// per anrop, se pkg/adapter/network/helper.go), så beslutet måste tas
	// innan något görs.
	var touch []config.Interface
	var devices []string
	for _, iface := range newCfg.Interfaces {
		prev, hadPrev := prevByID[iface.ID]
		changed := hadPrev && interfaceConfigDiffers(prev, iface)

		isVLAN := iface.VLANID > 0 && iface.Parent != ""
		deviceMissing := false
		if iface.Device != "" {
			if _, err := net.InterfaceByName(iface.Device); err != nil {
				deviceMissing = true
			}
		}

		// Finns ingen tidigare konfiguration att jämföra med (boot, eller ett
		// nytillkommet gränssnitt) avgör systemets faktiska tillstånd.
		drifted := !hadPrev && !netAdapter.MatchesSystemState(iface)

		if !changed && !drifted && !(isVLAN && deviceMissing) {
			continue
		}
		if drifted {
			log.Printf("[NET] %s stämmer inte med konfigurationen — återställer", iface.Device)
		}

		// Om en VLAN flyttats till ett annat fysiskt kort (Parent/VLANID
		// ändrats) ligger det GAMLA subinterfacet kvar på Linux och måste
		// rivas — annars fortsätter det fånga trafik på fel kort. Görs FÖRE
		// tillämpningen som skapar det nya subinterfacet.
		if hadPrev && prev.VLANID > 0 && prev.Device != "" &&
			(prev.Parent != iface.Parent || prev.VLANID != iface.VLANID) {
			if err := netAdapter.DeleteVLANInterface(ctx, prev.Device); err != nil {
				log.Printf("[NET] kunde inte ta bort gammalt VLAN %s: %v", prev.Device, err)
			}
		}

		device := iface.Device
		if isVLAN {
			device = fmt.Sprintf("%s.%d", iface.Parent, iface.VLANID)
		}
		touch = append(touch, iface)
		devices = append(devices, device)
	}

	// Skriv ner konfigurationen på OS-nivå och tillämpa den på de kort som
	// behöver det. Ett enda anrop med HELA gränssnittslistan: lagren är
	// deklarativa och behöver hela bilden för att kunna städa bort det som
	// inte längre finns. Görs även när inget kort behöver röras, så att filen
	// hålls i synk (t.ex. efter att ett gränssnitt tagits bort).
	persisted := false
	if network.DetectPersistBackend() == nil {
		warnings = append(warnings, BackendWarning{
			Backend: "network-persist",
			Message: "Hittade varken netplan, NetworkManager eller systemd-networkd. " +
				"Gränssnittsadresserna sätts direkt i kärnan och gäller nu, men skrivs inte " +
				"ner någonstans och FÖRSVINNER vid omstart.",
		})
	} else if _, err := network.ApplyPersistent(ctx, network.ApplyRequest{
		Interfaces:  newCfg.Interfaces,
		Reconfigure: devices,
	}); err != nil {
		log.Printf("[NET] kunde inte spara nätverkskonfigurationen: %v", err)
		warnings = append(warnings, BackendWarning{
			Backend: "network-persist",
			Message: fmt.Sprintf("Kunde inte spara nätverkskonfigurationen: %v. "+
				"Adresserna sätts direkt i kärnan och gäller nu, men försvinner vid omstart.", err),
		})
	} else {
		persisted = true
	}

	// ANDRA PASSET: den imperativa `ip`-vägen som FALLBACK — inte som
	// komplement. Kördes den även när persistenslagret lyckats skulle den
	// flusha och sätta om en adress som just satts (och för ett DHCP-kort
	// trigga en andra, onödig förhandling direkt efter den första).
	for i, iface := range touch {
		if !persisted {
			if err := netAdapter.ApplyInterfaceConfig(ctx, iface); err != nil {
				log.Printf("[NET] kunde inte tillämpa gränssnitt %s: %v", iface.Device, err)
			}
		}
		// Oavsett väg: ett internt kort får aldrig behålla en default-rutt.
		// Persistenslagren är konfigurerade att inte skapa någon, men en rutt
		// som redan LIGGER där (t.ex. från en DHCP-lease kortet hade innan
		// det byttes till statiskt) försvinner inte av sig själv.
		if iface.Enabled && !strings.EqualFold(iface.Zone, "WAN") {
			netAdapter.RemoveDefaultRoute(ctx, devices[i])
		}
	}

	// Gränssnitt som fanns i prevCfg men tagits bort ur den nya
	// konfigurationen ska av-konfigureras — annars ligger IP och ev. rutt
	// kvar tills nästa omstart (applyInterfaces-loopen ovan rör bara kort som
	// finns KVAR i newCfg). Ett borttaget VLAN-subinterface rivs helt; ett
	// borttaget fysiskt kort får sina adresser och default-rutt bortflushade
	// (själva enheten kan ligga kvar i hypervisorn tills den tas bort där).
	// Deras poster i persistenslagret städas av backend.Write ovan, som
	// skriver hela konfigurationen och tar bort det som inte längre finns.
	if prevCfg != nil {
		newByID := map[string]bool{}
		for _, iface := range newCfg.Interfaces {
			newByID[iface.ID] = true
		}
		for _, prev := range prevCfg.Interfaces {
			if newByID[prev.ID] || prev.Device == "" {
				continue
			}
			if prev.VLANID > 0 && prev.Parent != "" {
				if err := netAdapter.DeleteVLANInterface(ctx, prev.Device); err != nil {
					log.Printf("[NET] kunde inte ta bort borttaget VLAN %s: %v", prev.Device, err)
				}
			} else if err := netAdapter.DeconfigureInterface(ctx, prev.Device); err != nil {
				log.Printf("[NET] kunde inte av-konfigurera borttaget gränssnitt %s: %v", prev.Device, err)
			}
		}
	}
}

// applyStaticRoutes tillämpar (respektive tar bort) statiska IP-rutter på
// Linux via "ip route replace"/"ip route del" (se pkg/adapter/network). Till
// skillnad från applyInterfaces ovan är "replace" idempotent, så alla
// AKTIVERADE rutter i newCfg appliceras om vid varje anrop utan att man
// först behöver avgöra om de ändrats — det är billigt och riskfritt (ingen
// flush inblandad). Bara borttagning kräver en jämförelse mot prevCfg: en
// rutt som funnits men försvunnit ur configen (borttagen, inaktiverad, eller
// fått ett nytt Network så att den gamla CIDR:en inte längre täcks) måste
// rivas explicit, annars ligger den kvar i kärnans routingtabell för evigt.
//
// prevCfg == nil (boot) betyder "ingen jämförelse" → bara applicera,
// samma mönster som applyInterfaces.
func (e *Engine) applyStaticRoutes(ctx context.Context, newCfg, prevCfg *config.Config) {
	if newCfg == nil {
		return
	}
	netAdapter := network.NewAdapter()

	for _, r := range newCfg.StaticRoutes {
		if !r.Enabled {
			continue
		}
		if err := netAdapter.ApplyStaticRoute(ctx, r); err != nil {
			log.Printf("[NET] kunde inte sätta rutt %s: %v", r.Network, err)
		}
	}

	if prevCfg == nil {
		return
	}
	newByID := map[string]config.StaticRoute{}
	for _, r := range newCfg.StaticRoutes {
		newByID[r.ID] = r
	}
	for _, prev := range prevCfg.StaticRoutes {
		cur, stillEnabled := newByID[prev.ID]
		if !stillEnabled || !cur.Enabled || cur.Network != prev.Network {
			if err := netAdapter.DeleteStaticRoute(ctx, prev); err != nil {
				log.Printf("[NET] kunde inte ta bort rutt %s: %v", prev.Network, err)
			}
		}
	}
}

// interfaceConfigDiffers jämför de fält som faktiskt påverkar Linux-
// konfigurationen av ett gränssnitt.
func interfaceConfigDiffers(a, b config.Interface) bool {
	return a.Enabled != b.Enabled ||
		a.Device != b.Device ||
		a.Parent != b.Parent ||
		a.VLANID != b.VLANID ||
		a.AddressType != b.AddressType ||
		a.IPv4 != b.IPv4
}

// GetDHCPLeases returnerar aktuella DHCP-utlåningar (Kea memfile) berikade
// med vilket gränssnitt/zon varje klient hör till — matchat genom att se
// vilket AKTIVERAT gränssnitts subnät klientens IP ligger i. WAN utesluts
// (ingen DHCP-server körs där), liksom leases som inte matchar något
// konfigurerat subnät.
func (e *Engine) GetDHCPLeases() ([]dhcp.LeaseDetail, error) {
	leases, err := dhcp.ParseLeasesDetailed(e.dhcpAdapter.LeaseDatabasePath())
	if err != nil {
		return nil, err
	}
	cfg := e.store.GetRunningConfig()
	if cfg == nil {
		return []dhcp.LeaseDetail{}, nil
	}

	type ifaceNet struct {
		device string
		zone   string
		net    *net.IPNet
	}
	var nets []ifaceNet
	for _, iface := range cfg.Interfaces {
		if !iface.Enabled || iface.Zone == "WAN" || iface.IPv4 == "" {
			continue
		}
		_, n, perr := net.ParseCIDR(iface.IPv4)
		if perr != nil || n == nil {
			continue
		}
		nets = append(nets, ifaceNet{device: iface.Device, zone: iface.Zone, net: n})
	}

	out := make([]dhcp.LeaseDetail, 0, len(leases))
	for _, l := range leases {
		ip := net.ParseIP(l.IP)
		if ip == nil {
			continue
		}
		for _, n := range nets {
			if n.net.Contains(ip) {
				l.Interface = n.device
				l.Zone = n.zone
				out = append(out, l)
				break
			}
		}
	}
	return out, nil
}

// ApplyRunningConfigAtBoot laddar den senast committade konfigurationen i
// samtliga backends vid agentstart (kallas från main.go innan API-servern
// startar). Går inte via Safe Apply/rollback-timern — det är bara att
// återskapa det tillstånd som redan var bekräftat innan omstarten.
func (e *Engine) ApplyRunningConfigAtBoot(ctx context.Context) error {
	running := e.store.GetRunningConfig()
	// prevCfg=nil → ingen tidigare konfiguration att jämföra med. Då avgör
	// systemets faktiska tillstånd vilka kort som behöver röras: de som redan
	// stämmer lämnas orörda, de som glidit ifrån konfigurationen (t.ex. en
	// statisk management-IP som ersatts av en DHCP-lease) rättas. Se
	// applyInterfaces.
	e.applyInterfaces(ctx, running, nil)
	e.applyStaticRoutes(ctx, running, nil)
	return e.applyBackends(ctx, running, false)
}

func (e *Engine) GetRunningConfig() *config.Config {
	return e.store.GetRunningConfig()
}

func (e *Engine) GetCandidateConfig() *config.Config {
	return e.store.GetCandidateConfig()
}

func (e *Engine) UpdateCandidate(cfg *config.Config) error {
	// Status-fälten på ett Object.Source (LastUpdated/LastError/EntryCount)
	// ägs av AGENTEN — de sätts av hot-lista/GeoIP-uppdateraren (Fas 5,
	// UpdateObjectValues) utanför Safe Apply. En klient som PUT:ar hela
	// configen ska inte kunna skriva över dem (upptäckt 2026-08-20: GUI:t
	// utelämnade fälten i sin JSON, så varje sparning nollställde
	// "senast uppdaterad" och objektet visade "Aldrig uppdaterad" trots att
	// listan var hämtad). Återställ dem från den nu kända serversidan.
	preserveObjectSourceStatus(cfg, e.store.GetRunningConfig())
	preserveDNSBlocklistStatus(cfg, e.store.GetRunningConfig())
	return e.store.SetCandidateConfig(cfg)
}

// preserveObjectSourceStatus kopierar de agent-ägda status-fälten från
// prev till motsvarande objekt (matchat på ID) i incoming. RefreshHours,
// Kind, URL och CountryCode rörs INTE — de är klient-ägda inställningar.
func preserveObjectSourceStatus(incoming, prev *config.Config) {
	if incoming == nil || prev == nil {
		return
	}
	prevByID := map[string]*config.ObjectSource{}
	for i := range prev.Objects {
		if prev.Objects[i].Source != nil {
			prevByID[prev.Objects[i].ID] = prev.Objects[i].Source
		}
	}
	for i := range incoming.Objects {
		src := incoming.Objects[i].Source
		if src == nil {
			continue
		}
		if old, ok := prevByID[incoming.Objects[i].ID]; ok {
			src.LastUpdated = old.LastUpdated
			src.LastError = old.LastError
			src.EntryCount = old.EntryCount
		}
	}
}

// preserveDNSBlocklistStatus är samma fix som preserveObjectSourceStatus
// ovan, men för DNS.Blocklists (Fas 6) — samma bugg, aldrig fixad här.
// Upptäckt 2026-08-24: en administratör hade StevenBlack hosts-listan
// korrekt uppdaterad på servern (82561 domäner, running.json), men GUI:t
// visade "0 domäner" — kandidaten hade nollställts av en HELT OREL-
// ATERAD sparning (t.ex. en DHCP-ändring) eftersom klientens egen kopia av
// blocklistans status var förlegad när den PUT:ade hela configen.
// RefreshHours, Kind och URL rörs INTE — klient-ägda inställningar.
func preserveDNSBlocklistStatus(incoming, prev *config.Config) {
	if incoming == nil || prev == nil || incoming.DNS == nil || prev.DNS == nil {
		return
	}
	prevByID := map[string]config.DNSBlocklistSource{}
	for _, b := range prev.DNS.Blocklists {
		prevByID[b.ID] = b
	}
	for i := range incoming.DNS.Blocklists {
		if old, ok := prevByID[incoming.DNS.Blocklists[i].ID]; ok {
			incoming.DNS.Blocklists[i].LastUpdated = old.LastUpdated
			incoming.DNS.Blocklists[i].LastError = old.LastError
			incoming.DNS.Blocklists[i].EntryCount = old.EntryCount
		}
	}
}

// ValidateCandidate validerar en candidate-konfiguration utan att ändra systemet.
func (e *Engine) ValidateCandidate(ctx context.Context, cfg *config.Config) error {
	// Ordningen är medveten: VÅRA egna, begripliga kontroller körs FÖRE
	// backendarnas dry-run. Kördes de efter (som tidigare) vann alltid
	// nft:s lågnivåfel kapplöpningen om vem som fick rapportera — en DNAT
	// med ogiltig intern IP och port 99999 gav t.ex. "Could not resolve
	// hostname: Temporary failure in name resolution / Service out of
	// range" i GUI:t, i stället för "policy X: intern mål-IP ... är inte en
	// giltig IP-adress". Samma fel, obegripligt formulerat.
	if len(cfg.Interfaces) == 0 {
		return fmt.Errorf("konfigurationen måste ha minst ett gränssnitt")
	}
	if err := validateInterfaces(cfg); err != nil {
		return err
	}
	if err := validateUniqueNames(cfg); err != nil {
		return err
	}
	if err := validatePolicies(cfg); err != nil {
		return err
	}
	if err := validateSNIRoutes(cfg); err != nil {
		return err
	}
	if err := validateStaticRoutes(cfg); err != nil {
		return err
	}

	// Därefter backendarnas egen dry-run (nft -c, Kea, Unbound m.fl.), som
	// fångar allt vi inte modellerar själva.
	if err := e.applyBackends(ctx, cfg, true); err != nil {
		return fmt.Errorf("validering misslyckades: %w", err)
	}

	return nil
}

// validateInterfaces kontrollerar att ett aktiverat, statiskt gränssnitts
// IPv4-fält är en giltig CIDR-adress ("10.13.13.1/24"), inte bara en bar
// IP ("10.13.13.1"). Upptäckt live 2026-08-24: en administratörs VLAN
// hade tappat sin /24-suffix i running.json (GUI:t skickar fältet
// oredigerat, ingen validering fångade det) — net.ParseCIDR i
// GetDHCPLeases (matchar en DHCP-lease mot vilket gränssnitts subnät den
// hör till) misslyckas tyst för en sådan sträng och HELA gränssnittets
// leases försvann då ur DHCP-vyn, utan felmeddelande någonstans. Kördes
// interfacet ändå fortsatte fungera på nätverksnivå (en tidigare korrekt
// applicerad adress ligger kvar på kortet), vilket gjorde felet extra
// förvirrande — allt såg ut att fungera utom just lease-listan.
func validateInterfaces(cfg *config.Config) error {
	for _, iface := range cfg.Interfaces {
		if err := validateInterfaceMAC(iface); err != nil {
			return err
		}
		if !iface.Enabled || iface.AddressType != "static" || iface.IPv4 == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(iface.IPv4); err != nil {
			label := iface.Name
			if label == "" {
				label = iface.Device
			}
			return fmt.Errorf("gränssnitt %q: IPv4-adressen %q måste anges med prefix (t.ex. \"10.13.13.1/24\"), inte bara en bar IP-adress", label, iface.IPv4)
		}
	}
	return nil
}

// validateInterfaceMAC kontrollerar en manuellt satt MAC-adress. Den skrivs
// rakt in i ett `ip link set ... address`-anrop, så formatet måste vara känt
// giltigt innan vi kommer dit. Två adresser avvisas utöver rena syntaxfel:
//
//   - multicast (lägsta biten i första oktetten satt) — en sådan käll-MAC är
//     ogiltig på ethernet och kortet blir tyst; switchen släpper ramarna.
//   - hel-noll — kortet får ingen användbar identitet alls.
//
// Vi kräver 6 oktetter (EUI-48): net.ParseMAC godtar även 8 och 20 byte
// (EUI-64/InfiniBand), vilket inte går att sätta på ett ethernetkort.
func validateInterfaceMAC(iface config.Interface) error {
	mac := strings.TrimSpace(iface.MACAddress)
	if mac == "" {
		return nil
	}
	label := iface.Name
	if label == "" {
		label = iface.Device
	}
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("gränssnitt %q: %q är ingen giltig MAC-adress — ange den på formen aa:bb:cc:dd:ee:ff", label, mac)
	}
	if len(hw) != 6 {
		return fmt.Errorf("gränssnitt %q: MAC-adressen måste vara 6 oktetter (aa:bb:cc:dd:ee:ff)", label)
	}
	if hw[0]&0x01 != 0 {
		return fmt.Errorf("gränssnitt %q: %q är en multicast-adress och kan inte användas som kortets egen MAC — första oktetten måste vara jämn", label, mac)
	}
	allZero := true
	for _, b := range hw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("gränssnitt %q: MAC-adressen får inte vara 00:00:00:00:00:00", label)
	}
	return nil
}

// validateUniqueNames säkerställer att objekt respektive zoner inte har
// duplicerade namn. Namnet är det administratören ser och väljer i GUI:t
// (Policy-editorns From/To, DHCP/DNS m.m.) — det tekniskt unika i datamodellen
// är ID:t, men användaren ser bara namnet, så två med samma namn är tvetydigt.
// Jämförelsen är skiftlägesokänslig och trimmar blanksteg. (Objekt kontra zon
// får dela namn — de väljs i olika sammanhang och lagras separat.)
func validateUniqueNames(cfg *config.Config) error {
	seenObj := map[string]string{}
	for _, o := range cfg.Objects {
		key := strings.ToLower(strings.TrimSpace(o.Name))
		if key == "" {
			continue
		}
		if prev, dup := seenObj[key]; dup {
			return fmt.Errorf("två objekt har samma namn %q — namn måste vara unika (byt namn på det ena)", prev)
		}
		seenObj[key] = o.Name
	}
	seenZone := map[string]string{}
	for _, z := range cfg.Zones {
		key := strings.ToLower(strings.TrimSpace(z.Name))
		if key == "" {
			continue
		}
		if prev, dup := seenZone[key]; dup {
			return fmt.Errorf("två zoner har samma namn %q — namn måste vara unika (byt namn på det ena)", prev)
		}
		seenZone[key] = z.Name
	}
	return nil
}

// validatePolicies kör de policy-nära kontrollerna: att varje zon-val
// matchar ett konfigurerat gränssnitt, att tjänste-/portsträngen går att
// tolka, och att DNAT-parametrarna är kompletta.
//
// Zon-kontrollen finns eftersom nftables-adaptern (se zoneMatchExpr)
// annars tyst hoppar över regeln — samma skydd mot "matcha allt" som redan
// finns för tomma objekt-listor — vilket utan kontrollen bara syns som att
// "regeln aldrig gör något", obegripligt för en administratör som skrivit
// fel zonnamn.
func findPolicyByID(policies []config.Policy, id string) (config.Policy, bool) {
	for _, p := range policies {
		if p.ID == id {
			return p, true
		}
	}
	return config.Policy{}, false
}

func validatePolicies(cfg *config.Config) error {
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
	// 2b. Skyddade (Protected) policyer — just nu bara Management API-
	// åtkomsten (config.MgmtAPIPolicyID) — får varken inaktiveras eller tas
	// bort. Kontrollen körs här, vid Apply, eftersom det är ögonblicket en
	// ändring faktiskt slår igenom på den riktiga brandväggen: en
	// administratör som (avsiktligt eller via ett GUI-fel) stänger av eller
	// raderar den skulle annars kunna låsa sig ute ur webb-GUI:t helt, utan
	// en text-baserad reservväg som SSH har.
	mgmtPol, mgmtFound := findPolicyByID(cfg.Policies, config.MgmtAPIPolicyID)
	if !mgmtFound {
		return fmt.Errorf("policyn för Management API (%s) saknas — den kan inte tas bort, eftersom det är den enda vägen in i GUI:t", config.MgmtAPIPolicyID)
	}
	if !mgmtPol.Enabled {
		return fmt.Errorf("policyn %q är skyddad och kan inte inaktiveras — det skulle låsa ute administratören ur GUI:t", mgmtPol.Name)
	}

	for _, pol := range cfg.Policies {
		if !pol.Enabled {
			continue
		}

		// 4. Tjänste-/portsträngen måste gå att tolka. En otolkbar sträng
		// (t.ex. "80,443" eller en felstavning) fick tidigare
		// nftables-adaptern att generera en regel HELT UTAN portbegränsning
		// — en accept-regel avsedd för en enda port öppnade då tyst alla
		// portar. Adaptern hoppar numera över sådana regler istället
		// (fail-closed), men utan den här kontrollen hade användaren bara
		// sett att regeln "aldrig gör något", utan att förstå varför.
		if err := validatePolicyService(cfg, pol); err != nil {
			return err
		}

		// 4b. Schemat (Fas 7 — tidsstyrda regler) måste vara komplett och
		// välformat. Utan den här kontrollen kunde ett AKTIVERAT schema utan
		// dagar och utan kompletta tider rendera regeln helt utan
		// tidsbegränsning (dygnet runt) — se scheduleMatchExpr i
		// pkg/adapter/nftables. Ogiltiga dag-/tidssträngar gick dessutom rakt
		// in i nft-JSON och fick HELA ruleset-applyn att failas med ett
		// obegripligt lågnivåfel.
		if err := validatePolicySchedule(pol); err != nil {
			return err
		}

		// 5. DNAT-parametrar måste vara kompletta och rimliga — annars
		// genereras en trasig prerouting-regel som nft avvisar med ett
		// lågnivåfel långt från orsaken.
		if pol.Action == config.ActionDNAT {
			if err := validatePolicyNAT(pol); err != nil {
				return err
			}
			// DNAT-policyer undantas från zon-kontrollen nedan.
			continue
		}

		if pol.Local {
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

// validatePolicyService kontrollerar att policyns Service-referens går att
// översätta till ett nftables-matchningsuttryck — samma parsning som
// nftables-adaptern använder vid rendering, exponerad som ett begripligt
// valideringsfel istället för en tyst bortvald regel.
func validatePolicyService(cfg *config.Config, pol config.Policy) error {
	if nftables.PolicyServiceIsParseable(cfg, pol.Service) {
		return nil
	}
	return fmt.Errorf(
		"policy %q: tjänsten/porten %q går inte att tolka (använd t.ex. \"443\", \"TCP:443\", \"UDP:53\", \"TCP:8000-8100\", \"ICMP\", \"ANY\", eller en kommaseparerad lista som \"80,443,TCP:8000-8100,UDP:53\" — varje del utan eget tcp:/udp:-prefix ärver protokollet från föregående del, eller tcp om inget angetts alls)",
		pol.Name, pol.Service)
}

// scheduleDayNames är de exakta dagsträngar nftables `meta day` accepterar
// (och som GUI:t skickar). Allt annat avvisas hellre än skickas vidare till
// nft.
var scheduleDayNames = map[string]bool{
	"Monday": true, "Tuesday": true, "Wednesday": true, "Thursday": true,
	"Friday": true, "Saturday": true, "Sunday": true,
}

// scheduleTimePattern: HH:MM (24-timmars), valfritt med sekunder.
var scheduleTimePattern = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9])?$`)

// validatePolicySchedule kontrollerar att ett aktiverat schema faktiskt
// begränsar regeln i tid, och att dag-/tidsvärdena är sådana nftables
// förstår. Se kommentaren vid anropsstället för vad som gick fel utan den.
func validatePolicySchedule(pol config.Policy) error {
	sched := pol.Schedule
	if sched == nil || !sched.Enabled {
		return nil
	}
	hasDays := len(sched.Days) > 0
	hasTimes := sched.StartTime != "" && sched.EndTime != ""
	if !hasDays && !hasTimes {
		return fmt.Errorf(
			"policy %q: schemat är aktiverat men saknar både veckodagar och start-/sluttid — välj minst en dag eller ett komplett tidsintervall (regeln skulle annars gälla dygnet runt, tvärtemot avsikten)",
			pol.Name)
	}
	if (sched.StartTime == "") != (sched.EndTime == "") {
		return fmt.Errorf("policy %q: schemat har bara en av start-/sluttid angiven — ange båda eller ingen", pol.Name)
	}
	for _, d := range sched.Days {
		if !scheduleDayNames[d] {
			return fmt.Errorf("policy %q: okänd veckodag %q i schemat", pol.Name, d)
		}
	}
	for label, t := range map[string]string{"starttid": sched.StartTime, "sluttid": sched.EndTime} {
		if t != "" && !scheduleTimePattern.MatchString(t) {
			return fmt.Errorf("policy %q: %s %q är inte ett giltigt klockslag (använd HH:MM, t.ex. 08:00)", pol.Name, label, t)
		}
	}
	return nil
}

// validatePolicyNAT kontrollerar att en DNAT-policy har de fält som
// prerouting-regeln faktiskt behöver.
func validatePolicyNAT(pol config.Policy) error {
	if pol.NAT == nil {
		return fmt.Errorf("policy %q: port forwarding (DNAT) saknar NAT-inställningar", pol.Name)
	}
	if net.ParseIP(pol.NAT.InternalIP) == nil {
		return fmt.Errorf("policy %q: intern mål-IP %q är inte en giltig IP-adress", pol.Name, pol.NAT.InternalIP)
	}
	if pol.NAT.ExternalIP != "" && net.ParseIP(pol.NAT.ExternalIP) == nil {
		return fmt.Errorf("policy %q: extern IP %q är inte en giltig IP-adress", pol.Name, pol.NAT.ExternalIP)
	}
	for label, port := range map[string]int{"extern port": pol.NAT.ExternalPort, "intern port": pol.NAT.InternalPort} {
		if port < 1 || port > 65535 {
			return fmt.Errorf("policy %q: %s %d ligger utanför giltigt intervall 1-65535", pol.Name, label, port)
		}
	}
	if proto := strings.ToLower(pol.NAT.Protocol); proto != "" && proto != "tcp" && proto != "udp" {
		return fmt.Errorf("policy %q: protokollet %q stöds inte för port forwarding (använd tcp eller udp)", pol.Name, pol.NAT.Protocol)
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

// validateSNIRoutes kontrollerar de namnbaserade routnings-reglerna innan
// HAProxy-adapterns egen `haproxy -c`-dry-run — så att modellfel ger ett
// begripligt svar i stället för ett lågnivåfel från HAProxy.
func validateSNIRoutes(cfg *config.Config) error {
	usedPorts := map[int]bool{} // aktiva rutters ListenPort, för unikhetskontroll
	dnatPorts := map[int]bool{} // aktiva DNAT-policyers ExternalPort
	for _, pol := range cfg.Policies {
		if pol.Enabled && pol.Action == config.ActionDNAT && pol.NAT != nil && pol.NAT.ExternalPort > 0 {
			dnatPorts[pol.NAT.ExternalPort] = true
		}
	}

	for _, r := range cfg.SNIRoutes {
		if !r.Enabled {
			continue
		}
		label := r.Name
		if label == "" {
			label = r.ID
		}
		if r.ListenPort < 1 || r.ListenPort > 65535 {
			return fmt.Errorf("SNI-rutt %q: lyssnarporten %d ligger utanför giltigt intervall 1-65535", label, r.ListenPort)
		}
		if usedPorts[r.ListenPort] {
			return fmt.Errorf("SNI-rutt %q: lyssnarporten %d används redan av en annan aktiv SNI-rutt (två kan inte lyssna på samma port)", label, r.ListenPort)
		}
		usedPorts[r.ListenPort] = true
		if r.ListenPort == cfg.Settings.APIPort {
			return fmt.Errorf("SNI-rutt %q: lyssnarporten %d används redan av administrations-API:t", label, r.ListenPort)
		}
		if dnatPorts[r.ListenPort] {
			return fmt.Errorf("SNI-rutt %q: lyssnarporten %d krockar med en port forward (DNAT) på samma port — DNAT kapar porten före brandväggens egen tjänst", label, r.ListenPort)
		}
		if r.ExternalIP != "" && net.ParseIP(r.ExternalIP) == nil {
			return fmt.Errorf("SNI-rutt %q: extern IP %q är inte en giltig IP-adress", label, r.ExternalIP)
		}
		if len(r.Backends) == 0 && r.DefaultBackend == nil {
			return fmt.Errorf("SNI-rutt %q: regeln saknar både backends och fallback-mål — den gör ingenting", label)
		}

		// Hostnamn måste vara unika inom en rutt (annars tvetydig routning).
		seenHost := map[string]bool{}
		for i := range r.Backends {
			be := r.Backends[i]
			if err := validateSNIBackend(label, &be, false); err != nil {
				return err
			}
			for _, h := range be.Hostnames {
				key := strings.ToLower(strings.TrimSpace(h))
				if key == "" {
					continue
				}
				if seenHost[key] {
					return fmt.Errorf("SNI-rutt %q: värdnamnet %q förekommer i flera backends — routningen blir tvetydig", label, h)
				}
				seenHost[key] = true
			}
		}
		if r.DefaultBackend != nil {
			if err := validateSNIBackend(label, r.DefaultBackend, true); err != nil {
				return err
			}
		}

		// OpenVPN-fallback kräver att OpenVPN är aktiverat och kör TCP
		// (HAProxy tcp-passthrough fungerar inte mot en UDP-daemon).
		if usesOpenVPN(r) {
			if cfg.OpenVPN == nil || !cfg.OpenVPN.Enabled {
				return fmt.Errorf("SNI-rutt %q: pekar på lokal OpenVPN som fallback, men OpenVPN är inte aktiverat", label)
			}
			if strings.ToLower(cfg.OpenVPN.Protocol) != "tcp" {
				return fmt.Errorf("SNI-rutt %q: OpenVPN måste köra i TCP-läge för att kunna delas på samma port (ändra OpenVPN-protokollet till TCP)", label)
			}
		}
	}
	return nil
}

// validateStaticRoutes kontrollerar att varje aktiverad statisk rutt (se
// config.StaticRoute) går att applicera på Linux — ett format-fel här skulle
// annars bara synas som ett obegripligt lågnivåfel från "ip route replace"
// (t.ex. "Error: an inet prefix is expected rather than ...") långt från
// orsaken, samma motivering som validatePolicyService har för brandväggs-
// reglerna.
func validateStaticRoutes(cfg *config.Config) error {
	seenNetwork := map[string]bool{}
	knownDevices := map[string]bool{}
	for _, iface := range cfg.Interfaces {
		if iface.Device != "" {
			knownDevices[iface.Device] = true
		}
	}
	for _, r := range cfg.StaticRoutes {
		if !r.Enabled {
			continue
		}
		label := r.Name
		if label == "" {
			label = r.ID
		}
		if _, _, err := net.ParseCIDR(r.Network); err != nil {
			return fmt.Errorf("rutt %q: nätet %q är inte en giltig CIDR-adress (t.ex. 192.168.113.0/24)", label, r.Network)
		}
		if net.ParseIP(r.Gateway) == nil {
			return fmt.Errorf("rutt %q: gatewayen %q är inte en giltig IP-adress", label, r.Gateway)
		}
		if seenNetwork[r.Network] {
			return fmt.Errorf("rutt %q: nätet %s har redan en annan aktiv rutt — två rutter kan inte peka på samma nät", label, r.Network)
		}
		seenNetwork[r.Network] = true
		if r.Interface != "" && !knownDevices[r.Interface] {
			return fmt.Errorf("rutt %q: gränssnittet %q finns inte bland konfigurerade gränssnitt", label, r.Interface)
		}
	}
	return nil
}

// validateSNIBackend kontrollerar att en backend har exakt ETT måltyp
// (intern server ELLER lokal tjänst) och giltiga värden. isDefault=true
// tillåter tomma hostnamn (fallback matchar allt övrigt).
func validateSNIBackend(routeLabel string, b *config.SNIBackend, isDefault bool) error {
	hasTarget := b.TargetIP != "" || b.TargetPort != 0
	hasLocal := b.LocalService != ""
	if hasTarget && hasLocal {
		return fmt.Errorf("SNI-rutt %q: en backend kan inte ha både en intern server och en lokal tjänst", routeLabel)
	}
	if !hasTarget && !hasLocal {
		return fmt.Errorf("SNI-rutt %q: en backend saknar mål (ange intern server IP:port eller en lokal tjänst)", routeLabel)
	}
	if hasLocal && b.LocalService != config.LocalServiceOpenVPN {
		return fmt.Errorf("SNI-rutt %q: okänd lokal tjänst %q (stöds: openvpn)", routeLabel, b.LocalService)
	}
	if hasTarget {
		if net.ParseIP(b.TargetIP) == nil {
			return fmt.Errorf("SNI-rutt %q: intern server-IP %q är inte en giltig IP-adress", routeLabel, b.TargetIP)
		}
		if b.TargetPort < 1 || b.TargetPort > 65535 {
			return fmt.Errorf("SNI-rutt %q: intern server-port %d ligger utanför giltigt intervall 1-65535", routeLabel, b.TargetPort)
		}
	}
	if !isDefault {
		hasName := false
		for _, h := range b.Hostnames {
			if strings.TrimSpace(h) != "" {
				hasName = true
				break
			}
		}
		if !hasName {
			return fmt.Errorf("SNI-rutt %q: en backend (som inte är fallback) saknar värdnamn", routeLabel)
		}
	}
	return nil
}

// usesOpenVPN returnerar true om någon backend eller fallback i rutten
// pekar på den lokala OpenVPN-tjänsten.
func usesOpenVPN(r config.SNIRoute) bool {
	for i := range r.Backends {
		if r.Backends[i].LocalService == config.LocalServiceOpenVPN {
			return true
		}
	}
	return r.DefaultBackend != nil && r.DefaultBackend.LocalService == config.LocalServiceOpenVPN
}

// ApplyCandidate applicerar candidate-konfigurationen och startar 30-sekunders rollback-timern.
func (e *Engine) ApplyCandidate(ctx context.Context, user string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	candidate := e.store.GetCandidateConfig()
	prevRunning := e.store.GetRunningConfig()

	// Validera först
	if err := e.ValidateCandidate(ctx, candidate); err != nil {
		return fmt.Errorf("kan inte applicera ogiltig konfiguration: %w", err)
	}

	// Tillämpa gränssnittsändringar (skapa VLAN, IP/DHCP) — bara de
	// gränssnitt som ändrats jämfört med running, så en VLAN-ändring aldrig
	// rör LAN/WAN och tvärtom. Görs FÖRE brandväggsreglerna så nya VLAN-
	// devices finns när reglerna refererar dem.
	e.applyInterfaces(ctx, candidate, prevRunning)
	// Statiska rutter måste också finnas INNAN nftables-reglerna nedan
	// appliceras — annars kan en policy som beror på att ett nät faktiskt
	// är nåbart (t.ex. en Allow-regel mot 192.168.113.0/24) verka trasig
	// trots att regeln i sig är korrekt, bara för att paketen aldrig hittar
	// dit i första hand.
	e.applyStaticRoutes(ctx, candidate, prevRunning)

	// Applicera skarpt mot Linux-kärnan (nftables, Kea DHCP, WireGuard).
	//
	// applyBackends applicerar backendsen i tur och ordning med nftables
	// FÖRST. Om en senare backend fallerar (upptäckt skarpt 2026-08-20:
	// suricata kunde inte skriva /etc/suricata/suricata.yaml) hann de
	// tidigare redan ändra systemet — brandväggen stod då kvar med
	// candidate-konfigurationens nftables-regler medan API:t svarade
	// "misslyckades", och eftersom vi returnerar innan state sätts till
	// StateUnconfirmed startades ingen Safe Apply-timer som kunde städa
	// upp. Resultatet var ett tyst halvapplicerat tillstånd som ingen
	// automatik rullade tillbaka. Nu återställs running-konfigurationen
	// omedelbart vid ett misslyckat apply, så systemet alltid landar i ett
	// känt tillstånd.
	if err := e.applyBackends(ctx, candidate, false); err != nil {
		applyErr := err
		// applyInterfaces MÅSTE köras även vid återställning, inte bara
		// applyBackends — annars återställs bara nftables/DNS/DHCP/
		// Suricata-KONFIGURATIONEN, medan gränssnittens FAKTISKA länkstatus
		// (ip link up/down, satt av applyInterfaces ovan) blir kvar i det
		// misslyckade candidate-tillståndet. Upptäckt 2026-08-24: en
		// administratör stängde av WAN-gränssnittet (ip link ... down),
		// vilket fick Suricata (konfigurerad att sniffa just det kortet)
		// att vägra starta om — apply misslyckades, och ÅTERSTÄLLNINGEN
		// misslyckades DÄRFÖR OCKSÅ (Suricata försökte starta om mot ett
		// kort som running.json sa var uppe men som fysiskt fortfarande var
		// nere), och lämnade brandväggen med running.json som sa
		// "WAN aktiverat" medan kortet i verkligheten var nedstängt.
		e.applyInterfaces(ctx, e.store.GetRunningConfig(), candidate)
		if rbErr := e.applyBackends(ctx, e.store.GetRunningConfig(), false); rbErr != nil {
			log.Printf("[SAFE APPLY] KRITISKT: apply misslyckades (%v) OCH återställningen till running config misslyckades (%v) — systemet kan vara halvapplicerat", applyErr, rbErr)
			return fmt.Errorf("misslyckades applicera konfiguration: %w (återställningen misslyckades också: %v)", applyErr, rbErr)
		}
		_ = e.store.LogAudit(user, "APPLY_FAILED_ROLLED_BACK", fmt.Sprintf("Apply misslyckades (%v), återställde till running config", applyErr))
		return fmt.Errorf("misslyckades applicera konfiguration: %w", applyErr)
	}

	e.state = StateUnconfirmed
	e.unconfirmedCfg = candidate

	// Om det redan finns en timer igång, stoppa den
	if e.confirmTimer != nil {
		e.confirmTimer.Stop()
	}

	// Klampas till ett rimligt intervall. Tidigare defaultades BARA värdet 0
	// till 30 s — ett NEGATIVT värde gav en negativ duration till
	// time.AfterFunc, som då utlöser omedelbart och rullar tillbaka varje
	// Apply direkt (kodgranskning 2026-08-25). Ett orimligt stort värde gör
	// tvärtom skyddsnätet meningslöst.
	timeout := time.Duration(candidate.Settings.RollbackTimeoutSec) * time.Second
	const minRollbackTimeout, maxRollbackTimeout = 10 * time.Second, 10 * time.Minute
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if timeout < minRollbackTimeout {
		timeout = minRollbackTimeout
	}
	if timeout > maxRollbackTimeout {
		timeout = maxRollbackTimeout
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
	// Samma fix som i ApplyCandidate ovan: e.unconfirmedCfg är den
	// konfiguration som faktiskt applicerades skarpt (och nu ska rullas
	// tillbaka) — applyInterfaces måste jämföra MOT den för att veta vilka
	// gränssnitts länkstatus (ip link up/down) som faktiskt behöver
	// återställas, annars återställs bara backend-konfigurationen.
	e.applyInterfaces(ctx, running, e.unconfirmedCfg)
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

	// Kopiera ut Values i stället för att ta en pekare in i den DELADE
	// running-konfigurationen: den läses samtidigt av API-handlers (t.ex.
	// GET /config/running) och av nftables-renderingen, så ett append rakt
	// in i den slicen är en datakapplöpning (upptäckt vid kodgranskning
	// 2026-08-20). Skrivningen sker i stället samlat via
	// store.UpdateObjectValuesDirect, som tar store-låset.
	var objID string
	var values []string
	for i := range cfg.Objects {
		if cfg.Objects[i].ID == cfg.IDS.AutoBlockObjectID {
			objID = cfg.Objects[i].ID
			values = append(values, cfg.Objects[i].Values...)
			break
		}
	}
	if objID == "" {
		return fmt.Errorf("ids: auto-block-objektet %q finns inte", cfg.IDS.AutoBlockObjectID)
	}

	blocked := map[string]bool{}
	for _, ip := range values {
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
			values = append(values, ev.SrcIP)
			added = true
		}
	}
	e.idsLastAlertTS = newestSeen

	if !added {
		return nil
	}

	if err := e.store.UpdateObjectValuesDirect(objID, values); err != nil {
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

// UsernameByID slår upp användarnamnet för ett konto-ID. Behövs av
// API-lagret för att kunna ogiltigförklara ett kontos aktiva sessioner vid
// radering/lösenordsåterställning, där bara ID:t skickas in. Tom sträng om
// kontot inte finns.
func (e *Engine) UsernameByID(id string) string {
	for _, u := range e.store.Users.ListUsers() {
		if u.ID == id {
			return u.Username
		}
	}
	return ""
}

// setIPForwarding slår på/av kärnans IPv4-forwarding via /proc/sys.
// Systemd-enheten kör med ProtectKernelTunables=false + CAP_NET_ADMIN, så
// skrivningen är tillåten. Se applyBackends för varför detta behövs.
func setIPForwarding(enabled bool) error {
	val := []byte("0\n")
	if enabled {
		val = []byte("1\n")
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", val, 0644); err != nil {
		return fmt.Errorf("kunde inte skriva net.ipv4.ip_forward: %w", err)
	}
	return nil
}

// setARPHardening sätter net.ipv4.conf.all.arp_ignore=1 och arp_announce=2 (se
// applyBackends för motivering — förhindrar ARP-flux som annars kan låsa ut
// administratören när WAN/LAN delar L2-segment). Skriver "all"-knapparna; de
// gäller som en logisk ELLER/MAX med per-interface-värdena, så nya kort täcks
// automatiskt.
func setARPHardening() error {
	writes := map[string]string{
		"/proc/sys/net/ipv4/conf/all/arp_ignore":   "1\n",
		"/proc/sys/net/ipv4/conf/all/arp_announce": "2\n",
	}
	for path, val := range writes {
		if err := os.WriteFile(path, []byte(val), 0644); err != nil {
			return fmt.Errorf("kunde inte skriva %s: %w", path, err)
		}
	}
	return nil
}

// ListConfigHistory returnerar de senast bekräftade konfigurationerna som
// finns sparade på brandväggen (se pkg/store/history.go).
func (e *Engine) ListConfigHistory() []store.ConfigHistoryEntry {
	return e.store.ListConfigHistory()
}

// RestoreConfigFromHistory laddar en sparad konfiguration och lägger den som
// KANDIDAT — den appliceras inte här. Administratören trycker sedan
// Applicera som vanligt och får hela Safe Apply-kedjan (validering,
// 30-sekunders bekräftelse, automatisk rollback vid utelåsning). Att
// applicera en gammal konfiguration direkt vore att kringgå precis det
// skydd som finns för att man inte ska låsa ut sig.
func (e *Engine) RestoreConfigFromHistory(id, user string) (*config.Config, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.state == StateUnconfirmed {
		return nil, fmt.Errorf("det finns en obekräftad ändring — bekräfta eller rulla tillbaka den först")
	}

	cfg, err := e.store.LoadHistoricConfig(id)
	if err != nil {
		return nil, err
	}
	// Samma validering som vilken annan kandidatändring som helst: en gammal
	// konfiguration kan referera ett gränssnitt som inte finns kvar.
	if err := e.ValidateCandidate(context.Background(), cfg); err != nil {
		return nil, fmt.Errorf("den sparade konfigurationen är inte giltig mot dagens system: %w", err)
	}
	if err := e.store.SetCandidateConfig(cfg); err != nil {
		return nil, err
	}
	_ = e.store.LogAudit(user, "RESTORE_CONFIG_HISTORY", fmt.Sprintf("Laddade sparad konfiguration %s som kandidat", id))
	return cfg, nil
}

// lanDHCPWarnings varnar för interna gränssnitt som hämtar sin egen adress
// via DHCP. En brandvägg bör ha en fast adress på insidan: klienterna får
// brandväggens IP som gateway och DNS i sina egna DHCP-svar, så ändras
// brandväggens adress när leasen förnyas pekar hela LAN:et fel tills de
// hunnit förnya. Kör kortet dessutom en DHCP-SERVER är läget direkt
// motsägelsefullt — den delar ut en gateway-adress den själv inte äger.
//
// Medvetet en VARNING och inte ett valideringsfel. En färsk installation
// ärver det korten redan är inställda på (se store.adoptSystemAddressing),
// och ligger LAN på DHCP där ska administratören kunna applicera sina
// brandväggsregler och byta till en statisk adress i lugn och ro — inte
// mötas av ett Apply som vägrar gå igenom.
func lanDHCPWarnings(cfg *config.Config) []BackendWarning {
	var out []BackendWarning
	for _, iface := range cfg.Interfaces {
		if !iface.Enabled || iface.AddressType != "dhcp" {
			continue
		}
		if strings.EqualFold(iface.Zone, "WAN") || strings.EqualFold(iface.Zone, "HOST") {
			continue
		}
		label := iface.Name
		if label == "" {
			label = iface.Device
		}
		msg := fmt.Sprintf("Gränssnittet %q (zon %s) hämtar sin adress via DHCP. "+
			"Brandväggens interna kort bör ha en fast adress — klienterna får den som "+
			"gateway och DNS, och pekar fel om den ändras.", label, iface.Zone)
		if iface.DHCP != nil && iface.DHCP.Enabled {
			msg += " Kortet kör dessutom en DHCP-server, som delar ut en gateway-adress brandväggen själv inte äger."
		}
		out = append(out, BackendWarning{Backend: "interfaces", Message: msg})
	}
	return out
}
