package config

import "time"

// Config representerar hela brandväggens deklarativa tillstånd.
type Config struct {
	Version      int              `json:"version"`                 // Konfigurationsversion
	Revision     int64            `json:"revision"`                // Inkrementeras vid varje commit
	UpdatedAt    time.Time        `json:"updated_at"`              // Tidstämpel för senaste ändring
	Interfaces   []Interface      `json:"interfaces"`              // Fysiska nätverkskort & VLANs
	Zones        []Zone           `json:"zones"`                   // Zoner (WAN, LAN, SERVERS, IOT, GUEST, VPN)
	Objects      []Object         `json:"objects"`                 // Objekt (Hosts, Subnets, IP-listor, GeoIP)
	Services     []Service        `json:"services"`                // Tjänster (HTTP, HTTPS, SSH, Custom ports)
	Policies     []Policy         `json:"policies"`                // Brandväggs- och NAT-regler
	Settings     Settings         `json:"settings"`                // System- och management-inställningar
	WireGuard    *WireGuardConfig `json:"wireguard,omitempty"`     // VPN-serverkonfiguration (Fas 3)
	OpenVPN      *OpenVPNConfig   `json:"openvpn,omitempty"`       // VPN-serverkonfiguration (Fas 4)
	DNS          *DNSConfig       `json:"dns,omitempty"`           // DNS-resolver & domänfiltrering (Fas 6)
	Syslog       *SyslogConfig    `json:"syslog,omitempty"`        // Centraliserad logg-vidarebefordran (Fas 8)
	IDS          *IDSConfig       `json:"ids,omitempty"`           // Suricata IDS (Fas 9)
	SNIRoutes    []SNIRoute       `json:"sni_routes,omitempty"`    // Namnbaserad routning (SNI passthrough via HAProxy)
	StaticRoutes []StaticRoute    `json:"static_routes,omitempty"` // Statiska IP-rutter (t.ex. ett internt nät nåbart via en annan gateway)
}

// StaticRoute representerar en statisk IP-rutt (`ip route add <Network> via
// <Gateway> [dev <Interface>]`) — för nät som inte nås via brandväggens
// vanliga default-rutt utan kräver en specifik gateway, t.ex. ett internt
// nät bakom en annan router på LAN-sidan. Skiljer sig från Policy: en Policy
// styr om trafik TILLÅTS, en StaticRoute styr VART den skickas för att nå
// dit överhuvudtaget — brandväggen behöver båda för att nå ett sådant nät
// (utan rutten hittar den aldrig dit; utan en Allow-policy stoppas trafiken
// ändå av Default Deny).
type StaticRoute struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Network är målnätet i CIDR-form, t.ex. "192.168.113.0/24". En enskild
	// host går också bra som /32.
	Network string `json:"network"`
	// Gateway är IP-adressen trafik till Network ska skickas via.
	Gateway string `json:"gateway"`
	// Interface är valfritt gränssnittsnamn (Interface.Device, t.ex.
	// "ens19") — anges bara om gatewayen är tvetydig (nås via flera
	// gränssnitt) eller för att tvinga rutten via ett specifikt kort. Tomt
	// värde = låt kärnan välja gränssnitt utifrån gatewayens adress, vilket
	// räcker i de allra flesta fall.
	Interface   string `json:"interface,omitempty"`
	Description string `json:"description"`
}

// IDSConfig styr Suricata i passivt IDS-läge (af-packet, INTE inline/
// NFQUEUE-läge — se pkg/adapter/suricata). AutoBlock lägger automatiskt
// käll-IP:n från larm på/under AutoBlockSeverity till ett REDAN
// EXISTERANDE Object (AutoBlockObjectID, t.ex. ett vanligt "iplist"-objekt
// som användaren skapat i Objekt-vyn) — samma "skriv om Values direkt i
// running"-mönster som hotlist-uppdatering (Fas 5) använder. Agenten
// skapar ALDRIG objektet eller en policy automatiskt: blockering kräver
// fortfarande att användaren själv har en Deny-policy som refererar
// objektet — detta bygger bara upp/underhåller listans innehåll.
type IDSConfig struct {
	Enabled           bool   `json:"enabled"`
	Interface         string `json:"interface"`
	AutoBlock         bool   `json:"auto_block"`
	AutoBlockObjectID string `json:"auto_block_object_id,omitempty"`
	AutoBlockSeverity int    `json:"auto_block_severity"` // t.ex. 2 — bara larm med severity <= detta värde triggar block (1=högst allvarlighetsgrad)
}

// SyslogConfig styr vidarebefordran av brandväggens systemloggar (bl.a.
// SH-ACCEPT/SH-DENY-raderna från nftables) till en central syslog-mottagare
// på nätet, utöver den lokala journald-lagringen som alltid finns kvar.
type SyslogConfig struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "udp" eller "tcp"
}

// DNSConfig styr brandväggens lokala DNS-resolver (Fas 6). Den faktiska
// blocklistan med domäner lagras ALDRIG i denna struct/JSON-configen (en
// domänblocklista kan innehålla hundratusentals poster) — bara käll-
// metadata. Agenten (pkg/threatfeed) cachar den nedladdade domänlistan
// till en egen fil på disk (se pkg/adapter/dns), som Unbound sedan
// inkluderar direkt.
type DNSConfig struct {
	Enabled         bool     `json:"enabled"`
	UpstreamServers []string `json:"upstream_servers"` // t.ex. ["1.1.1.1", "1.0.0.1"]
	DoTEnabled      bool     `json:"dot_enabled"`      // DNS-over-TLS mot upstream-servrarna
	DoTHostname     string   `json:"dot_hostname"`     // TLS-hostnamn för DoT-verifiering, t.ex. "cloudflare-dns.com"

	// Recursive: om sant görs INGEN forward-zone alls — Unbound slår då
	// själv mot rot-servrarna (fullständig rekursiv upplösning) istället
	// för att vidarebefordra till UpstreamServers. UpstreamServers/DoT-
	// fälten ignoreras i så fall.
	Recursive bool `json:"recursive"`

	// Blocklists tillåter FLERA samtidigt aktiva domänblocklistor (t.ex.
	// StevenBlack hosts + en egen anpassad URL parallellt) — se
	// pkg/adapter/dns.GenerateBlocklistConfig som slår ihop dem alla.
	Blocklists []DNSBlocklistSource `json:"blocklists,omitempty"`

	CustomBlockedDomains []string `json:"custom_blocked_domains,omitempty"` // Manuellt inmatade, alltid blockerade
	CustomAllowedDomains []string `json:"custom_allowed_domains,omitempty"` // Undantag från blocklistan (allowlist)

	// StaticRecords är manuellt inmatade DNS-poster (A-poster) i den
	// lokala zonen, t.ex. en server med fast IP som ska nås via namn.
	StaticRecords []DNSStaticRecord `json:"static_records,omitempty"`

	// LocalDomain är suffixet DHCP-tilldelade värdnamn registreras under,
	// t.ex. "lan" ger "skrivare.lan". Töm/"" stänger inte av registrering,
	// men ger namn utan suffix.
	LocalDomain string `json:"local_domain,omitempty"`

	// DHCPHostnameRegistration styr om enheter som får en DHCP-lease
	// (och skickade ett värdnamn i sin DHCP-förfrågan) automatiskt
	// registreras i den lokala DNS-zonen. Se pkg/adapter/dhcp.ParseLeases.
	DHCPHostnameRegistration bool `json:"dhcp_hostname_registration"`
}

// DNSStaticRecord är en manuellt inmatad A-post i den lokala DNS-zonen.
type DNSStaticRecord struct {
	Hostname string `json:"hostname"` // t.ex. "server1" eller "server1.lan"
	IP       string `json:"ip"`
}

// DNSBlocklistSource beskriver EN automatiskt uppdaterad domänblocklista
// (Fas 6). Precis som ObjectSource (Fas 5) lagras den faktiska domänlistan
// ALDRIG i denna struct — bara källmetadata/status. Agenten cachar den
// nedladdade listan till en egen fil på disk, nyckad på ID (se
// Store.SaveDNSBlocklistDomains).
type DNSBlocklistSource struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Enabled      bool   `json:"enabled"`
	Kind         string `json:"kind"`          // "stevenblack_hosts", "custom_domain_url"
	URL          string `json:"url,omitempty"` // Endast för kind="custom_domain_url"
	RefreshHours int    `json:"refresh_hours"`
	LastUpdated  string `json:"last_updated,omitempty"`
	LastError    string `json:"last_error,omitempty"`
	EntryCount   int    `json:"entry_count,omitempty"`
}

// WireGuardConfig representerar server-sidans WireGuard-inställningar (wg0).
// Servern har en egen keypair (privata nyckeln lagras krypterad, se
// Store.EnsureWireGuardServerKeys — den skickas ALDRIG över API:t eller
// sparas i denna struct). Endast klienternas publika nycklar lagras här.
type WireGuardConfig struct {
	Enabled         bool            `json:"enabled"`
	ListenPort      int             `json:"listen_port"`                 // t.ex. 51820
	Address         string          `json:"address"`                     // Serverns IP i VPN-nätet, t.ex. "10.66.66.1/24"
	Endpoint        string          `json:"endpoint"`                    // Publik host/IP klienter ansluter mot, t.ex. "vpn.example.se"
	ServerPublicKey string          `json:"server_public_key,omitempty"` // Fylls i dynamiskt av agenten vid läsning, aldrig skriven av klienten
	Peers           []WireGuardPeer `json:"peers"`
}

// WireGuardPeer representerar en tillåten VPN-klient. Endast den publika
// nyckeln lagras server-side — klientens privata nyckel genereras och visas
// en gång i GUI:t (se /api/v1/vpn/wireguard/generate-peer-keys) och sparas
// aldrig på brandväggen.
type WireGuardPeer struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	AllowedIPs string `json:"allowed_ips"` // t.ex. "10.66.66.2/32"
	Enabled    bool   `json:"enabled"`
}

// OpenVPNConfig representerar server-sidans OpenVPN-inställningar (Fas 4).
// CA:ns och serverns privata nycklar lagras ALDRIG i denna struct — de
// hålls krypterade av Store (EnsureOpenVPNCA/EnsureOpenVPNServerCert) på
// samma sätt som WireGuard-serverns nyckelpar (Fas 3). CACertPEM är
// public och skickas till klienter/GUI utan risk.
type OpenVPNConfig struct {
	Enabled    bool            `json:"enabled"`
	ListenPort int             `json:"listen_port"`           // t.ex. 1194
	Protocol   string          `json:"protocol"`              // "udp" eller "tcp"
	Address    string          `json:"address"`               // VPN-subnät, t.ex. "10.77.77.0/24"
	Endpoint   string          `json:"endpoint"`              // Publik host/IP klienter ansluter mot
	CACertPEM  string          `json:"ca_cert_pem,omitempty"` // Fylls i dynamiskt av agenten, aldrig skriven av klienten
	Clients    []OpenVPNClient `json:"clients"`
}

// OpenVPNClient representerar en utfärdad klientprofil. Klientens privata
// nyckel visas en gång vid utfärdande (se /api/v1/vpn/openvpn/generate-client)
// och sparas aldrig på brandväggen — bara det publika certifikatet/serienumret
// (för spårbarhet och spärrning via CRL) lagras här.
type OpenVPNClient struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	Revoked    bool   `json:"revoked"`
	CertSerial string `json:"cert_serial,omitempty"`
	CertPEM    string `json:"cert_pem,omitempty"`
	IssuedAt   string `json:"issued_at,omitempty"`
}

// Interface representerar ett nätverksgränssnitt eller VLAN.
type Interface struct {
	ID          string   `json:"id"`           // t.ex. "eth0", "eth1", "vlan10"
	Name        string   `json:"name"`         // Läsbart visningsnamn satt av användaren (valfritt, faller tillbaka på Device i GUI:t)
	Device      string   `json:"device"`       // Linux device name, t.ex. "eth0", "eth1.10"
	Parent      string   `json:"parent"`       // För VLAN: föräldra-interface, t.ex. "eth1"
	VLANID      int      `json:"vlan_id"`      // 0 för fysiska, 1-4094 för VLAN
	Zone        string   `json:"zone"`         // Kopplad zon: "WAN", "LAN", "SERVERS", etc.
	Enabled     bool     `json:"enabled"`      // Om gränssnittet är aktivt
	AddressType string   `json:"address_type"` // "static", "dhcp"
	IPv4        string   `json:"ipv4"`         // IP/CIDR t.ex. "192.168.10.1/24"
	Gateway     string   `json:"gateway"`      // Default gateway (främst WAN)
	DNSServers  []string `json:"dns_servers"`  // Statiska DNS-servrar för gränssnittet, t.ex. ["1.1.1.1", "8.8.8.8"]
	MTU         int      `json:"mtu"`          // MTU (standard 1500)
	// MACAddress sätter kortets MAC manuellt ("MAC-kloning"). Främst för WAN:
	// många ISP:er binder abonnemanget till MAC-adressen på den router som
	// först registrerades, och byter man hårdvara får man ingen DHCP-lease
	// förrän den gamla adressen klonas. Tomt = rör inte kortets MAC (behåll
	// den brända adressen).
	MACAddress string      `json:"mac_address,omitempty"`
	DHCP       *DHCPConfig `json:"dhcp,omitempty"` // DHCP Server inställningar för detta interface/VLAN
}

// DHCPConfig innehåller DHCP-serverkonfiguration för ett gränssnitt/VLAN.
type DHCPConfig struct {
	Enabled      bool              `json:"enabled"`
	RangeStart   string            `json:"range_start"`    // t.ex. "192.168.10.100"
	RangeEnd     string            `json:"range_end"`      // t.ex. "192.168.10.250"
	Gateway      string            `json:"gateway"`        // t.ex. "192.168.10.1"
	DNSServers   []string          `json:"dns_servers"`    // t.ex. ["192.168.10.1", "1.1.1.1"]
	LeaseTimeSec int               `json:"lease_time_sec"` // t.ex. 86400 (24h)
	Reservations []DHCPReservation `json:"reservations"`   // Statiska MAC -> IP reservationer
}

// DHCPReservation representerar en reserverad IP för en viss MAC-adress.
type DHCPReservation struct {
	Hostname string `json:"hostname"` // t.ex. "Camera-IoT"
	MAC      string `json:"mac"`      // t.ex. "AA:BB:CC:11:22:33"
	IP       string `json:"ip"`       // t.ex. "192.168.10.50"
}

// Zone representerar en säkerhetszon.
type Zone struct {
	Name        string `json:"name"`        // t.ex. "WAN", "LAN", "SERVERS", "IOT", "VPN"
	Description string `json:"description"` // Beskrivning
}

// ObjectType för brandväggsobjekt.
type ObjectType string

const (
	ObjectTypeHost    ObjectType = "host"
	ObjectTypeNetwork ObjectType = "network"
	ObjectTypeGroup   ObjectType = "group"
	ObjectTypeIPList  ObjectType = "iplist"
	ObjectTypeGeoIP   ObjectType = "geoip"
)

// Object representerar ett återanvändbart nätverks- eller host-objekt.
type Object struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Type        ObjectType    `json:"type"`
	Values      []string      `json:"values"` // IP-adresser, CIDR, eller medlems-IDn vid group
	Description string        `json:"description"`
	Source      *ObjectSource `json:"source,omitempty"` // Fas 5: gör Values automatiskt uppdaterade från en extern källa
}

// ObjectSource beskriver en extern, automatiskt uppdaterad källa för ett
// iplist- eller geoip-objekts Values (Fas 5 — Hot-listor & GeoIP). Agenten
// (pkg/threatfeed) hämtar och skriver om Values med jämna mellanrum; GUI:t
// visar bara status (LastUpdated/LastError/EntryCount) och kan trigga en
// omedelbar uppdatering.
type ObjectSource struct {
	Kind         string `json:"kind"`                   // "spamhaus_drop", "spamhaus_edrop", "tor_exit_nodes", "custom_url", "geoip_country"
	URL          string `json:"url,omitempty"`          // Endast för kind="custom_url"
	CountryCode  string `json:"country_code,omitempty"` // Endast för kind="geoip_country", ISO 3166-1 alpha-2 (t.ex. "RU")
	RefreshHours int    `json:"refresh_hours"`          // Hur ofta listan uppdateras, standard 24
	LastUpdated  string `json:"last_updated,omitempty"`
	LastError    string `json:"last_error,omitempty"`
	EntryCount   int    `json:"entry_count,omitempty"`
}

// Service representerar en protokoll/port-definition.
type Service struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Protocol    string   `json:"protocol"` // "tcp", "udp", "icmp", "any", eller "group"
	Ports       []string `json:"ports"`    // t.ex. ["80", "443"], ["53"]
	Description string   `json:"description"`
	// Members innehåller andra Service-ID:n och används bara när
	// Protocol == "group" (Fas 7 — Service Groups). En Policy som
	// refererar till en grupp matchar unionen av alla medlemmarnas
	// protokoll/portar.
	Members []string `json:"members,omitempty"`
}

// PolicyAction anger vad brandväggen gör med matchad trafik.
type PolicyAction string

const (
	ActionAccept     PolicyAction = "accept"
	ActionDrop       PolicyAction = "drop"
	ActionReject     PolicyAction = "reject"
	ActionDNAT       PolicyAction = "dnat"       // Port forwarding (eller 1:1 NAT om NAT.ExternalIP är satt)
	ActionMasquerade PolicyAction = "masquerade" // Outbound NAT
	ActionSNAT       PolicyAction = "snat"       // Fas 7: Avancerad NAT — SNAT-override istället för default masquerade
)

// Policy representerar en brandväggs- eller NAT-regel.
type Policy struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Priority är ENBART ett informativt fält. Den faktiska
	// matchningsordningen i nftables bestäms av ordningen i Config.Policies
	// (första matchande regel vinner) — se nftables-adapterns rendering och
	// _movePolicy i GUI:ts policies_screen.dart, som därför flyttar posten i
	// listan i stället för att ändra ett nummer. Kommentaren sa tidigare
	// "Lägre nummer = högre prioritet", vilket var direkt missvisande:
	// ingen kod har någonsin sorterat på fältet.
	Priority    int          `json:"priority"`
	SourceZone  string       `json:"source_zone"`   // Zon eller "ANY"
	DestZone    string       `json:"dest_zone"`     // Zon eller "ANY"
	SourceObj   string       `json:"source_obj"`    // Objekt-ID eller "ANY"
	DestObj     string       `json:"dest_obj"`      // Objekt-ID eller "ANY"
	Service     string       `json:"service"`       // Service-ID eller "ANY"
	Action      PolicyAction `json:"action"`        // accept, drop, reject, dnat, masquerade
	NAT         *NATConfig   `json:"nat,omitempty"` // Ev. NAT-parametrar vid DNAT/SNAT
	Logging     bool         `json:"logging"`       // Om trafiken ska loggas
	Description string       `json:"description"`
	Local       bool         `json:"local,omitempty"`    // Om true gäller policyn åtkomst till brandväggen själv (INPUT-kedjan, t.ex. SSH/Management API) istället för vidarebefordrad trafik (FORWARD-kedjan).
	Critical    bool         `json:"critical,omitempty"` // Om true måste GUI:t be om en uttrycklig bekräftelse innan policyn inaktiveras eller tas bort, eftersom den styr åtkomst som kan behövas för att administrera brandväggen.
	// Protected är ett strängare skydd än Critical: en sådan policy går
	// inte att inaktivera eller ta bort ens med bekräftelse — bara GUI:t
	// (och validatePolicies vid Apply, som stoppar det oavsett vad klienten
	// skickar in) hindrar det. Används för Management API-åtkomsten
	// (MgmtAPIPolicyID), där en avstängning skulle låsa ute administratören
	// ur webb-GUI:t helt utan text-baserad reservväg som SSH har.
	Protected bool `json:"protected,omitempty"`
	// Schedule gör policyn tidsstyrd (Fas 7 — Schema/tidsbaserade regler).
	// nil/Enabled=false betyder att policyn gäller alltid, som tidigare.
	Schedule *PolicySchedule `json:"schedule,omitempty"`
}

// MgmtAPIPolicyID är ID:t för den skyddade (Protected) Local-policyn som
// styr åtkomst till Management API (GUI:t) på LAN/VLAN. Den genereras
// speciellt av nftables-adaptern (som läser porten från Settings.APIPort,
// inte från Policy.Service — se resolveMgmtAPIPort) och kontrolleras
// explicit av validatePolicies vid Apply.
const MgmtAPIPolicyID = "sys-mgmt-api-lan"

// PolicySchedule begränsar när en Policy är aktiv, matchat i nftables via
// `meta day`/`meta hour` (Fas 7). Days är en lista av engelska veckodags-
// namn ("Monday".."Sunday", som nftables kräver) — tom lista betyder alla
// dagar. StartTime/EndTime är "HH:MM" i brandväggens lokala tid.
type PolicySchedule struct {
	Enabled   bool     `json:"enabled"`
	Days      []string `json:"days,omitempty"` // t.ex. ["Monday","Tuesday","Wednesday","Thursday","Friday"]
	StartTime string   `json:"start_time"`     // "HH:MM", t.ex. "08:00"
	EndTime   string   `json:"end_time"`       // "HH:MM", t.ex. "17:00"
}

// NATConfig innehåller parametrar för Port Forwarding, 1:1 NAT eller SNAT.
type NATConfig struct {
	ExternalPort int    `json:"external_port,omitempty"` // Port på WAN-sida vid DNAT (t.ex. 443)
	InternalIP   string `json:"internal_ip,omitempty"`   // Mål-IP på insidan vid DNAT (t.ex. 192.168.20.10)
	InternalPort int    `json:"internal_port,omitempty"` // Målport på insidan vid DNAT (t.ex. 443)
	Protocol     string `json:"protocol,omitempty"`      // "tcp" eller "udp"
	// ExternalIP (Fas 7 — Avancerad NAT):
	//  - Vid Action=dnat: om satt görs 1:1 NAT (statisk NAT) mot just
	//    denna WAN-IP istället för att matcha alla WAN-interfacets IP:n.
	//  - Vid Action=snat: den IP-adress utgående trafik ska SNAT:as till,
	//    istället för standard-masquerade (t.ex. en sekundär WAN-IP).
	ExternalIP string `json:"external_ip,omitempty"`
}

// Settings innehåller globala management-inställningar.
type Settings struct {
	HostName             string   `json:"hostname"`
	APIPort              int      `json:"api_port"`               // Standard 8443
	AllowedManagementLAN []string `json:"allowed_management_lan"` // Tillåtna IP-nät för API
	RollbackTimeoutSec   int      `json:"rollback_timeout_sec"`   // Standard 30 sekunder

	// Mode styr agentens driftläge (Fas 13): "" eller "gateway" (standard,
	// oförändrat beteende — router/appliance med FORWARD/NAT/DHCP) eller
	// "host" (enkelkorts-/värddator-läge — bara INPUT/OUTPUT-hårdning,
	// ingen FORWARD/NAT/DHCP/IDS, inget WAN/LAN-zonkrav). Se
	// pkg/adapter/nftables.RenderJSON och Engine.applyBackends.
	Mode string `json:"mode,omitempty"`

	// Timezone är serverns tidszon i IANA-format ("Europe/Stockholm").
	// Tomt = rör inte systemets nuvarande inställning.
	//
	// Tidszonen syns i allt servern själv tidsstämplar — journald (och därmed
	// trafikloggen) skriver lokal tid med offset. Stod servern kvar på UTC
	// medan administratören satt i CEST blev loggen två timmar fel, utan att
	// något var trasigt (rapporterat 2026-08-26).
	Timezone string `json:"timezone,omitempty"`
}

const (
	ModeGateway = "gateway"
	ModeHost    = "host"
)

// IsHostMode returnerar true om configen är i enkelkorts-/värddator-läge.
// Tomt Mode-fält (befintliga/gamla installationer) räknas som gateway-läge
// — bakåtkompatibelt default.
func (c *Config) IsHostMode() bool {
	return c.Settings.Mode == ModeHost
}

// SNIRoute är EN lyssnarport (t.ex. 443) som via SNI-namnet i TLS
// ClientHello dirigerar krypterad trafik vidare till OLIKA interna servrar
// UTAN att terminera TLS (HAProxy mode tcp, req.ssl_sni — passthrough).
// Certifikaten stannar därmed på de interna servrarna och änd-till-änd-
// krypteringen bevaras. Varje aktiv rutt blir en egen HAProxy-frontend samt
// en INPUT-accept-regel på sin ListenPort (HAProxy lyssnar på brandväggen
// själv — det är alltså INTE DNAT/prerouting).
type SNIRoute struct {
	ID         string `json:"id"`
	Name       string `json:"name"` // Läsbart namn i GUI:t
	Enabled    bool   `json:"enabled"`
	ListenPort int    `json:"listen_port"` // valfri port; MÅSTE vara unik per aktiv rutt (två frontends kan inte binda samma port)
	// ExternalIP (valfritt): binder frontend på en specifik WAN-IP i stället
	// för alla adresser. Tomt = bind på :ListenPort (alla adresser).
	ExternalIP string `json:"external_ip,omitempty"`
	// Backends: varje post är ETT mål med ett eller flera SNI-namn.
	Backends []SNIBackend `json:"backends"`
	// DefaultBackend: fallback för trafik UTAN matchande SNI (inklusive
	// SNI-lös trafik som OpenVPN). nil = sådan trafik släpps. Kan peka på en
	// lokal brandväggstjänst (LocalService).
	DefaultBackend *SNIBackend `json:"default_backend,omitempty"`
}

// SNIBackend är ETT vidarebefordringsmål: antingen en intern server
// (TargetIP:TargetPort) ELLER en lokal brandväggstjänst (LocalService).
// De två är ömsesidigt uteslutande.
type SNIBackend struct {
	// Hostnames: ett eller flera SNI-namn som riktas hit. Wildcard
	// "*.exempel.se" stöds. Tom lista bara för DefaultBackend (matchar allt
	// övrigt).
	Hostnames []string `json:"hostnames,omitempty"`
	// Målalternativ (a): intern server.
	TargetIP   string `json:"target_ip,omitempty"`
	TargetPort int    `json:"target_port,omitempty"`
	// Målalternativ (b): lokal brandväggstjänst. Just nu bara "openvpn".
	LocalService string `json:"local_service,omitempty"`
}

const (
	// LocalServiceOpenVPN pekar en SNI-backend mot brandväggens egen
	// OpenVPN-daemon (för port-delning på t.ex. 443).
	LocalServiceOpenVPN = "openvpn"
	// OpenVPNLoopbackPort är porten OpenVPN binder på 127.0.0.1 när den
	// frontas av en SNI-rutt (i stället för sin publika ListenPort — HAProxy
	// äger då den publika porten).
	OpenVPNLoopbackPort = 11194
)

// OpenVPNFrontedBySNI returnerar true + den publika lyssnarporten om någon
// AKTIV SNI-rutt frontar den lokala OpenVPN-tjänsten (som backend eller
// default). Då binder OpenVPN loopback-TCP i stället för publik WAN-port,
// och nftables-adaptern öppnar INTE OpenVPN:s egen ListenPort på WAN.
// Delas av openvpn-, nftables- och haproxy-adaptrarna så ingen state
// dupliceras.
func (c *Config) OpenVPNFrontedBySNI() (fronted bool, publicPort int) {
	isOVPN := func(b *SNIBackend) bool {
		return b != nil && b.LocalService == LocalServiceOpenVPN
	}
	for _, r := range c.SNIRoutes {
		if !r.Enabled {
			continue
		}
		for i := range r.Backends {
			if isOVPN(&r.Backends[i]) {
				return true, r.ListenPort
			}
		}
		if isOVPN(r.DefaultBackend) {
			return true, r.ListenPort
		}
	}
	return false, 0
}

// ConntrackEntry representerar en aktiv stateful nätverksanslutning för diagnostik.
type ConntrackEntry struct {
	Protocol string `json:"protocol"`
	SrcIP    string `json:"src_ip"`
	SrcPort  int    `json:"src_port"`
	DstIP    string `json:"dst_ip"`
	DstPort  int    `json:"dst_port"`
	State    string `json:"state"`
	SrcMAC   string `json:"src_mac,omitempty"` // Slås upp via ARP-tabellen, LAN-sidan
	// DstMAC slås upp på samma sätt som SrcMAC (via ARP-tabellen) och är
	// bara tillgänglig när målet är en direktansluten LAN-enhet — för
	// WAN-mål finns ingen lokal ARP-post och fältet blir tomt.
	DstMAC string `json:"dst_mac,omitempty"`
}

// FirewallLogEntry representerar EN loggad paket-händelse (både tillåten
// OCH nekad — se Action) läst ur kärnans logg (kernel/journald) för
// nftables "log"-regler (se pkg/adapter/nftables SH-ACCEPT-/SH-DENY-*-
// prefixen). Namnet på den policy som fattade beslutet ingår i själva
// log-prefixet och plockas ut här (PolicyName) — så GUI:t kan visa VILKEN
// regel som tillät/nekade trafiken, inte bara att den gjorde det.
type FirewallLogEntry struct {
	Timestamp  string `json:"timestamp"`
	Action     string `json:"action"` // "accept" eller "deny"
	Chain      string `json:"chain"`  // "INPUT" eller "FWD"
	PolicyName string `json:"policy_name,omitempty"`
	InIface    string `json:"in_iface,omitempty"`
	OutIface   string `json:"out_iface,omitempty"`
	SrcMAC     string `json:"src_mac,omitempty"`
	DstMAC     string `json:"dst_mac,omitempty"`
	SrcIP      string `json:"src_ip"`
	DstIP      string `json:"dst_ip"`
	Protocol   string `json:"protocol"`
	SrcPort    int    `json:"src_port,omitempty"`
	DstPort    int    `json:"dst_port,omitempty"`
}

// SecurityEvent representerar ett larm från Suricata (Fas 9 — IDS/IPS),
// utplockat ur eve.json. Precis som FirewallLogEntry lagras dessa aldrig i
// den deklarativa configen — de läses bara ut vid varje förfrågan (se
// pkg/adapter/suricata.ReadRecentAlerts).
type SecurityEvent struct {
	Timestamp string `json:"timestamp"`
	Severity  int    `json:"severity"` // 1 (högst) - 3 (lägst), Suricatas egen skala
	Signature string `json:"signature"`
	Category  string `json:"category,omitempty"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port,omitempty"`
	DstIP     string `json:"dst_ip"`
	DstPort   int    `json:"dst_port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
}
