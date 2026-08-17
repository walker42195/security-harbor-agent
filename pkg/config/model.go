package config

import "time"

// Config representerar hela brandväggens deklarativa tillstånd.
type Config struct {
	Version    int         `json:"version"`    // Konfigurationsversion
	Revision   int64       `json:"revision"`   // Inkrementeras vid varje commit
	UpdatedAt  time.Time   `json:"updated_at"` // Tidstämpel för senaste ändring
	Interfaces []Interface `json:"interfaces"` // Fysiska nätverkskort & VLANs
	Zones      []Zone      `json:"zones"`      // Zoner (WAN, LAN, SERVERS, IOT, GUEST, VPN)
	Objects    []Object    `json:"objects"`    // Objekt (Hosts, Subnets, IP-listor, GeoIP)
	Services   []Service   `json:"services"`   // Tjänster (HTTP, HTTPS, SSH, Custom ports)
	Policies   []Policy    `json:"policies"`   // Brandväggs- och NAT-regler
	Settings   Settings    `json:"settings"`   // System- och management-inställningar
}

// Interface representerar ett nätverksgränssnitt eller VLAN.
type Interface struct {
	ID          string      `json:"id"`           // t.ex. "eth0", "eth1", "vlan10"
	Device      string      `json:"device"`       // Linux device name, t.ex. "eth0", "eth1.10"
	Parent      string      `json:"parent"`       // För VLAN: föräldra-interface, t.ex. "eth1"
	VLANID      int         `json:"vlan_id"`      // 0 för fysiska, 1-4094 för VLAN
	Zone        string      `json:"zone"`         // Kopplad zon: "WAN", "LAN", "SERVERS", etc.
	Enabled     bool        `json:"enabled"`      // Om gränssnittet är aktivt
	AddressType string      `json:"address_type"` // "static", "dhcp"
	IPv4        string      `json:"ipv4"`         // IP/CIDR t.ex. "192.168.10.1/24"
	Gateway     string      `json:"gateway"`      // Default gateway (främst WAN)
	DNSServers  []string    `json:"dns_servers"`  // Statiska DNS-servrar för gränssnittet, t.ex. ["1.1.1.1", "8.8.8.8"]
	MTU         int         `json:"mtu"`          // MTU (standard 1500)
	DHCP        *DHCPConfig `json:"dhcp,omitempty"`// DHCP Server inställningar för detta interface/VLAN
}

// DHCPConfig innehåller DHCP-serverkonfiguration för ett gränssnitt/VLAN.
type DHCPConfig struct {
	Enabled      bool              `json:"enabled"`
	RangeStart   string            `json:"range_start"`  // t.ex. "192.168.10.100"
	RangeEnd     string            `json:"range_end"`    // t.ex. "192.168.10.250"
	Gateway      string            `json:"gateway"`      // t.ex. "192.168.10.1"
	DNSServers   []string          `json:"dns_servers"`  // t.ex. ["192.168.10.1", "1.1.1.1"]
	LeaseTimeSec int               `json:"lease_time_sec"` // t.ex. 86400 (24h)
	Reservations []DHCPReservation `json:"reservations"` // Statiska MAC -> IP reservationer
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
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Type        ObjectType `json:"type"`
	Values      []string   `json:"values"`      // IP-adresser, CIDR, eller medlems-IDn vid group
	Description string     `json:"description"`
}

// Service representerar en protokoll/port-definition.
type Service struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Protocol    string   `json:"protocol"` // "tcp", "udp", "icmp", "any"
	Ports       []string `json:"ports"`    // t.ex. ["80", "443"], ["53"]
	Description string   `json:"description"`
}

// PolicyAction anger vad brandväggen gör med matchad trafik.
type PolicyAction string

const (
	ActionAccept     PolicyAction = "accept"
	ActionDrop       PolicyAction = "drop"
	ActionReject     PolicyAction = "reject"
	ActionDNAT       PolicyAction = "dnat"       // Port forwarding
	ActionMasquerade PolicyAction = "masquerade" // Outbound NAT
)

// Policy representerar en brandväggs- eller NAT-regel.
type Policy struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Enabled     bool         `json:"enabled"`
	Priority    int          `json:"priority"`      // Lägre nummer = högre prioritet
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
}

// NATConfig innehåller parametrar för Port Forwarding eller SNAT.
type NATConfig struct {
	ExternalPort int    `json:"external_port,omitempty"` // Port på WAN-sida vid DNAT (t.ex. 443)
	InternalIP   string `json:"internal_ip,omitempty"`   // Mål-IP på insidan vid DNAT (t.ex. 192.168.20.10)
	InternalPort int    `json:"internal_port,omitempty"` // Målport på insidan vid DNAT (t.ex. 443)
	Protocol     string `json:"protocol,omitempty"`      // "tcp" eller "udp"
}

// Settings innehåller globala management-inställningar.
type Settings struct {
	HostName             string   `json:"hostname"`
	APIPort              int      `json:"api_port"`               // Standard 8443
	AllowedManagementLAN []string `json:"allowed_management_lan"` // Tillåtna IP-nät för API
	RollbackTimeoutSec   int      `json:"rollback_timeout_sec"`   // Standard 30 sekunder
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
}

// FirewallLogEntry representerar en nekad/blockerad paket-händelse, läst ur
// kärnans logg (kernel/journald) för nftables "log"-regler (se
// pkg/adapter/nftables SH-DENY-*-prefixen).
type FirewallLogEntry struct {
	Timestamp string `json:"timestamp"`
	Chain     string `json:"chain"` // "INPUT" eller "FWD"
	InIface   string `json:"in_iface,omitempty"`
	OutIface  string `json:"out_iface,omitempty"`
	SrcMAC    string `json:"src_mac,omitempty"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	Protocol  string `json:"protocol"`
	SrcPort   int    `json:"src_port,omitempty"`
	DstPort   int    `json:"dst_port,omitempty"`
}
