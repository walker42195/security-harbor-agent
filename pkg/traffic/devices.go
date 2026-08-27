package traffic

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Device är en enhet på nätet, sammanslagen ur flera källor:
// grannbordet (IP <-> MAC), DHCP-utlåningar (MAC -> värdnamn) och
// gränssnittets zon ur konfigurationen.
type Device struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	Vendor    string `json:"vendor,omitempty"`
	Interface string `json:"interface,omitempty"`
	Zone      string `json:"zone,omitempty"`
	// Online speglar grannbordets tillstånd. STALE betyder "vi har sett den,
	// men inte nyligen" och räknas som online — annars hade varje enhet som
	// inte skickat något de senaste sekunderna blinkat till offline.
	Online bool `json:"online"`
	// RandomizedMAC är satt när MAC-adressens lokalt-administrerade bit är
	// satt. Det är nästan alltid en modern mobil eller laptop med
	// integritetsskydd påslaget. Presenteras som en upplysning, aldrig som
	// ett påstående om anslutningstyp — brandväggen kan inte se skillnad på
	// wifi och kabel.
	RandomizedMAC bool `json:"randomized_mac"`
	// FirstSeen är första gången agenten såg adressen. Nya enheter på ett nät
	// är säkerhetsinformation, inte pynt.
	FirstSeen int64 `json:"first_seen,omitempty"`
	LastSeen  int64 `json:"last_seen,omitempty"`
}

// zoneLookup mappar gränssnittsnamn till zon.
type zoneLookup func(device string) string

// Inventory håller enhetsregistret och minns när varje MAC sågs första gången.
type Inventory struct {
	mu        sync.RWMutex
	firstSeen map[string]int64 // MAC (eller IP om MAC saknas) -> unix
	path      string

	ouiOnce sync.Once
	oui     map[string]string
}

func NewInventory(statePath string) *Inventory {
	return &Inventory{firstSeen: map[string]int64{}, path: statePath}
}

type neighEntry struct {
	Dst    string   `json:"dst"`
	Dev    string   `json:"dev"`
	LLAddr string   `json:"lladdr"`
	State  []string `json:"state"`
}

// Scan bygger enhetslistan.
//
// staticNames är manuellt registrerade DNS-poster, nyckel IP. De har FÖRETRÄDE
// framför DHCP-utlåningens värdnamn: en post som någon skrivit in för hand är
// ett medvetet val, medan lease-namnet är vad klienten själv råkade skicka.
// Utan dem saknade manuellt registrerade värdar namn helt i vyn, eftersom
// utlåningarna är nycklade på MAC och de statiska posterna på IP.
func (inv *Inventory) Scan(ctx context.Context, leasePath string, staticNames map[string]string, zoneOf zoneLookup) []Device {
	now := time.Now().Unix()
	leases := readLeases(leasePath)

	out, err := exec.CommandContext(ctx, "ip", "-j", "neigh", "show").Output()
	if err != nil {
		return nil
	}
	var entries []neighEntry
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil
	}

	inv.mu.Lock()
	defer inv.mu.Unlock()

	devices := make([]Device, 0, len(entries))
	for _, e := range entries {
		if e.LLAddr == "" || e.Dst == "" {
			continue // ingen MAC = inget vi kan identifiera
		}
		zone := ""
		if zoneOf != nil {
			zone = zoneOf(e.Dev)
		}
		// WAN-sidans granne är operatörens router, inte en enhet på nätet.
		if strings.EqualFold(zone, "WAN") {
			continue
		}

		mac := strings.ToLower(e.LLAddr)
		key := mac
		if _, ok := inv.firstSeen[key]; !ok {
			inv.firstSeen[key] = now
		}

		d := Device{
			IP:            e.Dst,
			MAC:           mac,
			Hostname:      hostnameFor(e.Dst, mac, staticNames, leases),
			Vendor:        inv.vendorOf(mac),
			Interface:     e.Dev,
			Zone:          zone,
			Online:        isOnline(e.State),
			RandomizedMAC: isRandomizedMAC(mac),
			FirstSeen:     inv.firstSeen[key],
			LastSeen:      now,
		}
		devices = append(devices, d)
	}
	return devices
}

// isOnline: FAILED och INCOMPLETE betyder att adressen inte svarar.
func isOnline(states []string) bool {
	for _, s := range states {
		switch strings.ToUpper(s) {
		case "FAILED", "INCOMPLETE", "NONE":
			return false
		}
	}
	return len(states) > 0
}

// isRandomizedMAC läser den lokalt-administrerade biten i första oktetten.
func isRandomizedMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	b, err := strconv.ParseUint(mac[:2], 16, 8)
	if err != nil {
		return false
	}
	return b&0x02 != 0
}

// readLeases läser Keas lease-fil och returnerar MAC -> värdnamn.
func readLeases(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 2 {
		return out
	}
	// Kolumnordning enligt Keas header: address,hwaddr,...,hostname,state
	idx := map[string]int{}
	for i, name := range rows[0] {
		idx[strings.TrimSpace(name)] = i
	}
	macCol, hostCol := idx["hwaddr"], idx["hostname"]
	if macCol == 0 && hostCol == 0 {
		return out
	}
	for _, row := range rows[1:] {
		if macCol >= len(row) || hostCol >= len(row) {
			continue
		}
		host := strings.TrimSpace(row[hostCol])
		if host == "" {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(row[macCol]))] = host
	}
	return out
}

// ouiPaths är där ieee-data-paketet lägger tillverkarregistret. Saknas det
// visas ingen tillverkare — det är en bekvämlighet, inte ett krav.
var ouiPaths = []string{
	"/usr/share/ieee-data/oui.txt",
	"/var/lib/ieee-data/oui.txt",
}

func (inv *Inventory) vendorOf(mac string) string {
	inv.ouiOnce.Do(inv.loadOUI)
	if len(mac) < 8 {
		return ""
	}
	prefix := strings.ToUpper(strings.ReplaceAll(mac[:8], ":", "-"))
	return inv.oui[prefix]
}

// loadOUI läser registret EN gång. Filen är ~5,8 MB text men bara
// prefix + namn behålls (~30 000 poster, ett par MB) — och den läses aldrig
// om, till skillnad från en genomsökning per uppdatering.
func (inv *Inventory) loadOUI() {
	inv.oui = map[string]string{}
	for _, p := range ouiPaths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			// Format: "00-00-00   (hex)\t\tXEROX CORPORATION"
			i := strings.Index(line, "(hex)")
			if i < 0 {
				continue
			}
			prefix := strings.ToUpper(strings.TrimSpace(line[:i]))
			vendor := strings.TrimSpace(line[i+len("(hex)"):])
			if len(prefix) == 8 && vendor != "" {
				inv.oui[prefix] = vendor
			}
		}
		f.Close()
		if len(inv.oui) > 0 {
			return
		}
	}
}

// SaveFirstSeen persisterar förstagångsdatumen. Utan det skulle varje enhet
// se ut som ny efter en omstart, och "ny enhet"-signalen bli meningslös.
func (inv *Inventory) SaveFirstSeen() error {
	inv.mu.RLock()
	data, err := json.Marshal(inv.firstSeen)
	inv.mu.RUnlock()
	if err != nil {
		return err
	}
	tmp := inv.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, inv.path)
}

func (inv *Inventory) LoadFirstSeen() {
	data, err := os.ReadFile(inv.path)
	if err != nil {
		return
	}
	var m map[string]int64
	if err := json.Unmarshal(data, &m); err != nil {
		return
	}
	inv.mu.Lock()
	inv.firstSeen = m
	inv.mu.Unlock()
}

// hostnameFor väljer namn i ordningen: manuell DNS-post, därefter DHCP-
// utlåningens värdnamn. Tom sträng om ingendera finns — då visar GUI:t
// IP-adressen i stället.
func hostnameFor(ip, mac string, staticNames, leases map[string]string) string {
	if n := staticNames[ip]; n != "" {
		return n
	}
	return leases[mac]
}
