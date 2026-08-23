package store

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/wireguard"
	"github.com/walker42195/security-harbor-agent/pkg/config"
	"github.com/walker42195/security-harbor-agent/pkg/pki"
)

type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	User      string    `json:"user"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
}

type Store struct {
	mu           sync.RWMutex
	baseDir      string
	runningCfg   *config.Config
	candidateCfg *config.Config
	crypto       *CryptoHandler
	Users        *UserStore
}

// NewStore öppnar (eller skapar) persistenslagret i baseDir. Master-
// nyckeln för kryptering at-rest hanteras HELT internt (se
// loadOrCreateMasterKey i masterkey.go) — genereras slumpmässigt vid
// första anropet på en ny installation, laddas därefter från disk. Ingen
// hårdkodad/delad nyckel någonstans i källkoden längre.
//
// seedMode styr VILKEN standardkonfiguration som skapas om baseDir är
// tom (helt ny installation) — config.ModeGateway (eller "") för en
// router/appliance-seed, config.ModeHost för enkortsdator-seed (Fas 13).
// Rör bara den allra första uppstarten; en redan initierad installation
// läser sin befintliga running.json oavsett vad som skickas in här.
func NewStore(baseDir string, seedMode string) (*Store, error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("misslyckades skapa store-katalog %s: %w", baseDir, err)
	}

	masterKey, err := loadOrCreateMasterKey(baseDir)
	if err != nil {
		return nil, fmt.Errorf("misslyckades hämta master-nyckel: %w", err)
	}

	crypto, err := NewCryptoHandler(masterKey)
	if err != nil {
		return nil, fmt.Errorf("misslyckades skapa crypto-handler: %w", err)
	}

	s := &Store{
		baseDir: baseDir,
		crypto:  crypto,
	}

	// Ladda eller skapa standardkonfiguration
	if err := s.loadOrInit(seedMode); err != nil {
		return nil, err
	}

	users, err := newUserStore(baseDir, crypto)
	if err != nil {
		return nil, fmt.Errorf("misslyckades initiera användarlagring: %w", err)
	}
	s.Users = users

	return s, nil
}

func (s *Store) loadOrInit(seedMode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// running och candidate måste vara SEPARATA objekt, inte två pekare
	// till samma struct. Tidigare tilldelades samma pekare till båda, vilket
	// betyder att allt som skriver i candidate (t.ex. UpdateObjectValues
	// eller IDS-auto-block) samtidigt skrev i running — utan att en enda
	// commit gjorts. Rollback-garantin i Safe Apply bygger på att running
	// är den orörda "senast kända säkra" konfigurationen; delade de objekt
	// fanns i praktiken inget att rulla tillbaka TILL.
	// (Upptäckt vid kodgranskning 2026-08-20. I praktiken maskerades det
	// oftast av att SetCandidateConfig byter ut candidate-pekaren vid
	// första GUI-ändringen, men fönstret dessförinnan var verkligt.)
	runningPath := filepath.Join(s.baseDir, "running.json")
	if _, err := os.Stat(runningPath); os.IsNotExist(err) {
		defaultCfg := defaultSeedConfig(seedMode)
		s.runningCfg = defaultCfg
		s.candidateCfg = cloneConfig(defaultCfg)
		return s.saveConfigLocked(runningPath, defaultCfg)
	}

	data, err := os.ReadFile(runningPath)
	if err != nil {
		return fmt.Errorf("misslyckades läsa %s: %w", runningPath, err)
	}

	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("misslyckades tolka running config: %w", err)
	}

	// Säkerställ att standard-policyer/-objekt som tillkommit efter att den här
	// configen först skapades finns med även i en befintlig installation (seed
	// gäller bara nya). Säker utan commit — den injicerade Deny-policyn är
	// avstängd. Sparas direkt så den överlever omstart.
	if ensureDefaultAutoBlock(&cfg) {
		if err := s.saveConfigLocked(runningPath, &cfg); err != nil {
			return fmt.Errorf("misslyckades spara migrerad config: %w", err)
		}
	}

	s.runningCfg = &cfg
	s.candidateCfg = cloneConfig(&cfg)
	return nil
}

// cloneConfig gör en djup kopia via JSON-serialisering. Configen är ren
// data (inga funktioner/kanaler/cykler) och sparas redan som JSON, så
// round-trippen är förlustfri per definition — samma representation som
// filen på disk. Vid ett (i praktiken omöjligt) fel returneras originalet
// hellre än nil, så anroparen aldrig får en nil-config.
func cloneConfig(cfg *config.Config) *config.Config {
	if cfg == nil {
		return nil
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return cfg
	}
	var out config.Config
	if err := json.Unmarshal(data, &out); err != nil {
		return cfg
	}
	return &out
}

// defaultSeedConfig bygger standardkonfigurationen för en helt ny
// installation. Gateway-läge (default) behåller det ursprungliga,
// dev-referensmiljö-formade seedet (ens18/ens19, en LAN-IP som råkar
// matcha 10.0.0.163) av bakåtkompatibilitetsskäl — host-läge (Fas 13) får
// ett genuint topologi-neutralt seed: ett enda, generiskt namngivet
// interface, ingen WAN/LAN-uppdelning, ingen hårdkodad IP.
func defaultSeedConfig(seedMode string) *config.Config {
	base := config.Config{
		Version:   1,
		Revision:  1,
		UpdatedAt: time.Now(),
		// Ett tomt standardobjekt som IDS auto-block (Fas 9) kan skriva
		// larmade käll-IP:n till. Finns med från start så att IDS-sidan i
		// GUI:t kan förifylla objektet direkt — auto-block är fortfarande
		// AVSTÄNGT tills användaren själv slår på det, och blockering kräver
		// dessutom att man skapar en Deny-policy som refererar objektet.
		Objects: []config.Object{
			{
				ID:          "obj-ips-autoblock",
				Name:        "IPS - Auto block",
				Type:        config.ObjectTypeIPList,
				Values:      []string{},
				Description: "Käll-IP:n som IDS auto-block lägger till automatiskt (Fas 9). Referera detta objekt från en Deny-policy för att faktiskt blockera dem.",
			},
		},
		Policies: []config.Policy{
			{
				ID:          "sys-ssh-lan",
				Name:        "Tillåt SSH till brandväggen",
				Enabled:     true,
				Priority:    1,
				SourceZone:  "LAN",
				DestZone:    "SELF",
				Service:     "22",
				Action:      config.ActionAccept,
				Local:       true,
				Critical:    true,
				Description: "Tillåter SSH-inloggning till brandväggen själv från det interna nätverket. Om du inaktiverar denna behöver du en annan väg in (t.ex. tangentbord och skärm, eller seriekonsol) för att kunna administrera brandväggen.",
			},
			// Färdig (men AVSTÄNGD) Deny-policy som refererar auto-block-objektet
			// ovan — se ipsAutoBlockDenyPolicy för motivering och detaljer.
			ipsAutoBlockDenyPolicy(),
		},
		Settings: config.Settings{
			HostName:           "security-harbor",
			APIPort:            8443,
			RollbackTimeoutSec: 30,
		},
	}

	if seedMode == config.ModeHost {
		base.Settings.Mode = config.ModeHost
		base.Interfaces = []config.Interface{
			{ID: "host0", Device: "eth0", Zone: "HOST", Enabled: true, AddressType: "dhcp"},
		}
		base.Zones = []config.Zone{
			{Name: "HOST", Description: "Denna dators enda gränssnitt"},
		}
		// SSH-policyn ovan pekar på SourceZone "LAN" — i host-läge finns
		// ingen "LAN"-zon (bara "HOST"), så peka om den till den faktiska
		// zonen.
		base.Policies[0].SourceZone = "HOST"
		return &base
	}

	base.Interfaces = []config.Interface{
		{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
		{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.163/24"},
	}
	base.Zones = []config.Zone{
		{Name: "WAN", Description: "Utsida / Internet"},
		{Name: "LAN", Description: "Internt nätverk"},
		{Name: "SERVERS", Description: "Serverzon"},
		{Name: "IOT", Description: "IoT-enheter"},
		{Name: "VPN", Description: "VPN-klienter"},
	}
	return &base
}

// ipsAutoBlockObjectID är ID:t på det objekt som IDS auto-block fyller med
// larmens käll-IP:n, och som ipsAutoBlockDenyPolicy refererar.
const ipsAutoBlockObjectID = "obj-ips-autoblock"

// ipsAutoBlockDenyPolicy är den färdiga men AVSTÄNGDA Deny-policyn som
// refererar auto-block-objektet. Den finns med i regellistan från start så att
// administratören bara behöver slå på den (och aktivera auto-block under
// Säkerhetshändelser) för att larmens käll-IP:n faktiskt ska blockeras —
// objektet i sig blockerar inget. Ligger tidigt i listan så att blockeringen
// vinner över ev. senare Allow-policies (första matchande regel vinner).
// SourceObj-uppslaget hoppar över regeln helt så länge objektet är tomt (se
// objectMatchExpr i nftables-adaptern), så en påslagen men tom regel blockerar
// ingenting av misstag.
func ipsAutoBlockDenyPolicy() config.Policy {
	return config.Policy{
		ID:          "sys-ips-autoblock-deny",
		Name:        "Blockera auto-blockerade IP:n (IPS)",
		Enabled:     false,
		Priority:    2,
		SourceZone:  "ANY",
		DestZone:    "ANY",
		SourceObj:   ipsAutoBlockObjectID,
		DestObj:     "ANY",
		Service:     "ANY",
		Action:      config.ActionDrop,
		Logging:     true,
		Description: "Släpper (drop) all trafik från IP:n som IDS auto-block lagt i objektet \"IPS - Auto block\". Avstängd som standard — slå på den, och aktivera auto-block under Säkerhetshändelser, för att faktiskt blockera larmens käll-IP:n.",
	}
}

// ensureDefaultAutoBlock injicerar den avstängda auto-block-Deny-policyn (och
// vid behov själva auto-block-objektet) i en BEFINTLIG config som saknar dem —
// seed-configen gäller ju bara nya installationer. Returnerar true om något
// lades till (så anroparen kan spara). Ändringen är säker att köra utan en
// uttrycklig commit: policyn är avstängd och objektet tomt, så inget beteende
// ändras förrän administratören själv slår på regeln.
func ensureDefaultAutoBlock(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	changed := false

	hasObj := false
	for _, o := range cfg.Objects {
		if o.ID == ipsAutoBlockObjectID {
			hasObj = true
			break
		}
	}
	if !hasObj {
		cfg.Objects = append(cfg.Objects, config.Object{
			ID:          ipsAutoBlockObjectID,
			Name:        "IPS - Auto block",
			Type:        config.ObjectTypeIPList,
			Values:      []string{},
			Description: "Käll-IP:n som IDS auto-block lägger till automatiskt. Referera detta objekt från en Deny-policy för att faktiskt blockera dem.",
		})
		changed = true
	}

	hasPolicy := false
	for _, p := range cfg.Policies {
		if p.ID == "sys-ips-autoblock-deny" {
			hasPolicy = true
			break
		}
	}
	if !hasPolicy {
		// Lägg den tidigt (efter en ev. Local/SSH-policy) så blockeringen
		// vinner över senare Allow-policies. Enklast: först i listan.
		cfg.Policies = append([]config.Policy{ipsAutoBlockDenyPolicy()}, cfg.Policies...)
		changed = true
	}
	return changed
}

func (s *Store) saveConfigLocked(path string, cfg *config.Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}

func (s *Store) GetRunningConfig() *config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.runningCfg
}

func (s *Store) GetCandidateConfig() *config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.candidateCfg
}

func (s *Store) SetCandidateConfig(cfg *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg.Revision = s.runningCfg.Revision + 1
	cfg.UpdatedAt = time.Now()

	s.candidateCfg = cfg
	candidatePath := filepath.Join(s.baseDir, "candidate.json")
	return s.saveConfigLocked(candidatePath, cfg)
}

// UpdateObjectValues skriver om Values (och Source-statusfälten) för ett
// Object med automatisk källa (Fas 5 — hot-listor/GeoIP, se pkg/threatfeed),
// i BÅDE running och candidate om objektet finns i båda. Detta går INTE via
// Safe Apply/candidate-bekräftelse — periodiska bakgrundsuppdateringar av en
// hot-listas innehåll är inte en användarändring som ska kräva manuell
// commit, till skillnad från redigeringar i GUI:t. Anroparen (pkg/threatfeed-
// schemaläggaren i main.go) ansvarar för att sedan trigga en ny nftables-
// applicering så att förändringen faktiskt slår igenom.
func (s *Store) UpdateObjectValues(objID string, values []string, fetchErr error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	apply := func(cfg *config.Config) {
		if cfg == nil {
			return
		}
		for i := range cfg.Objects {
			if cfg.Objects[i].ID != objID || cfg.Objects[i].Source == nil {
				continue
			}
			found = true
			if fetchErr != nil {
				cfg.Objects[i].Source.LastError = fetchErr.Error()
				continue
			}
			cfg.Objects[i].Values = values
			cfg.Objects[i].Source.EntryCount = len(values)
			cfg.Objects[i].Source.LastUpdated = time.Now().Format(time.RFC3339)
			cfg.Objects[i].Source.LastError = ""
		}
	}
	apply(s.runningCfg)
	apply(s.candidateCfg)

	if !found {
		return fmt.Errorf("objekt %q med automatisk källa hittades inte", objID)
	}

	if err := s.saveConfigLocked(filepath.Join(s.baseDir, "running.json"), s.runningCfg); err != nil {
		return err
	}
	if s.candidateCfg != nil {
		if err := s.saveConfigLocked(filepath.Join(s.baseDir, "candidate.json"), s.candidateCfg); err != nil {
			return err
		}
	}
	return nil
}

// UpdateObjectValuesDirect skriver om Values för ETT VANLIGT Object (utan
// Source, till skillnad från UpdateObjectValues) i BÅDE running och
// candidate om det finns i båda. Används av IDS-auto-block (Fas 9) för att
// lägga till larmade käll-IP:n i ett objekt användaren själv pekat ut —
// precis som hotlist-uppdatering går det INTE via Safe Apply/candidate-
// bekräftelse. Anroparen (Engine) ansvarar för att sedan trigga en ny
// nftables-applicering.
func (s *Store) UpdateObjectValuesDirect(objID string, values []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	apply := func(cfg *config.Config) {
		if cfg == nil {
			return
		}
		for i := range cfg.Objects {
			if cfg.Objects[i].ID != objID {
				continue
			}
			found = true
			cfg.Objects[i].Values = values
		}
	}
	apply(s.runningCfg)
	apply(s.candidateCfg)

	if !found {
		return fmt.Errorf("objekt %q hittades inte", objID)
	}

	if err := s.saveConfigLocked(filepath.Join(s.baseDir, "running.json"), s.runningCfg); err != nil {
		return err
	}
	if s.candidateCfg != nil {
		if err := s.saveConfigLocked(filepath.Join(s.baseDir, "candidate.json"), s.candidateCfg); err != nil {
			return err
		}
	}
	return nil
}

// blocklistIDPattern är en sträng ALLOWLIST för DNSBlocklistSource.ID —
// den kommer direkt från klienten (admin-API:t, se handleCandidateConfig)
// och används för att bygga ett filnamn. Utan denna spärr kan ett ID som
// innehåller "/" eller ".." fly ur baseDir helt (path traversal, hittat
// och bekräftat skarpt under en säkerhetsgranskning 2026-08-19 — ett ID
// som "/../pentest_poc_test" fick filen att hamna direkt i baseDir, helt
// utan "dns_blocklist_"-prefixet, och kunde i princip landat i vilken
// katalog som helst agenten har skrivrättighet till, t.ex. /etc/wireguard
// eller /etc/suricata). Bara alfanumeriskt + bindestreck/understreck
// tillåts — gott om utrymme för alla ID:n GUI:t faktiskt genererar.
var blocklistIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func dnsBlocklistPath(baseDir, id string) (string, error) {
	if !blocklistIDPattern.MatchString(id) {
		return "", fmt.Errorf("ogiltigt blocklist-ID %q (endast bokstäver, siffror, - och _ tillåtna)", id)
	}
	return filepath.Join(baseDir, "dns_blocklist_"+id+".txt"), nil
}

// SaveDNSBlocklistDomains cachar den hämtade DNS-domänblocklistan för EN
// källa (Fas 6, nyckad på DNSBlocklistSource.ID eftersom flera listor kan
// vara aktiva samtidigt) till en egen fil på disk — ALDRIG i running/
// candidate.json, eftersom en domänblocklista (t.ex. StevenBlack hosts)
// kan innehålla hundratusentals poster.
func (s *Store) SaveDNSBlocklistDomains(id string, domains []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path, err := dnsBlocklistPath(s.baseDir, id)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.Join(domains, "\n")), 0644)
}

// LoadDNSBlocklistDomains läser den cachade domänlistan för EN källa.
// Returnerar en tom lista (inte fel) om ingen hämtning ännu skett.
func (s *Store) LoadDNSBlocklistDomains(id string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	path, err := dnsBlocklistPath(s.baseDir, id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}
	return strings.Split(trimmed, "\n"), nil
}

// LoadAllEnabledDNSBlocklistDomains läser och slår ihop (deduplicerat) de
// cachade domänlistorna för ALLA aktiverade källor i cfg.DNS.Blocklists —
// det som faktiskt ska skickas till Unbound (se pkg/adapter/dns).
func (s *Store) LoadAllEnabledDNSBlocklistDomains(sources []config.DNSBlocklistSource) ([]string, error) {
	seen := map[string]bool{}
	var all []string
	for _, src := range sources {
		if !src.Enabled {
			continue
		}
		domains, err := s.LoadDNSBlocklistDomains(src.ID)
		if err != nil {
			return nil, fmt.Errorf("kunde inte läsa cachad blocklista för %q: %w", src.Name, err)
		}
		for _, d := range domains {
			if !seen[d] {
				seen[d] = true
				all = append(all, d)
			}
		}
	}
	return all, nil
}

// UpdateDNSBlocklistStatus skriver om statusfälten (senast uppdaterad/fel/
// antal poster) för EN blocklist-källa (matchad på ID) i BÅDE running och
// candidate, utanför Safe Apply/candidate-bekräftelse — samma resonemang
// som UpdateObjectValues (Fas 5): en bakgrundsuppdatering av listinnehåll
// är inte en användarändring som ska kräva manuell commit.
func (s *Store) UpdateDNSBlocklistStatus(id string, entryCount int, fetchErr error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	apply := func(cfg *config.Config) {
		if cfg == nil || cfg.DNS == nil {
			return
		}
		for i := range cfg.DNS.Blocklists {
			if cfg.DNS.Blocklists[i].ID != id {
				continue
			}
			found = true
			if fetchErr != nil {
				cfg.DNS.Blocklists[i].LastError = fetchErr.Error()
				continue
			}
			cfg.DNS.Blocklists[i].EntryCount = entryCount
			cfg.DNS.Blocklists[i].LastUpdated = time.Now().Format(time.RFC3339)
			cfg.DNS.Blocklists[i].LastError = ""
		}
	}
	apply(s.runningCfg)
	apply(s.candidateCfg)

	if !found {
		return fmt.Errorf("DNS-blocklista %q hittades inte", id)
	}

	if err := s.saveConfigLocked(filepath.Join(s.baseDir, "running.json"), s.runningCfg); err != nil {
		return err
	}
	if s.candidateCfg != nil {
		if err := s.saveConfigLocked(filepath.Join(s.baseDir, "candidate.json"), s.candidateCfg); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) CommitCandidate() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Kopia, inte samma pekare — se cloneConfig/loadOrInit. Annars pekar
	// running och candidate på samma struct igen efter varje commit, och
	// nästa direktskrivning i candidate (hotlist-uppdatering, IDS-auto-
	// block) muterar running i smyg.
	s.runningCfg = cloneConfig(s.candidateCfg)
	runningPath := filepath.Join(s.baseDir, "running.json")
	return s.saveConfigLocked(runningPath, s.runningCfg)
}

// wgServerKeys är den okrypterade formen som encrypteras som en blob innan
// den skrivs till disk (se EnsureWireGuardServerKeys).
type wgServerKeys struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// EnsureWireGuardServerKeys returnerar brandväggens egna WireGuard-nyckelpar,
// och genererar+krypterar (AES-256-GCM via Store.crypto, Fas 0 steg 0.5) ett
// nytt par vid första anropet. Den privata nyckeln lämnar aldrig disk okrypterad
// och exponeras aldrig via Management-API:t (endast publika nyckeln görs det).
func (s *Store) EnsureWireGuardServerKeys() (privateKey, publicKey string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keyPath := filepath.Join(s.baseDir, "wireguard_server.key.enc")

	if data, readErr := os.ReadFile(keyPath); readErr == nil {
		plain, decErr := s.crypto.Decrypt(data)
		if decErr != nil {
			return "", "", fmt.Errorf("misslyckades dekryptera WireGuard-serverns nyckelpar: %w", decErr)
		}
		var keys wgServerKeys
		if jsonErr := json.Unmarshal(plain, &keys); jsonErr != nil {
			return "", "", fmt.Errorf("korrupt WireGuard-nyckelfil: %w", jsonErr)
		}
		return keys.PrivateKey, keys.PublicKey, nil
	}

	priv, pub, genErr := wireguard.GenerateKeypair()
	if genErr != nil {
		return "", "", fmt.Errorf("misslyckades generera WireGuard-serverns nyckelpar: %w", genErr)
	}

	plain, jsonErr := json.Marshal(wgServerKeys{PrivateKey: priv, PublicKey: pub})
	if jsonErr != nil {
		return "", "", jsonErr
	}
	cipherBytes, encErr := s.crypto.Encrypt(plain)
	if encErr != nil {
		return "", "", fmt.Errorf("misslyckades kryptera WireGuard-serverns nyckelpar: %w", encErr)
	}
	if writeErr := os.WriteFile(keyPath, cipherBytes, 0600); writeErr != nil {
		return "", "", fmt.Errorf("misslyckades skriva %s: %w", keyPath, writeErr)
	}

	return priv, pub, nil
}

// pemKeyPair är den okrypterade formen som krypteras som en blob innan den
// skrivs till disk (samma mönster som wgServerKeys ovan).
type pemKeyPair struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
	Serial  string `json:"serial"`
}

func (s *Store) loadOrCreateKeyPair(filename string, generate func() (*pki.KeyPair, error)) (*pki.KeyPair, error) {
	path := filepath.Join(s.baseDir, filename)

	if data, readErr := os.ReadFile(path); readErr == nil {
		plain, decErr := s.crypto.Decrypt(data)
		if decErr != nil {
			return nil, fmt.Errorf("misslyckades dekryptera %s: %w", filename, decErr)
		}
		var kp pemKeyPair
		if jsonErr := json.Unmarshal(plain, &kp); jsonErr != nil {
			return nil, fmt.Errorf("korrupt nyckelfil %s: %w", filename, jsonErr)
		}
		return &pki.KeyPair{CertPEM: kp.CertPEM, KeyPEM: kp.KeyPEM, Serial: kp.Serial}, nil
	}

	kp, genErr := generate()
	if genErr != nil {
		return nil, genErr
	}

	plain, jsonErr := json.Marshal(pemKeyPair{CertPEM: kp.CertPEM, KeyPEM: kp.KeyPEM, Serial: kp.Serial})
	if jsonErr != nil {
		return nil, jsonErr
	}
	cipherBytes, encErr := s.crypto.Encrypt(plain)
	if encErr != nil {
		return nil, fmt.Errorf("misslyckades kryptera %s: %w", filename, encErr)
	}
	if writeErr := os.WriteFile(path, cipherBytes, 0600); writeErr != nil {
		return nil, fmt.Errorf("misslyckades skriva %s: %w", path, writeErr)
	}

	return kp, nil
}

// EnsureManagementTLSCert returnerar (och genererar+krypterar vid första
// anropet) certifikatet för Management-API:ets HTTPS-lyssnare. Följer
// exakt samma "generera vid första anropet, ladda från disk sedan"-mönster
// som EnsureOpenVPNCA nedan — en nyinstallerad brandvägg får alltså ett
// TLS-certifikat helt automatiskt vid första uppstart, inget manuellt steg.
func (s *Store) EnsureManagementTLSCert(ips []net.IP, dnsNames []string) (*pki.KeyPair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadOrCreateKeyPair("management_tls.key.enc", func() (*pki.KeyPair, error) {
		return pki.GenerateSelfSignedServerCert("security-harbor", ips, dnsNames)
	})
}

// EnsureOpenVPNCA returnerar brandväggens OpenVPN-CA (genererar+krypterar ett
// nytt vid första anropet, Fas 4). CA-nyckeln lämnar aldrig disk okrypterad
// och exponeras aldrig via Management-API:t — bara CACertPEM (publikt) gör det.
func (s *Store) EnsureOpenVPNCA() (*pki.KeyPair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadOrCreateKeyPair("openvpn_ca.key.enc", func() (*pki.KeyPair, error) {
		return pki.GenerateCA("Security Harbor CA")
	})
}

// EnsureOpenVPNServerCert returnerar brandväggens OpenVPN-servercertifikat,
// signerat av CA:n från EnsureOpenVPNCA, och genererar+krypterar ett nytt
// vid första anropet.
func (s *Store) EnsureOpenVPNServerCert() (*pki.KeyPair, error) {
	ca, err := s.EnsureOpenVPNCA()
	if err != nil {
		return nil, fmt.Errorf("openvpn: kunde inte hämta CA: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadOrCreateKeyPair("openvpn_server.key.enc", func() (*pki.KeyPair, error) {
		return pki.IssueCert(ca.CertPEM, ca.KeyPEM, "security-harbor-server", true)
	})
}

func (s *Store) LogAudit(user, action, details string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := AuditEntry{
		Timestamp: time.Now(),
		User:      user,
		Action:    action,
		Details:   details,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	auditPath := filepath.Join(s.baseDir, "audit.log")
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(data)
	return err
}
