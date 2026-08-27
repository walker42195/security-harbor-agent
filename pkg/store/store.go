package store

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/network"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/openvpn"
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
		adoptSystemAddressing(defaultCfg)
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
	changed := ensureDefaultAutoBlock(&cfg)
	if ensureDefaultMgmtAPIPolicy(&cfg) {
		changed = true
	}
	if changed {
		if err := s.saveConfigLocked(runningPath, &cfg); err != nil {
			return fmt.Errorf("misslyckades spara migrerad config: %w", err)
		}
	}

	s.runningCfg = &cfg

	// Ladda tillbaka en tidigare sparad, ännu inte applicerad kandidat
	// (candidate.json) om en sådan finns — INNAN den här fixen (2026-08-24)
	// skrevs candidate.json visserligen till disk vid varje SetCandidateConfig,
	// men lästes ALDRIG tillbaka här: candidateCfg sattes ovillkorligen till en
	// klon av running.json, vilket tyst kastade bort osparade GUI-ändringar vid
	// varje agentomstart — inklusive varje självuppdatering. Upptäckt
	// 2026-08-24 när en administratör inte förstod varför en klient-refresh
	// inte visade en nymigrerad policy men en full app-omstart gjorde det:
	// det var faktiskt bara timing (agenten hann starta om mellan de två
	// försöken), men letandet avslöjade att den ordningen hade kunnat radera
	// riktiga ändringar.
	candidatePath := filepath.Join(s.baseDir, "candidate.json")
	s.candidateCfg = s.loadCandidateOrFallback(candidatePath, &cfg)
	return nil
}

// loadCandidateOrFallback läser candidate.json om den finns och går att
// tolka, annars (ingen fil — normalt vid första uppstarten efter en
// installation eller efter en Confirm/Rollback som synkat kandidaten mot
// running — eller en trasig fil) faller den tillbaka till en klon av
// running (samma beteende som tidigare, se loadOrInit).
//
// Samma migreringar som running.json (ensureDefaultAutoBlock,
// ensureDefaultMgmtAPIPolicy) körs även på en inläst kandidat: en gammal,
// osparad kandidat kan sakna en policy/objekt som tillkommit sedan den
// sparades, vilket annars skulle få validatePolicies att avvisa en Apply
// av den (t.ex. saknad Management API-policy) med ett obegripligt fel.
func (s *Store) loadCandidateOrFallback(candidatePath string, running *config.Config) *config.Config {
	data, err := os.ReadFile(candidatePath)
	if err != nil {
		return cloneConfig(running)
	}
	var cand config.Config
	if err := json.Unmarshal(data, &cand); err != nil {
		log.Printf("[STORE] kunde inte tolka %s (%v) - återställer kandidaten till körande konfiguration", candidatePath, err)
		return cloneConfig(running)
	}
	changed := ensureDefaultAutoBlock(&cand)
	if ensureDefaultMgmtAPIPolicy(&cand) {
		changed = true
	}
	if changed {
		if err := s.saveConfigLocked(candidatePath, &cand); err != nil {
			log.Printf("[STORE] kunde inte spara migrerad kandidat %s: %v", candidatePath, err)
		}
	}
	return &cand
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
			mgmtAPIPolicy("LAN"),
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
		// SSH- och Management API-policyerna ovan pekar på SourceZone "LAN"
		// — i host-läge finns ingen "LAN"-zon (bara "HOST"), så peka om dem
		// till den faktiska zonen.
		base.Policies[0].SourceZone = "HOST"
		base.Policies[1].SourceZone = "HOST"
		return &base
	}

	base.Interfaces = []config.Interface{
		{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
		// Adresstyperna här är bara ett utgångsläge: adoptSystemAddressing
		// skriver över dem med vad korten FAKTISKT är inställda på innan
		// configen sparas första gången. En hårdkodad statisk IP hade annars
		// varit en fälla — ett Apply hade flyttat lådan dit och kapat
		// administratörens anslutning — medan ett hårdkodat "dhcp" lika tyst
		// hade kastat bort en redan satt statisk management-adress.
		{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "dhcp"},
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
// mgmtAPIPolicy bygger den skyddade (Protected) Local-policyn för Management
// API-åtkomst (GUI:t). Fram till 2026-08-24 var den här regeln en helt
// hårdkodad rad i nftables-adaptern, osynlig och oredigerbar i Policies-vyn.
// Den är nu en riktig Policy — synlig, och SourceZone/Schema/Description går
// att redigera — men Protected=true gör att varken GUI eller
// validatePolicies (vid Apply) tillåter att den inaktiveras eller tas bort:
// det är fortfarande den enda vägen in i GUI:t utan en text-baserad
// reservväg som SSH. Själva porten styrs alltid av Settings.APIPort, inte av
// Service-fältet här (se resolveMgmtAPIPort i nftables-adaptern) — annars
// hade regeln kunnat komma ur synk med den faktiska lyssningsporten.
func mgmtAPIPolicy(sourceZone string) config.Policy {
	return config.Policy{
		ID:          config.MgmtAPIPolicyID,
		Name:        "Tillåt Management API (GUI) till brandväggen",
		Enabled:     true,
		Priority:    1,
		SourceZone:  sourceZone,
		DestZone:    "SELF",
		Service:     "ANY", // Ignoreras av adaptern för denna policy — porten kommer alltid från Settings.APIPort.
		Action:      config.ActionAccept,
		Local:       true,
		Critical:    true,
		Protected:   true,
		Description: "Tillåter åtkomst till administrationsgränssnittet (GUI:t) på brandväggens Management API-port. Kan inte inaktiveras eller tas bort — det är den enda vägen in i GUI:t, utan en text-baserad reservväg som SSH. Ändra porten under Inställningar.",
	}
}

// ensureDefaultMgmtAPIPolicy injicerar mgmtAPIPolicy i en BEFINTLIG config
// som saknar den — seed-configen gäller ju bara nya installationer. Fram
// till 2026-08-24 fanns ingen sådan Policy alls; åtkomsten genererades helt
// dolt av nftables-adaptern. Säker att köra utan uttrycklig commit: den
// injicerade policyn är Enabled=true och Action=accept, dvs. exakt samma
// beteende brandväggen redan hade (adaptern genererade samma regel
// hårdkodat) — ingenting öppnas eller stängs som inte redan var öppet.
// Returnerar true om något lades till (så anroparen kan spara).
func ensureDefaultMgmtAPIPolicy(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, p := range cfg.Policies {
		if p.ID == config.MgmtAPIPolicyID {
			return false
		}
	}
	sourceZone := "LAN"
	if cfg.Settings.Mode == config.ModeHost {
		sourceZone = "HOST"
	}
	// Läggs sist i listan (inte först, som i seed-configen) för att inte
	// rubba matchningsordningen för policyer som redan finns i en
	// befintlig installation — första matchande regel vinner, och den här
	// migrationen ska bara TILLFÖRA synlighet/redigerbarhet, inte ändra
	// vilken regel som vinner för befintlig trafik.
	cfg.Policies = append(cfg.Policies, mgmtAPIPolicy(sourceZone))
	return true
}

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
		ID:       "sys-ips-autoblock-deny",
		Name:     "Blockera auto-blockerade IP:n (IPS)",
		Enabled:  false,
		Priority: 2,
		// Tom källzon (inte "ANY") när källan anges via objekt — annars visar
		// GUI:t både "ANY" och objektet i From-rutan. Tom zon = ingen
		// zonbegränsning, precis som "ANY", men utan den dubbla posten.
		SourceZone:  "",
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
const ipsAutoBlockObjectName = "IPS - Auto block"

func ensureDefaultAutoBlock(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	changed := false

	// 1. Bestäm det KANONISKA auto-block-objektet, i prioordning:
	//    a) det objekt IDS auto-block redan skriver till (ids.auto_block_object_id),
	//       om det pekar på ett befintligt objekt,
	//    b) annars ett befintligt objekt med namnet "IPS - Auto block",
	//    c) annars skapa ett nytt med det stabila seed-ID:t.
	// Att matcha på NAMN (inte bara på ett hårdkodat ID) är viktigt: en
	// befintlig installation kan redan ha ett auto-block-objekt med ett
	// GUI-genererat ID (obj_...), och en tidigare version av den här
	// migrationen som bara letade på ID skapade då ett DUBBLETT-objekt.
	existing := map[string]bool{}
	firstNamed := ""
	for _, o := range cfg.Objects {
		existing[o.ID] = true
		if o.Name == ipsAutoBlockObjectName && firstNamed == "" {
			firstNamed = o.ID
		}
	}
	canonicalID := ""
	switch {
	case cfg.IDS != nil && cfg.IDS.AutoBlockObjectID != "" && existing[cfg.IDS.AutoBlockObjectID]:
		canonicalID = cfg.IDS.AutoBlockObjectID
	case firstNamed != "":
		canonicalID = firstNamed
	default:
		cfg.Objects = append(cfg.Objects, config.Object{
			ID:          ipsAutoBlockObjectID,
			Name:        ipsAutoBlockObjectName,
			Type:        config.ObjectTypeIPList,
			Values:      []string{},
			Description: "Käll-IP:n som IDS auto-block lägger till automatiskt. Referera detta objekt från en Deny-policy för att faktiskt blockera dem.",
		})
		canonicalID = ipsAutoBlockObjectID
		changed = true
	}

	// 2. Säkerställ Deny-policyn och att den pekar på det kanoniska objektet
	//    (annars skulle den kunna vakta ett tomt duplikat medan IDS fyller ett
	//    annat objekt — regeln hade då aldrig blockerat något).
	hasPolicy := false
	for i := range cfg.Policies {
		if cfg.Policies[i].ID == "sys-ips-autoblock-deny" {
			hasPolicy = true
			// Rätta en tidigare injicerad variant som satte källzonen till
			// "ANY" i stället för tom (gav en dubbel "ANY"+objekt-post i From).
			if strings.EqualFold(cfg.Policies[i].SourceZone, "ANY") {
				cfg.Policies[i].SourceZone = ""
				changed = true
			}
			if cfg.Policies[i].SourceObj != canonicalID {
				cfg.Policies[i].SourceObj = canonicalID
				changed = true
			}
			break
		}
	}
	if !hasPolicy {
		// Lägg den tidigt (före ev. Allow-policies) så blockeringen vinner —
		// första matchande regel vinner. Enklast: först i listan.
		p := ipsAutoBlockDenyPolicy()
		p.SourceObj = canonicalID
		cfg.Policies = append([]config.Policy{p}, cfg.Policies...)
		changed = true
	}

	// 3. Städa bort ev. duplicerade "IPS - Auto block"-objekt som inte är det
	//    kanoniska (t.ex. det tomma duplikat en tidigare buggig migration la
	//    till). Bara säkert när de är TOMMA och inget refererar dem.
	referenced := map[string]bool{}
	if cfg.IDS != nil && cfg.IDS.AutoBlockObjectID != "" {
		referenced[cfg.IDS.AutoBlockObjectID] = true
	}
	for _, p := range cfg.Policies {
		if p.SourceObj != "" && p.SourceObj != "ANY" {
			referenced[p.SourceObj] = true
		}
		if p.DestObj != "" && p.DestObj != "ANY" {
			referenced[p.DestObj] = true
		}
	}
	kept := cfg.Objects[:0]
	removedDuplicate := false
	for _, o := range cfg.Objects {
		if o.Name == ipsAutoBlockObjectName && o.ID != canonicalID && len(o.Values) == 0 && !referenced[o.ID] {
			removedDuplicate = true
			continue
		}
		kept = append(kept, o)
	}
	if removedDuplicate {
		cfg.Objects = kept
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

// BaseDir är katalogen där agentens tillstånd ligger (/var/lib/security-harbor).
// Trafikhistoriken och enhetsregistret lagras här, inte under /etc — agenten
// äger den här katalogen och kan skapa filer i den.
func (s *Store) BaseDir() string { return s.baseDir }

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

// UpdateIDSRuleSelection skriver regelurvalet (tystade signaturer och
// avstängda kategorier) direkt till BÅDE running och candidate, samma mönster
// som UpdateObjectValuesDirect ovan.
//
// Skälet till att det inte går via candidate + commit: att tysta en signatur
// från IDS-vyn är en enskild, omedelbar åtgärd på ett larm man just tittar på
// — den ska inte ligga och vänta i en oapplicerad candidate tillsammans med
// halvfärdiga brandväggsregler, och den ska inte heller råka applicera dem.
func (s *Store) UpdateIDSRuleSelection(sigs []config.DisabledSignature, cats []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	apply := func(cfg *config.Config) {
		if cfg == nil || cfg.IDS == nil {
			return
		}
		cfg.IDS.DisabledSignatures = sigs
		cfg.IDS.DisabledCategories = cats
	}
	apply(s.runningCfg)
	apply(s.candidateCfg)

	if s.runningCfg == nil || s.runningCfg.IDS == nil {
		return fmt.Errorf("IDS är inte konfigurerat")
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
	// Arkivera den UTGÅENDE konfigurationen innan den skrivs över, så att
	// man kan gå tillbaka till den långt efter att Safe Apply-fönstret
	// stängts (se pkg/store/history.go). Görs vid COMMIT, inte vid apply:
	// en konfiguration som aldrig bekräftades rullades per definition
	// tillbaka och ska inte gå att återställa som ett fungerande läge.
	s.archiveConfigLocked(s.runningCfg)

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

// EnsureOpenVPNTLSCryptKey returnerar brandväggens tls-crypt-nyckel och
// genererar+krypterar en ny vid första anropet, samma mönster som CA:n ovan.
//
// Nyckeln är delad mellan servern och alla klientprofiler. Att byta den
// stänger därför ute varje redan utfärdad profil — den genereras en gång och
// roteras aldrig automatiskt.
func (s *Store) EnsureOpenVPNTLSCryptKey() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keyPath := filepath.Join(s.baseDir, "openvpn_tls_crypt.key.enc")

	if data, readErr := os.ReadFile(keyPath); readErr == nil {
		plain, decErr := s.crypto.Decrypt(data)
		if decErr != nil {
			return "", fmt.Errorf("misslyckades dekryptera tls-crypt-nyckeln: %w", decErr)
		}
		key := string(plain)
		if !openvpn.ValidTLSCryptKey(key) {
			return "", fmt.Errorf("korrupt tls-crypt-nyckel i %s", keyPath)
		}
		return key, nil
	}

	key, genErr := openvpn.GenerateTLSCryptKey()
	if genErr != nil {
		return "", genErr
	}
	cipherBytes, encErr := s.crypto.Encrypt([]byte(key))
	if encErr != nil {
		return "", fmt.Errorf("misslyckades kryptera tls-crypt-nyckeln: %w", encErr)
	}
	if writeErr := os.WriteFile(keyPath, cipherBytes, 0600); writeErr != nil {
		return "", fmt.Errorf("misslyckades skriva %s: %w", keyPath, writeErr)
	}
	return key, nil
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

// adoptSystemAddressing låter en FÄRSK installation ta över den
// adresskonfiguration korten redan har på OS-nivå, i stället för att påtvinga
// seed-configens gissning.
//
// Regeln användaren satte 2026-08-26: är kortet inställt på DHCP ska det
// förbli DHCP, och är det redan statiskt ska ingenting ändras. Det undviker
// båda fällorna. En hårdkodad statisk seed-IP (tidigare 10.0.0.163/24 från
// dev-referensmiljön) hade vid första appliceringen flyttat lådan dit och
// kapat administratörens session — men motsatsen är lika illa: en maskin som
// installerats med en medvetet satt statisk management-adress ska inte tyst
// hamna på en DHCP-lease bara för att seed-configen råkar säga "dhcp".
//
// Körs BARA när running.json saknas, alltså exakt en gång per installation.
// Därefter är configen sanningen och skrivs ner på OS-nivå vid varje
// applicering (se pkg/adapter/network/persist.go).
func adoptSystemAddressing(cfg *config.Config) {
	if cfg == nil {
		return
	}
	for i := range cfg.Interfaces {
		iface := &cfg.Interfaces[i]
		// VLAN har ingen befintlig OS-konfiguration att ärva — de skapas
		// först av agenten — och seedas aldrig med adress ändå.
		if iface.VLANID > 0 {
			continue
		}
		addressType, ipv4, gateway := network.AdoptSystemAddressing(iface.Device)
		iface.AddressType = addressType
		iface.IPv4 = ipv4
		if strings.EqualFold(iface.Zone, "WAN") {
			iface.Gateway = gateway
		}
		log.Printf("[INIT] %s ärver befintlig konfiguration från systemet: %s %s",
			iface.Device, addressType, ipv4)
	}
}
