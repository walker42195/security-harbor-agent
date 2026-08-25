package store

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// Konfigurationshistorik — de N senast BEKRÄFTADE konfigurationerna sparas
// på brandväggen så att en administratör kan gå tillbaka till en tidigare
// konfiguration långt efter att Safe Apply-fönstret stängts.
//
// Safe Apply skyddar bara mot att man låser ut sig i stunden: 30 sekunder
// utan bekräftelse och den senaste ändringen rullas tillbaka. Upptäcker man
// först dagen efter att en regeländring var fel finns inget att gå tillbaka
// till (efterfrågat 2026-08-25). Historiken täcker det fallet.
//
// Arkiveringen sker vid COMMIT, inte vid apply: en konfiguration som aldrig
// bekräftades rullades per definition tillbaka och ska inte kunna
// återställas som om den vore ett fungerande läge.

const (
	historyDirName = "config-history"
	// historyKeep speglar antalet sparade agent-versioner (se
	// systemd/lib-archive-version.sh) så att "de tre senaste" betyder samma
	// sak för både programvara och konfiguration.
	historyKeep = 3
)

// ConfigHistoryEntry är en post i historiken, som den exponeras över API:t.
type ConfigHistoryEntry struct {
	ID         string `json:"id"`          // filnamnets stam, används för att återställa
	Revision   int64  `json:"revision"`    // konfigurationens revisionsnummer
	ArchivedAt string `json:"archived_at"` // RFC3339
	SizeBytes  int64  `json:"size_bytes"`
}

// historyIDPattern är en ALLOWLIST för historik-ID:n. ID:t kommer från
// klienten vid återställning och används för att bygga en filsökväg — utan
// den här kontrollen vore det en sökvägstraversering rakt av.
var historyIDPattern = regexp.MustCompile(`^cfg-[0-9]{8}T[0-9]{6}Z-r[0-9]+$`)

func (s *Store) historyDir() string {
	return filepath.Join(s.baseDir, historyDirName)
}

// archiveConfigLocked sparar cfg i historiken och gallrar till historyKeep
// poster. Anroparen MÅSTE hålla s.mu. Fel loggas men returneras inte:
// historiken är en bekvämlighet, och att inte kunna skriva den får aldrig
// stoppa en commit av en konfiguration som redan applicerats skarpt.
func (s *Store) archiveConfigLocked(cfg *config.Config) {
	if cfg == nil {
		return
	}
	dir := s.historyDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("[HISTORIK] kunde inte skapa %s: %v", dir, err)
		return
	}

	id := fmt.Sprintf("cfg-%s-r%d", time.Now().UTC().Format("20060102T150405Z"), cfg.Revision)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Printf("[HISTORIK] kunde inte serialisera konfigurationen: %v", err)
		return
	}
	path := filepath.Join(dir, id+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("[HISTORIK] kunde inte skriva %s: %v", path, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("[HISTORIK] kunde inte byta namn på %s: %v", tmp, err)
		return
	}

	s.pruneHistoryLocked()
}

// pruneHistoryLocked behåller de historyKeep senaste posterna och tar bort
// resten. Sorteringen sker på filnamn, som börjar med en UTC-tidsstämpel i
// ett format som sorterar kronologiskt som sträng.
func (s *Store) pruneHistoryLocked() {
	entries := s.listHistoryLocked()
	if len(entries) <= historyKeep {
		return
	}
	for _, e := range entries[historyKeep:] {
		_ = os.Remove(filepath.Join(s.historyDir(), e.ID+".json"))
	}
}

// listHistoryLocked returnerar historiken, NYAST FÖRST.
func (s *Store) listHistoryLocked() []ConfigHistoryEntry {
	dirEntries, err := os.ReadDir(s.historyDir())
	if err != nil {
		return nil // saknad katalog = tom historik, inte ett fel
	}
	var out []ConfigHistoryEntry
	for _, de := range dirEntries {
		if de.IsDir() || filepath.Ext(de.Name()) != ".json" {
			continue
		}
		id := de.Name()[:len(de.Name())-len(".json")]
		if !historyIDPattern.MatchString(id) {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		out = append(out, ConfigHistoryEntry{
			ID:         id,
			Revision:   revisionFromHistoryID(id),
			ArchivedAt: info.ModTime().UTC().Format(time.RFC3339),
			SizeBytes:  info.Size(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID }) // nyast först
	return out
}

// revisionFromHistoryID plockar ut revisionsnumret ur "...-r<N>". ID:t har
// redan matchats mot historyIDPattern av anroparen, så suffixet finns.
func revisionFromHistoryID(id string) int64 {
	_, revStr, found := strings.Cut(id[strings.LastIndex(id, "-"):], "r")
	if !found {
		return 0
	}
	rev, err := strconv.ParseInt(revStr, 10, 64)
	if err != nil {
		return 0
	}
	return rev
}

// ListConfigHistory returnerar de sparade konfigurationerna, nyast först.
func (s *Store) ListConfigHistory() []ConfigHistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listHistoryLocked()
}

// LoadHistoricConfig läser en sparad konfiguration ur historiken. Den
// APPLICERAS INTE — anroparen lägger den som kandidat, så att den vanliga
// Safe Apply-kedjan (validering, 30-sekunders bekräftelse, automatisk
// rollback) gäller även för en återställning. Att applicera en gammal
// konfiguration rakt av vore att kringgå precis det skyddsnät som finns för
// att man inte ska låsa ut sig.
func (s *Store) LoadHistoricConfig(id string) (*config.Config, error) {
	if !historyIDPattern.MatchString(id) {
		return nil, fmt.Errorf("ogiltigt historik-ID")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(filepath.Join(s.historyDir(), id+".json"))
	if err != nil {
		return nil, fmt.Errorf("konfigurationen finns inte i historiken")
	}
	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("den sparade konfigurationen går inte att tolka: %w", err)
	}
	return &cfg, nil
}
