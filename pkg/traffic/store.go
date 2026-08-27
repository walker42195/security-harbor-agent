// Package traffic mäter och lagrar trafik per enhet.
//
// Mätningen görs av kärnan: nftables dynamiska set med counter (se
// pkg/adapter/nftables/accounting.go) räknar byte per IP. Agenten läser bara
// av räknarna med jämna mellanrum och lagrar SKILLNADEN sedan förra
// avläsningen — ingen paketkopiering, ingen egen räkning i userspace.
//
// Lagringen är avsiktligt BEGRÄNSAD. En brandvägg som fyller sin egen disk är
// värdelös (loggincidenten 2026-08-27 lämnade 13 GB av 30 använda innan taken
// sattes), så historiken nedsamplas i fasta ringbuffertar: ju äldre data,
// desto grövre upplösning. Storleken är därmed konstant och känd i förväg,
// oavsett hur länge lådan kört.
package traffic

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Resolution är en nedsamplingsnivå.
type Resolution struct {
	Name     string
	Interval time.Duration
	Points   int
}

// Resolutions täcker tre timmar i minutupplösning upp till två år i
// dygnsupplösning. Summa per enhet: 180+576+2160+730 = 3 646 punkter à 16 byte
// = ~58 kB. Vid 100 enheter ~6 MB totalt, vilket är taket oavsett drifttid.
var Resolutions = []Resolution{
	{Name: "1m", Interval: time.Minute, Points: 180},     // 3 timmar
	{Name: "5m", Interval: 5 * time.Minute, Points: 576}, // 48 timmar
	{Name: "1h", Interval: time.Hour, Points: 2160},      // 90 dygn
	{Name: "1d", Interval: 24 * time.Hour, Points: 730},  // 2 år
}

// Series är en ringbuffert för EN enhet i EN upplösning.
//
// Rx = nedladdat (byte TILL enheten), Tx = uppladdat (byte FRÅN enheten),
// alltid sett ur enhetens perspektiv — inte brandväggens. Det är den enda
// riktning som är begriplig i ett gränssnitt som säger "den här enheten har
// laddat ner X".
type Series struct {
	Rx []uint64 `json:"rx"`
	Tx []uint64 `json:"tx"`
	// LastSlot är det senaste slot-indexet (unix-tid / intervall) som skrivits.
	// Absolut, inte modulo — det är så vi vet hur många slots som ska nollas
	// när det varit tyst ett tag, och vilka punkter som är föråldrade.
	LastSlot int64 `json:"last_slot"`
}

func newSeries(points int) *Series {
	return &Series{Rx: make([]uint64, points), Tx: make([]uint64, points)}
}

// add lägger till byte i sloten för ts. Slots som hoppats över sedan förra
// skrivningen nollställs, annars hade gammal data från ett varv tidigare i
// ringen läckt in som om den vore färsk.
func (s *Series) add(slot int64, points int, rx, tx uint64) {
	if slot < s.LastSlot {
		return // äldre än det vi redan har; hör hemma i en punkt som rullat förbi
	}
	if slot > s.LastSlot {
		gap := slot - s.LastSlot
		if gap > int64(points) {
			gap = int64(points)
		}
		for i := int64(1); i <= gap; i++ {
			idx := int((s.LastSlot + i) % int64(points))
			s.Rx[idx], s.Tx[idx] = 0, 0
		}
		s.LastSlot = slot
	}
	idx := int(slot % int64(points))
	s.Rx[idx] += rx
	s.Tx[idx] += tx
}

// Point är en punkt ut mot API/GUI.
type Point struct {
	Timestamp int64  `json:"t"`
	Rx        uint64 `json:"rx"`
	Tx        uint64 `json:"tx"`
}

// pointsSince returnerar punkterna i kronologisk ordning, äldst först.
func (s *Series) pointsSince(res Resolution, count int) []Point {
	if count > res.Points {
		count = res.Points
	}
	out := make([]Point, 0, count)
	for i := count - 1; i >= 0; i-- {
		slot := s.LastSlot - int64(i)
		if slot < 0 {
			continue
		}
		idx := int(slot % int64(res.Points))
		out = append(out, Point{
			Timestamp: slot * int64(res.Interval/time.Second),
			Rx:        s.Rx[idx],
			Tx:        s.Tx[idx],
		})
	}
	return out
}

// Store håller alla enheters serier i alla upplösningar.
type Store struct {
	mu      sync.RWMutex
	dir     string
	buckets map[string]map[string]*Series // upplösningsnamn -> IP -> serie
	dirty   bool
}

func NewStore(dir string) *Store {
	s := &Store{dir: dir, buckets: map[string]map[string]*Series{}}
	for _, r := range Resolutions {
		s.buckets[r.Name] = map[string]*Series{}
	}
	return s
}

// Add bokför trafik för en IP vid tidpunkten now, i samtliga upplösningar.
func (s *Store) Add(now time.Time, ip string, rx, tx uint64) {
	if rx == 0 && tx == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range Resolutions {
		b := s.buckets[r.Name]
		ser := b[ip]
		if ser == nil {
			ser = newSeries(r.Points)
			ser.LastSlot = now.Unix() / int64(r.Interval/time.Second)
			b[ip] = ser
		}
		ser.add(now.Unix()/int64(r.Interval/time.Second), r.Points, rx, tx)
	}
	s.dirty = true
}

// Totals summerar all trafik en enhet har i den angivna upplösningen.
func (s *Store) Totals(resolution string) map[string]Point {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]Point{}
	b := s.buckets[resolution]
	for ip, ser := range b {
		var rx, tx uint64
		for i := range ser.Rx {
			rx += ser.Rx[i]
			tx += ser.Tx[i]
		}
		out[ip] = Point{Rx: rx, Tx: tx}
	}
	return out
}

// History returnerar de senaste count punkterna för en enhet.
func (s *Store) History(resolution, ip string, count int) []Point {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ser := s.buckets[resolution][ip]
	if ser == nil {
		return []Point{}
	}
	for _, r := range Resolutions {
		if r.Name == resolution {
			return ser.pointsSince(r, count)
		}
	}
	return []Point{}
}

// Prune tar bort enheter som inte setts på länge, så att en lådan som sett
// tusentals kortlivade DHCP-adresser genom åren inte växer obegränsat i
// ANTAL enheter — ringbuffertarna är visserligen fasta, men en per enhet.
func (s *Store) Prune(now time.Time, maxAge time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for _, r := range Resolutions {
		cutoff := now.Add(-maxAge).Unix() / int64(r.Interval/time.Second)
		b := s.buckets[r.Name]
		for ip, ser := range b {
			if ser.LastSlot < cutoff {
				delete(b, ip)
				removed++
			}
		}
	}
	if removed > 0 {
		s.dirty = true
	}
	return removed
}

// Devices listar alla IP:n som har data.
func (s *Store) Devices() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]bool{}
	for _, b := range s.buckets {
		for ip := range b {
			seen[ip] = true
		}
	}
	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

func (s *Store) path(res string) string {
	return filepath.Join(s.dir, "traffic_"+res+".json")
}

// Save skriver bara om något ändrats sedan förra sparningen — den här
// funktionen anropas på en timer och ska inte skriva till disk i onödan.
func (s *Store) Save() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	snapshot := map[string]map[string]*Series{}
	for name, b := range s.buckets {
		cp := make(map[string]*Series, len(b))
		for ip, ser := range b {
			cp[ip] = ser
		}
		snapshot[name] = cp
	}
	s.dirty = false
	s.mu.Unlock()

	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	for name, b := range snapshot {
		data, err := json.Marshal(b)
		if err != nil {
			return err
		}
		tmp := s.path(name) + ".tmp"
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return fmt.Errorf("kunde inte skriva %s: %w", tmp, err)
		}
		if err := os.Rename(tmp, s.path(name)); err != nil {
			return err
		}
	}
	return nil
}

// Load läser tillbaka historiken vid uppstart. En saknad eller trasig fil är
// inte ett fel — historik är trevligt att ha, aldrig något att vägra starta
// för.
func (s *Store) Load() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range Resolutions {
		data, err := os.ReadFile(s.path(r.Name))
		if err != nil {
			continue
		}
		var b map[string]*Series
		if err := json.Unmarshal(data, &b); err != nil {
			continue
		}
		for ip, ser := range b {
			if ser == nil || len(ser.Rx) != r.Points || len(ser.Tx) != r.Points {
				continue // fel storlek, t.ex. efter att Resolutions ändrats
			}
			s.buckets[r.Name][ip] = ser
		}
	}
}
