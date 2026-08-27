package traffic

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// catResolutions är MEDVETET grövre än trafikhistorikens. Kategoridata
// multipliceras med antalet kategorier (11) gånger antalet enheter, så samma
// upplösning som per-enhet-historiken hade gett tiotals megabyte i stället för
// dryga megabytet. Timme och dygn räcker för frågan "vad använder den här
// enheten nätet till".
var catResolutions = []Resolution{
	{Name: "1h", Interval: time.Hour, Points: 48},      // 2 dygn
	{Name: "1d", Interval: 24 * time.Hour, Points: 90}, // 3 månader
}

// maxDomainsPerDevice begränsar toppdomänlistan. En enhet kan prata med
// tusentals värdar per dygn; utan tak vore det en obegränsad karta per enhet.
const maxDomainsPerDevice = 40

// CategoryStore lagrar byte per (enhet, kategori) och en topplista över
// domäner per enhet.
type CategoryStore struct {
	mu      sync.RWMutex
	dir     string
	buckets map[string]map[string]*Series // upplösning -> "ip|kategori" -> serie
	domains map[string]map[string]uint64  // ip -> domän -> byte
	dirty   bool
}

func NewCategoryStore(dir string) *CategoryStore {
	s := &CategoryStore{dir: dir, buckets: map[string]map[string]*Series{}, domains: map[string]map[string]uint64{}}
	for _, r := range catResolutions {
		s.buckets[r.Name] = map[string]*Series{}
	}
	return s
}

func catKey(ip string, c Category) string { return ip + "|" + string(c) }

// Add bokför ett klassificerat flöde.
func (s *CategoryStore) Add(now time.Time, h CategoryHit) {
	if h.IP == "" || (h.Rx == 0 && h.Tx == 0) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := catKey(h.IP, h.Category)
	for _, r := range catResolutions {
		b := s.buckets[r.Name]
		ser := b[key]
		slot := now.Unix() / int64(r.Interval/time.Second)
		if ser == nil {
			ser = newSeries(r.Points)
			ser.LastSlot = slot
			b[key] = ser
		}
		ser.add(slot, r.Points, h.Rx, h.Tx)
	}

	if h.Domain != "" {
		d := s.domains[h.IP]
		if d == nil {
			d = map[string]uint64{}
			s.domains[h.IP] = d
		}
		// Vid taket rensas de minsta bort i stället för att vägra nya: en
		// enhet som byter beteende ska inte fastna med en gammal topplista.
		if len(d) >= maxDomainsPerDevice {
			if _, exists := d[h.Domain]; !exists {
				trimSmallest(d, maxDomainsPerDevice/2)
			}
		}
		d[h.Domain] += h.Rx + h.Tx
	}
	s.dirty = true
}

func trimSmallest(m map[string]uint64, keep int) {
	type kv struct {
		k string
		v uint64
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
	for _, e := range all[min(keep, len(all)):] {
		delete(m, e.k)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CategoryTotal är summan för en kategori.
type CategoryTotal struct {
	Category Category `json:"category"`
	Rx       uint64   `json:"rx"`
	Tx       uint64   `json:"tx"`
}

// DomainTotal är en domän i topplistan.
type DomainTotal struct {
	Domain string `json:"domain"`
	Bytes  uint64 `json:"bytes"`
}

// Totals summerar per kategori, valfritt filtrerat på EN enhet.
func (s *CategoryStore) Totals(resolution, ip string) []CategoryTotal {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agg := map[Category]*CategoryTotal{}
	for key, ser := range s.buckets[resolution] {
		devIP, cat, ok := splitCatKey(key)
		if !ok || (ip != "" && devIP != ip) {
			continue
		}
		t := agg[cat]
		if t == nil {
			t = &CategoryTotal{Category: cat}
			agg[cat] = t
		}
		for i := range ser.Rx {
			t.Rx += ser.Rx[i]
			t.Tx += ser.Tx[i]
		}
	}

	out := make([]CategoryTotal, 0, len(agg))
	for _, c := range AllCategories {
		if t := agg[c]; t != nil && (t.Rx > 0 || t.Tx > 0) {
			out = append(out, *t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rx+out[i].Tx > out[j].Rx+out[j].Tx })
	return out
}

// PerDevice summerar totalt per enhet och kategori.
func (s *CategoryStore) PerDevice(resolution string) map[string][]CategoryTotal {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agg := map[string]map[Category]*CategoryTotal{}
	for key, ser := range s.buckets[resolution] {
		devIP, cat, ok := splitCatKey(key)
		if !ok {
			continue
		}
		if agg[devIP] == nil {
			agg[devIP] = map[Category]*CategoryTotal{}
		}
		t := agg[devIP][cat]
		if t == nil {
			t = &CategoryTotal{Category: cat}
			agg[devIP][cat] = t
		}
		for i := range ser.Rx {
			t.Rx += ser.Rx[i]
			t.Tx += ser.Tx[i]
		}
	}

	out := map[string][]CategoryTotal{}
	for devIP, cats := range agg {
		var list []CategoryTotal
		for _, c := range AllCategories {
			if t := cats[c]; t != nil && (t.Rx > 0 || t.Tx > 0) {
				list = append(list, *t)
			}
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Rx+list[i].Tx > list[j].Rx+list[j].Tx })
		out[devIP] = list
	}
	return out
}

// TopDomains returnerar de mest trafikerade domänerna, valfritt för EN enhet.
func (s *CategoryStore) TopDomains(ip string, limit int) []DomainTotal {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agg := map[string]uint64{}
	for devIP, doms := range s.domains {
		if ip != "" && devIP != ip {
			continue
		}
		for d, b := range doms {
			agg[d] += b
		}
	}
	out := make([]DomainTotal, 0, len(agg))
	for d, b := range agg {
		out = append(out, DomainTotal{Domain: d, Bytes: b})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Domain < out[j].Domain
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func splitCatKey(key string) (string, Category, bool) {
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == '|' {
			return key[:i], Category(key[i+1:]), true
		}
	}
	return "", "", false
}

func (s *CategoryStore) path(name string) string {
	return filepath.Join(s.dir, "traffic_cat_"+name+".json")
}

func (s *CategoryStore) Save() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	snap := map[string]map[string]*Series{}
	for n, b := range s.buckets {
		cp := make(map[string]*Series, len(b))
		for k, v := range b {
			cp[k] = v
		}
		snap[n] = cp
	}
	doms := map[string]map[string]uint64{}
	for ip, d := range s.domains {
		cp := make(map[string]uint64, len(d))
		for k, v := range d {
			cp[k] = v
		}
		doms[ip] = cp
	}
	s.dirty = false
	s.mu.Unlock()

	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	write := func(path string, v any) error {
		data, err := json.Marshal(v)
		if err != nil {
			return err
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return err
		}
		return os.Rename(tmp, path)
	}
	for n, b := range snap {
		if err := write(s.path(n), b); err != nil {
			return err
		}
	}
	return write(s.path("domains"), doms)
}

func (s *CategoryStore) Load() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range catResolutions {
		data, err := os.ReadFile(s.path(r.Name))
		if err != nil {
			continue
		}
		var b map[string]*Series
		if err := json.Unmarshal(data, &b); err != nil {
			continue
		}
		for k, ser := range b {
			if ser != nil && len(ser.Rx) == r.Points && len(ser.Tx) == r.Points {
				s.buckets[r.Name][k] = ser
			}
		}
	}
	if data, err := os.ReadFile(s.path("domains")); err == nil {
		var d map[string]map[string]uint64
		if json.Unmarshal(data, &d) == nil && d != nil {
			s.domains = d
		}
	}
}
