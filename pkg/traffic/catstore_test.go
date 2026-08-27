package traffic

import (
	"testing"
	"time"
)

func TestCategoryStoreAggregates(t *testing.T) {
	s := NewCategoryStore(t.TempDir())
	now := time.Unix(1_700_000_000, 0)

	s.Add(now, CategoryHit{IP: "10.0.0.5", Category: CatStreaming, Domain: "netflix.com", Rx: 5000, Tx: 100})
	s.Add(now, CategoryHit{IP: "10.0.0.5", Category: CatStreaming, Domain: "youtube.com", Rx: 3000, Tx: 50})
	s.Add(now, CategoryHit{IP: "10.0.0.5", Category: CatAds, Domain: "doubleclick.net", Rx: 10, Tx: 10})
	s.Add(now, CategoryHit{IP: "10.0.0.9", Category: CatGaming, Domain: "steampowered.com", Rx: 900, Tx: 9})

	all := s.Totals("1h", "")
	if len(all) != 3 {
		t.Fatalf("fick %d kategorier, ville ha 3: %+v", len(all), all)
	}
	// Sorterat på störst först.
	if all[0].Category != CatStreaming || all[0].Rx != 8000 {
		t.Errorf("största = %+v", all[0])
	}

	// Filtrerat på en enhet.
	one := s.Totals("1h", "10.0.0.9")
	if len(one) != 1 || one[0].Category != CatGaming {
		t.Errorf("per enhet: %+v", one)
	}
}

func TestCategoryStorePerDevice(t *testing.T) {
	s := NewCategoryStore(t.TempDir())
	now := time.Unix(1_700_000_000, 0)
	s.Add(now, CategoryHit{IP: "10.0.0.5", Category: CatStreaming, Rx: 100})
	s.Add(now, CategoryHit{IP: "10.0.0.9", Category: CatWeb, Rx: 200})

	per := s.PerDevice("1h")
	if len(per) != 2 {
		t.Fatalf("fick %d enheter", len(per))
	}
	if per["10.0.0.5"][0].Category != CatStreaming {
		t.Errorf("fel kategori: %+v", per["10.0.0.5"])
	}
}

func TestCategoryStoreTopDomains(t *testing.T) {
	s := NewCategoryStore(t.TempDir())
	now := time.Unix(1_700_000_000, 0)
	s.Add(now, CategoryHit{IP: "10.0.0.5", Category: CatStreaming, Domain: "netflix.com", Rx: 100})
	s.Add(now, CategoryHit{IP: "10.0.0.5", Category: CatStreaming, Domain: "netflix.com", Rx: 900})
	s.Add(now, CategoryHit{IP: "10.0.0.9", Category: CatWeb, Domain: "example.com", Rx: 500})

	top := s.TopDomains("", 10)
	if len(top) != 2 || top[0].Domain != "netflix.com" || top[0].Bytes != 1000 {
		t.Fatalf("topplista: %+v", top)
	}
	// Per enhet.
	if got := s.TopDomains("10.0.0.9", 10); len(got) != 1 || got[0].Domain != "example.com" {
		t.Errorf("per enhet: %+v", got)
	}
}

func TestCategoryStoreDomainListIsBounded(t *testing.T) {
	// En enhet kan prata med tusentals värdar per dygn. Utan tak vore
	// topplistan en obegränsad karta per enhet.
	s := NewCategoryStore(t.TempDir())
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < 500; i++ {
		s.Add(now, CategoryHit{IP: "10.0.0.5", Category: CatWeb,
			Domain: string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example", Rx: uint64(i + 1)})
	}
	s.mu.RLock()
	n := len(s.domains["10.0.0.5"])
	s.mu.RUnlock()
	if n > maxDomainsPerDevice {
		t.Errorf("domänlistan växte till %d, taket är %d", n, maxDomainsPerDevice)
	}
	// De största ska ha överlevt gallringen.
	top := s.TopDomains("10.0.0.5", 1)
	if len(top) == 0 || top[0].Bytes < 400 {
		t.Errorf("gallringen behöll inte de största: %+v", top)
	}
}

func TestCategoryStoreSaveLoad(t *testing.T) {
	dir := t.TempDir()
	s := NewCategoryStore(dir)
	now := time.Unix(1_700_000_000, 0)
	s.Add(now, CategoryHit{IP: "10.0.0.5", Category: CatStreaming, Domain: "svtplay.se", Rx: 77, Tx: 7})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	s2 := NewCategoryStore(dir)
	s2.Load()
	tot := s2.Totals("1d", "10.0.0.5")
	if len(tot) != 1 || tot[0].Rx != 77 {
		t.Fatalf("efter Load: %+v", tot)
	}
	if top := s2.TopDomains("10.0.0.5", 5); len(top) != 1 || top[0].Domain != "svtplay.se" {
		t.Errorf("domäner efter Load: %+v", top)
	}
}

func TestSplitCatKeyHandlesIPv6ish(t *testing.T) {
	// Nyckeln delas på SISTA lodstrecket, så en adress som själv innehåller
	// kolon eller ovanliga tecken inte förstör uppdelningen.
	ip, cat, ok := splitCatKey("10.0.0.5|streaming")
	if !ok || ip != "10.0.0.5" || cat != CatStreaming {
		t.Errorf("fick %q %q %v", ip, cat, ok)
	}
	if _, _, ok := splitCatKey("utan-avdelare"); ok {
		t.Error("nyckel utan avdelare accepterades")
	}
}
