package traffic

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreAccumulatesWithinSlot(t *testing.T) {
	s := NewStore(t.TempDir())
	now := time.Unix(1_700_000_000, 0)
	s.Add(now, "10.0.0.5", 100, 50)
	s.Add(now.Add(10*time.Second), "10.0.0.5", 200, 25) // samma minutslot

	got := s.Totals("1m")["10.0.0.5"]
	if got.Rx != 300 || got.Tx != 75 {
		t.Errorf("rx/tx = %d/%d, ville ha 300/75", got.Rx, got.Tx)
	}
}

func TestStoreZeroesSkippedSlots(t *testing.T) {
	// Det här är den fällan en ringbuffert har: skriver man i slot N och sedan
	// i slot N+200 utan att nolla mellanliggande, ligger data från ett varv
	// tidigare kvar och ser ut som färsk trafik.
	s := NewStore(t.TempDir())
	base := time.Unix(1_700_000_000, 0)
	s.Add(base, "10.0.0.5", 1000, 1000)

	// Hoppa längre fram än hela ringen (180 punkter i 1m).
	s.Add(base.Add(500*time.Minute), "10.0.0.5", 7, 7)

	got := s.Totals("1m")["10.0.0.5"]
	if got.Rx != 7 || got.Tx != 7 {
		t.Errorf("rx/tx = %d/%d, ville ha 7/7 — gammal data läckte igenom ringen", got.Rx, got.Tx)
	}
}

func TestStoreAllResolutionsGetData(t *testing.T) {
	s := NewStore(t.TempDir())
	s.Add(time.Unix(1_700_000_000, 0), "10.0.0.5", 42, 7)
	for _, r := range Resolutions {
		got := s.Totals(r.Name)["10.0.0.5"]
		if got.Rx != 42 || got.Tx != 7 {
			t.Errorf("upplösning %s: rx/tx = %d/%d, ville ha 42/7", r.Name, got.Rx, got.Tx)
		}
	}
}

func TestStoreHistoryIsChronological(t *testing.T) {
	s := NewStore(t.TempDir())
	base := time.Unix(1_700_000_000, 0).Truncate(time.Minute)
	for i := 0; i < 5; i++ {
		s.Add(base.Add(time.Duration(i)*time.Minute), "10.0.0.5", uint64(i+1), 0)
	}
	pts := s.History("1m", "10.0.0.5", 5)
	if len(pts) != 5 {
		t.Fatalf("fick %d punkter, ville ha 5", len(pts))
	}
	for i := 1; i < len(pts); i++ {
		if pts[i].Timestamp <= pts[i-1].Timestamp {
			t.Fatalf("punkterna är inte kronologiska: %d efter %d", pts[i].Timestamp, pts[i-1].Timestamp)
		}
	}
	// Äldst först: 1, sedan 2 ... 5.
	if pts[0].Rx != 1 || pts[4].Rx != 5 {
		t.Errorf("första=%d sista=%d, ville ha 1 och 5 (äldst först)", pts[0].Rx, pts[4].Rx)
	}
}

func TestStoreSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	now := time.Unix(1_700_000_000, 0)
	s.Add(now, "10.0.0.5", 123, 456)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	// Ingen temp-fil kvar.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("temp-fil kvarlämnad: %s", e.Name())
		}
	}

	s2 := NewStore(dir)
	s2.Load()
	got := s2.Totals("1h")["10.0.0.5"]
	if got.Rx != 123 || got.Tx != 456 {
		t.Errorf("efter Load: rx/tx = %d/%d, ville ha 123/456", got.Rx, got.Tx)
	}
}

func TestStoreSaveSkipsWhenClean(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	s.Add(time.Unix(1_700_000_000, 0), "10.0.0.5", 1, 1)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(s.path("1m"))
	first := fi.ModTime()

	time.Sleep(20 * time.Millisecond)
	if err := s.Save(); err != nil { // inget nytt sedan sist
		t.Fatal(err)
	}
	fi2, _ := os.Stat(s.path("1m"))
	if !fi2.ModTime().Equal(first) {
		t.Error("Save skrev till disk trots att inget ändrats — timern anropar den ofta")
	}
}

func TestStorePruneRemovesStaleDevices(t *testing.T) {
	s := NewStore(t.TempDir())
	now := time.Unix(1_700_000_000, 0)
	s.Add(now.Add(-100*24*time.Hour), "10.0.0.99", 1, 1) // gammal
	s.Add(now, "10.0.0.5", 1, 1)                         // färsk

	s.Prune(now, 30*24*time.Hour)

	devs := s.Devices()
	for _, d := range devs {
		if d == "10.0.0.99" {
			t.Error("gammal enhet fanns kvar efter Prune — antalet enheter måste också vara begränsat, inte bara punkterna per enhet")
		}
	}
	found := false
	for _, d := range devs {
		if d == "10.0.0.5" {
			found = true
		}
	}
	if !found {
		t.Error("färsk enhet rensades bort")
	}
}

func TestStoreLoadIgnoresWrongSizedSeries(t *testing.T) {
	// Ändras Resolutions i en framtida version får gammal data inte läsas in
	// med fel längd — då hade indexeringen kunnat gå utanför arrayen.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "traffic_1m.json"),
		[]byte(`{"10.0.0.5":{"rx":[1,2,3],"tx":[1,2,3],"last_slot":5}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewStore(dir)
	s.Load()
	if len(s.Devices()) != 0 {
		t.Error("en serie med fel längd lästes in")
	}
}
