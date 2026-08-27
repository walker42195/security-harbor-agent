package traffic

import (
	"testing"
	"time"
)

func TestCollectorFirstSampleOnlySetsBaseline(t *testing.T) {
	// Räknarna kan ha byggts upp i timmar innan agenten startade. Bokförs de
	// som trafik "nu" får grafen en falsk spik vid varje omstart.
	s := NewStore(t.TempDir())
	c := NewCollector(s)
	t0 := time.Unix(1_700_000_000, 0)

	c.Sample(t0, map[string]Counters{"10.0.0.5": {RxBytes: 999_999, TxBytes: 999_999}})

	if got := s.Totals("1m")["10.0.0.5"]; got.Rx != 0 || got.Tx != 0 {
		t.Errorf("första avläsningen bokfördes som trafik: rx %d tx %d", got.Rx, got.Tx)
	}
}

func TestCollectorRecordsDeltas(t *testing.T) {
	s := NewStore(t.TempDir())
	c := NewCollector(s)
	t0 := time.Unix(1_700_000_000, 0)

	c.Sample(t0, map[string]Counters{"10.0.0.5": {RxBytes: 1000, TxBytes: 100}})
	c.Sample(t0.Add(10*time.Second), map[string]Counters{"10.0.0.5": {RxBytes: 3000, TxBytes: 400}})

	got := s.Totals("1m")["10.0.0.5"]
	if got.Rx != 2000 || got.Tx != 300 {
		t.Errorf("rx/tx = %d/%d, ville ha 2000/300", got.Rx, got.Tx)
	}
	// 2000 byte på 10 s = 200 B/s.
	if r := c.Rates()["10.0.0.5"]; r.RxBps != 200 || r.TxBps != 30 {
		t.Errorf("hastighet = %d/%d B/s, ville ha 200/30", r.RxBps, r.TxBps)
	}
}

func TestCollectorHandlesCounterReset(t *testing.T) {
	// "flush ruleset" vid varje policyändring nollar räknarna. Utan
	// specialhantering blir cur-prev ett negativt tal som wrappar till
	// flera exabyte och förstör hela historiken.
	s := NewStore(t.TempDir())
	c := NewCollector(s)
	t0 := time.Unix(1_700_000_000, 0)

	c.Sample(t0, map[string]Counters{"10.0.0.5": {RxBytes: 5000}})
	c.Sample(t0.Add(time.Minute), map[string]Counters{"10.0.0.5": {RxBytes: 9000}})
	// Nollställning: räknaren börjar om från 120.
	c.Sample(t0.Add(2*time.Minute), map[string]Counters{"10.0.0.5": {RxBytes: 120}})

	got := s.Totals("1h")["10.0.0.5"]
	// 4000 (första deltat) + 120 (hela värdet efter nollställning)
	if got.Rx != 4120 {
		t.Errorf("rx = %d, ville ha 4120 — nollställningen hanterades fel", got.Rx)
	}
	if got.Rx > 1<<60 {
		t.Fatal("räknaren wrappade runt — det är exakt buggen testet finns för")
	}
}

func TestCollectorNewDeviceCountsFromZero(t *testing.T) {
	s := NewStore(t.TempDir())
	c := NewCollector(s)
	t0 := time.Unix(1_700_000_000, 0)

	c.Sample(t0, map[string]Counters{"10.0.0.5": {RxBytes: 10}})
	// Ny enhet dyker upp i andra avläsningen med 700 byte redan räknade.
	c.Sample(t0.Add(time.Minute), map[string]Counters{
		"10.0.0.5": {RxBytes: 20},
		"10.0.0.9": {RxBytes: 700},
	})

	if got := s.Totals("1h")["10.0.0.9"]; got.Rx != 700 {
		t.Errorf("ny enhet: rx = %d, ville ha 700", got.Rx)
	}
}

func TestCollectorForgetsVanishedDevices(t *testing.T) {
	// Ett mängdelement har timeout. Försvinner enheten och kommer tillbaka
	// ska den räknas från noll igen, inte jämföras mot ett gammalt värde.
	s := NewStore(t.TempDir())
	c := NewCollector(s)
	t0 := time.Unix(1_700_000_000, 0)

	c.Sample(t0, map[string]Counters{"10.0.0.5": {RxBytes: 5000}})
	c.Sample(t0.Add(time.Minute), map[string]Counters{}) // borta
	c.Sample(t0.Add(2*time.Minute), map[string]Counters{"10.0.0.5": {RxBytes: 300}})

	if got := s.Totals("1h")["10.0.0.5"]; got.Rx != 300 {
		t.Errorf("rx = %d, ville ha 300", got.Rx)
	}
}
