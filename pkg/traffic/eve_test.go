package traffic

import (
	"os"
	"path/filepath"
	"testing"
)

func isTenDot(ip string) bool { return len(ip) > 3 && ip[:3] == "10." }

// Poster i samma form som Suricata 8.0.3 faktiskt skriver dem.
const (
	tlsLine  = `{"event_type":"tls","flow_id":111,"src_ip":"10.0.0.5","dest_ip":"1.2.3.4","tls":{"sni":"www.netflix.com"}}`
	flowLine = `{"event_type":"flow","flow_id":111,"src_ip":"10.0.0.5","dest_ip":"1.2.3.4","flow":{"bytes_toserver":1000,"bytes_toclient":50000}}`
)

func writeEve(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
}

func TestEveJoinsSniToFlowBytes(t *testing.T) {
	// Kärnan i klassificeringen: namnet kommer i tls-posten när anslutningen
	// öppnas, byten först i flow-posten när den stängs.
	dir := t.TempDir()
	p := filepath.Join(dir, "eve.json")
	writeEve(t, p, tlsLine, flowLine)

	hits, err := NewEveReader(p, isTenDot).Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("fick %d träffar, ville ha 1", len(hits))
	}
	h := hits[0]
	if h.IP != "10.0.0.5" || h.Category != CatStreaming {
		t.Errorf("ip=%s kategori=%s", h.IP, h.Category)
	}
	// Enhetens perspektiv: bytes_toclient är nedladdning.
	if h.Rx != 50000 || h.Tx != 1000 {
		t.Errorf("rx/tx = %d/%d, ville ha 50000/1000", h.Rx, h.Tx)
	}
}

func TestEveReadsOnlyNewData(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "eve.json")
	writeEve(t, p, tlsLine, flowLine)

	r := NewEveReader(p, isTenDot)
	if hits, _ := r.Read(); len(hits) != 1 {
		t.Fatalf("första läsningen gav %d", len(hits))
	}
	// Utan nya rader ska ingenting returneras — annars dubbelräknas allt vid
	// varje avläsning.
	if hits, _ := r.Read(); len(hits) != 0 {
		t.Fatalf("andra läsningen gav %d träffar, ville ha 0", len(hits))
	}
	writeEve(t, p, `{"event_type":"tls","flow_id":222,"src_ip":"10.0.0.9","tls":{"sni":"spotify.com"}}`,
		`{"event_type":"flow","flow_id":222,"src_ip":"10.0.0.9","dest_ip":"9.9.9.9","flow":{"bytes_toserver":10,"bytes_toclient":20}}`)
	hits, _ := r.Read()
	if len(hits) != 1 || hits[0].IP != "10.0.0.9" {
		t.Fatalf("fick %+v", hits)
	}
}

func TestEveHandlesRotation(t *testing.T) {
	// Efter logrotate är filen mindre än vår position. Utan hantering hade
	// läsaren tystnat för gott efter första rotationen.
	dir := t.TempDir()
	p := filepath.Join(dir, "eve.json")
	writeEve(t, p, tlsLine, flowLine)

	r := NewEveReader(p, isTenDot)
	r.Read()

	// Simulera rotation: ny, kortare fil.
	if err := os.WriteFile(p, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	writeEve(t, p, `{"event_type":"tls","flow_id":333,"src_ip":"10.0.0.7","tls":{"sni":"tv4play.se"}}`,
		`{"event_type":"flow","flow_id":333,"src_ip":"10.0.0.7","dest_ip":"8.8.8.8","flow":{"bytes_toserver":5,"bytes_toclient":9}}`)

	hits, _ := r.Read()
	if len(hits) != 1 || hits[0].Category != CatStreaming {
		t.Fatalf("efter rotation: %+v", hits)
	}
}

func TestEveIgnoresNonLocalAndFirewallOwnTraffic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "eve.json")
	// Flöde mellan två externa adresser — hör inte till någon enhet på nätet.
	writeEve(t, p,
		`{"event_type":"flow","flow_id":9,"src_ip":"1.2.3.4","dest_ip":"5.6.7.8","flow":{"bytes_toserver":10,"bytes_toclient":10}}`)
	hits, _ := NewEveReader(p, isTenDot).Read()
	if len(hits) != 0 {
		t.Errorf("externt flöde bokfördes som enhet: %+v", hits)
	}
}

func TestEveCountsDnsQueriesOnceNotTwice(t *testing.T) {
	// Både förfrågan och svar har samma flow_id. Räknas båda får varje
	// uppslag dubbel vikt, och svaret har dessutom resolvern som källa.
	dir := t.TempDir()
	p := filepath.Join(dir, "eve.json")
	writeEve(t, p,
		`{"event_type":"dns","flow_id":77,"src_ip":"10.0.0.5","dns":{"type":"query","queries":[{"rrname":"doubleclick.net"}]}}`,
		`{"event_type":"dns","flow_id":77,"src_ip":"10.0.0.1","dns":{"type":"answer","queries":[{"rrname":"doubleclick.net"}]}}`,
		`{"event_type":"flow","flow_id":77,"src_ip":"10.0.0.5","dest_ip":"10.0.0.1","flow":{"bytes_toserver":80,"bytes_toclient":200}}`)

	hits, _ := NewEveReader(p, isTenDot).Read()
	if len(hits) != 1 {
		t.Fatalf("fick %d träffar, ville ha 1", len(hits))
	}
	if hits[0].Category != CatAds {
		t.Errorf("kategori = %q, ville ha ads", hits[0].Category)
	}
}

func TestEveFlowWithoutNameIsOther(t *testing.T) {
	// Rå IP-trafik utan handskakning: ska räknas, men som "other".
	dir := t.TempDir()
	p := filepath.Join(dir, "eve.json")
	writeEve(t, p,
		`{"event_type":"flow","flow_id":5,"src_ip":"10.0.0.5","dest_ip":"1.2.3.4","flow":{"bytes_toserver":7,"bytes_toclient":8}}`)
	hits, _ := NewEveReader(p, isTenDot).Read()
	if len(hits) != 1 || hits[0].Category != CatOther {
		t.Fatalf("fick %+v", hits)
	}
}

func TestFlowNamesBoundedGrowth(t *testing.T) {
	// Uteblivna flow-poster får inte kunna fylla minnet.
	f := newFlowNames(10)
	for i := int64(1); i <= 100; i++ {
		f.put(i, "x.example")
	}
	f.mu.Lock()
	n := len(f.names)
	f.mu.Unlock()
	if n > 10 {
		t.Errorf("kartan växte till %d poster trots tak på 10", n)
	}
}
