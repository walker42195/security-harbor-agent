package store

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSaveDNSBlocklistDomainsRejectsPathTraversal skyddar mot en riktig,
// skarpt bekräftad sårbarhet (säkerhetsgranskning 2026-08-19):
// DNSBlocklistSource.ID kommer okontrollerat från klienten (admin-API:t)
// och byggdes tidigare rakt in i ett filnamn utan sanering — ett ID som
// "/../pentest_poc_test" fick den hämtade domänlistan att skrivas direkt
// i baseDir, helt utanför "dns_blocklist_"-namngivningen, vilket i
// praktiken kunde nå VILKEN katalog agenten alls har skrivrättighet till.
func TestSaveDNSBlocklistDomainsRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir, "")
	if err != nil {
		t.Fatalf("NewStore misslyckades: %v", err)
	}

	maliciousIDs := []string{
		"/../pentest_poc_test",
		"../../../etc/passwd",
		"foo/../../bar",
		"foo/bar",
		"",
	}
	for _, id := range maliciousIDs {
		if err := s.SaveDNSBlocklistDomains(id, []string{"evil.example.com"}); err == nil {
			t.Errorf("SaveDNSBlocklistDomains(%q, ...) förväntades ge fel, men lyckades", id)
		}
		if _, err := s.LoadDNSBlocklistDomains(id); err == nil {
			t.Errorf("LoadDNSBlocklistDomains(%q) förväntades ge fel, men lyckades", id)
		}
	}

	// Bekräfta att ingen fil skrevs UTANFÖR baseDir (t.ex. en katalognivå
	// upp) av något av försöken ovan.
	parentEntries, err := os.ReadDir(filepath.Dir(dir))
	if err != nil {
		t.Fatalf("kunde inte läsa förälderkatalogen: %v", err)
	}
	for _, e := range parentEntries {
		if e.Name() == "pentest_poc_test" || e.Name() == "passwd" {
			t.Fatalf("hittade en fil (%s) som läckt ut ur baseDir via path traversal", e.Name())
		}
	}

	// Ett giltigt ID ska fortfarande fungera helt normalt.
	if err := s.SaveDNSBlocklistDomains("bl1", []string{"ads.example.com"}); err != nil {
		t.Fatalf("SaveDNSBlocklistDomains med giltigt ID misslyckades: %v", err)
	}
	domains, err := s.LoadDNSBlocklistDomains("bl1")
	if err != nil {
		t.Fatalf("LoadDNSBlocklistDomains med giltigt ID misslyckades: %v", err)
	}
	if len(domains) != 1 || domains[0] != "ads.example.com" {
		t.Fatalf("förväntade [\"ads.example.com\"], fick %v", domains)
	}
}
