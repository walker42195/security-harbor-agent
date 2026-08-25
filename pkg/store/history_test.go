package store

import (
	"testing"
)

// Historiken ska hålla exakt de tre senaste BEKRÄFTADE konfigurationerna,
// nyast först, och gallra äldre automatiskt.
func TestConfigHistoryKeepsLastThree(t *testing.T) {
	s, err := NewStore(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}

	// Fem commits i rad. Varje commit arkiverar den UTGÅENDE running-configen,
	// så efter fem commits finns fem arkiverade lägen — varav tre ska vara kvar.
	for i := 0; i < 5; i++ {
		cand := cloneConfig(s.GetRunningConfig())
		if err := s.SetCandidateConfig(cand); err != nil {
			t.Fatal(err)
		}
		if err := s.CommitCandidate(); err != nil {
			t.Fatal(err)
		}
	}

	hist := s.ListConfigHistory()
	if len(hist) != historyKeep {
		t.Fatalf("förväntade %d sparade konfigurationer, fick %d", historyKeep, len(hist))
	}
	// Nyast först.
	for i := 1; i < len(hist); i++ {
		if hist[i-1].ID < hist[i].ID {
			t.Errorf("historiken är inte sorterad nyast först: %s före %s", hist[i-1].ID, hist[i].ID)
		}
	}
	// Revisionsnumret ska gå att läsa ur ID:t.
	if hist[0].Revision == 0 {
		t.Errorf("revisionsnumret plockades inte ut ur ID:t %q", hist[0].ID)
	}

	// Den nyaste ska gå att läsa tillbaka.
	cfg, err := s.LoadHistoricConfig(hist[0].ID)
	if err != nil {
		t.Fatalf("kunde inte läsa tillbaka %s: %v", hist[0].ID, err)
	}
	if cfg.Revision != hist[0].Revision {
		t.Errorf("revision i filen (%d) matchar inte listan (%d)", cfg.Revision, hist[0].Revision)
	}
}

// ID:t kommer från klienten och byggs till en filsökväg — sökvägstraversering
// måste avvisas.
func TestLoadHistoricConfigRejectsTraversal(t *testing.T) {
	s, err := NewStore(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"../../running", "../users.enc", "cfg-x", "", "/etc/passwd",
		"cfg-20260825T120000Z-r1/../../running",
	} {
		if _, err := s.LoadHistoricConfig(id); err == nil {
			t.Errorf("accepterade otillåtet historik-ID: %q", id)
		}
	}
}
