package svc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteIfChangedReportsOnlyRealChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	// Första skrivningen: filen finns inte → ändrad.
	changed, err := WriteIfChanged(path, []byte("hello\n"))
	if err != nil {
		t.Fatalf("WriteIfChanged: %v", err)
	}
	if !changed {
		t.Error("en ny fil ska rapporteras som ändrad")
	}

	// Identiskt innehåll → INTE ändrad. Det är den här signalen som avgör om
	// tjänsten startas om, dvs. om klienterna tappar DNS/DHCP i onödan.
	changed, err = WriteIfChanged(path, []byte("hello\n"))
	if err != nil {
		t.Fatalf("WriteIfChanged: %v", err)
	}
	if changed {
		t.Error("identiskt innehåll ska inte rapporteras som ändrat")
	}

	changed, err = WriteIfChanged(path, []byte("hej\n"))
	if err != nil {
		t.Fatalf("WriteIfChanged: %v", err)
	}
	if !changed {
		t.Error("nytt innehåll ska rapporteras som ändrat")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hej\n" {
		t.Errorf("fel innehåll på disk: %q", got)
	}
}

// Konfigurationsfilerna måste vara läsbara för tjänsternas egna konton
// (unbound, _kea, haproxy). os.CreateTemp ger 0600, så utan den explicita
// chmod:en hade tjänsterna inte kunnat läsa sin egen config.
func TestWriteIfChangedLeavesFileReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.conf")
	if _, err := WriteIfChanged(path, []byte("x")); err != nil {
		t.Fatalf("WriteIfChanged: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("fel rättigheter: %o, ville ha 644", perm)
	}
}

// Inga temp-filer får ligga kvar i katalogen — tjänsterna läser ofta HELA
// conf.d-kataloger, och en kvarglömd ".security-harbor.conf.123" hade då
// tolkats som ytterligare en konfigurationsfil.
func TestWriteIfChangedLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")
	for i := 0; i < 3; i++ {
		if _, err := WriteIfChanged(path, []byte{byte(i)}); err != nil {
			t.Fatalf("WriteIfChanged: %v", err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "test.conf" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("kvarglömda filer i katalogen: %v", names)
	}
}
