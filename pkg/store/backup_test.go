package store

import (
	"os"
	"strings"
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func TestBackupRestoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir, "")
	if err != nil {
		t.Fatalf("NewStore misslyckades: %v", err)
	}

	// Skapa lite verkligt tillstånd att säkerhetskopiera: en running-config
	// och ett krypterat nyckelpar (Management-TLS-certifikatet — ren Go,
	// kräver inga externa binärer som "wg" som kan saknas i testmiljön).
	cfg := &config.Config{Version: 1, Settings: config.Settings{HostName: "backup-test"}}
	if err := s.saveConfigLocked(dirFile(dir, "running.json"), cfg); err != nil {
		t.Fatalf("kunde inte skriva running.json: %v", err)
	}
	s.runningCfg = cfg
	if _, err := s.EnsureManagementTLSCert(nil, []string{"localhost"}); err != nil {
		t.Fatalf("EnsureManagementTLSCert misslyckades: %v", err)
	}

	backup, err := s.Backup("korrekt-losenfras")
	if err != nil {
		t.Fatalf("Backup misslyckades: %v", err)
	}
	if len(backup) == 0 {
		t.Fatal("Backup returnerade tom data")
	}

	// Återställ i en NY store-katalog med en ANNAN master-nyckel, för att
	// verifiera att backupen är portabel oavsett master-nyckel-skillnad.
	dir2 := t.TempDir()
	s2, err := NewStore(dir2, "")
	if err != nil {
		t.Fatalf("NewStore (mål) misslyckades: %v", err)
	}
	if err := s2.Restore(backup, "korrekt-losenfras"); err != nil {
		t.Fatalf("Restore misslyckades: %v", err)
	}

	// running.json ska nu finnas i mål-katalogen med rätt innehåll.
	restored, err := NewStore(dir2, "")
	if err != nil {
		t.Fatalf("NewStore (läs tillbaka) misslyckades: %v", err)
	}
	got := restored.GetRunningConfig()
	if got == nil || got.Settings.HostName != "backup-test" {
		t.Fatalf("återställd running.json har fel innehåll: %+v", got)
	}

	// TLS-nyckelparet ska gå att läsa (dvs. korrekt omkrypterat under s2:s
	// egen master-nyckel, inte s:s).
	kp, err := restored.EnsureManagementTLSCert(nil, []string{"localhost"})
	if err != nil {
		t.Fatalf("kunde inte läsa återställt TLS-nyckelpar: %v", err)
	}
	if kp.CertPEM == "" || kp.KeyPEM == "" {
		t.Fatal("återställt TLS-nyckelpar är tomt")
	}
}

func TestRestoreWrongPassphraseFails(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir, "")
	if err != nil {
		t.Fatalf("NewStore misslyckades: %v", err)
	}
	backup, err := s.Backup("ratt-losenfrasen")
	if err != nil {
		t.Fatalf("Backup misslyckades: %v", err)
	}

	dir2 := t.TempDir()
	s2, err := NewStore(dir2, "")
	if err != nil {
		t.Fatalf("NewStore misslyckades: %v", err)
	}
	err = s2.Restore(backup, "fel-losenfrasen")
	if err == nil {
		t.Fatal("förväntade fel vid återställning med fel lösenfras, fick nil")
	}
	if !strings.Contains(err.Error(), "lösenfras") && !strings.Contains(err.Error(), "korrupt") {
		t.Fatalf("förväntade ett tydligt fras-/korrupt-relaterat fel, fick: %v", err)
	}
}

func TestRestoreGarbageDataFails(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir, "")
	if err != nil {
		t.Fatalf("NewStore misslyckades: %v", err)
	}
	if err := s.Restore([]byte("inte en backup-fil alls"), "vad-som-helst"); err == nil {
		t.Fatal("förväntade fel för skräpdata, fick nil")
	}
}

func TestFactoryResetRemovesStateKeepsAuditLog(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir, "")
	if err != nil {
		t.Fatalf("NewStore misslyckades: %v", err)
	}
	cfg := &config.Config{Version: 1}
	if err := s.saveConfigLocked(dirFile(dir, "running.json"), cfg); err != nil {
		t.Fatalf("kunde inte skriva running.json: %v", err)
	}
	if _, err := s.EnsureManagementTLSCert(nil, []string{"localhost"}); err != nil {
		t.Fatalf("EnsureManagementTLSCert misslyckades: %v", err)
	}
	if err := s.LogAudit("test", "TEST_ACTION", "det här ska överleva en reset"); err != nil {
		t.Fatalf("LogAudit misslyckades: %v", err)
	}

	if err := s.FactoryReset(); err != nil {
		t.Fatalf("FactoryReset misslyckades: %v", err)
	}

	for _, name := range []string{"running.json", "management_tls.key.enc"} {
		if _, statErr := os.Stat(dirFile(dir, name)); !os.IsNotExist(statErr) {
			t.Fatalf("förväntade att %s tagits bort av FactoryReset, stat gav: %v", name, statErr)
		}
	}
	if _, statErr := os.Stat(dirFile(dir, "audit.log")); statErr != nil {
		t.Fatalf("audit.log ska INTE tas bort av FactoryReset, stat gav: %v", statErr)
	}
}

func dirFile(dir, name string) string {
	return dir + "/" + name
}
