package store

import "testing"

func TestLoadOrCreateMasterKeyGeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()

	key1, err := loadOrCreateMasterKey(dir)
	if err != nil {
		t.Fatalf("loadOrCreateMasterKey misslyckades: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("förväntade 32 bytes, fick %d", len(key1))
	}

	key2, err := loadOrCreateMasterKey(dir)
	if err != nil {
		t.Fatalf("andra anropet misslyckades: %v", err)
	}
	if string(key1) != string(key2) {
		t.Fatal("förväntade samma nyckel vid andra anropet (persisterad, inte omgenererad)")
	}
}

func TestLoadOrCreateMasterKeyDiffersAcrossInstallations(t *testing.T) {
	keyA, err := loadOrCreateMasterKey(t.TempDir())
	if err != nil {
		t.Fatalf("loadOrCreateMasterKey (A) misslyckades: %v", err)
	}
	keyB, err := loadOrCreateMasterKey(t.TempDir())
	if err != nil {
		t.Fatalf("loadOrCreateMasterKey (B) misslyckades: %v", err)
	}
	if string(keyA) == string(keyB) {
		t.Fatal("två olika installationer fick samma slumpade nyckel — inte slumpmässigt")
	}
}
