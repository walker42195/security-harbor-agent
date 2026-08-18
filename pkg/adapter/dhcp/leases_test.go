package dhcp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseLeaseFileFiltersInactiveAndDedupes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kea-leases4.csv")
	csv := "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n" +
		"10.0.0.42,aa:bb:cc:dd:ee:01,,86400,0,1,0,0,laptop,0,,0\n" +
		"10.0.0.43,aa:bb:cc:dd:ee:02,,86400,0,1,0,0,,0,,0\n" + // inget hostname, hoppas över
		"10.0.0.44,aa:bb:cc:dd:ee:03,,86400,0,1,0,0,declined-host,1,,0\n" + // state=1 (declined), hoppas över
		"10.0.0.42,aa:bb:cc:dd:ee:01,,86400,0,1,0,0,laptop-renewed,0,,0\n" // samma IP, senare rad ska vinna
	if err := os.WriteFile(path, []byte(csv), 0644); err != nil {
		t.Fatalf("kunde inte skriva testfil: %v", err)
	}

	leases, err := ParseLeaseFile(path)
	if err != nil {
		t.Fatalf("ParseLeaseFile misslyckades: %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("förväntade exakt 1 aktiv lease med hostname, fick %d: %+v", len(leases), leases)
	}
	if leases[0].Hostname != "laptop-renewed" {
		t.Errorf("förväntade att senaste raden för samma IP vinner (laptop-renewed), fick %q", leases[0].Hostname)
	}
}

func TestParseLeaseFileMissingFileReturnsEmpty(t *testing.T) {
	leases, err := ParseLeaseFile("/nonexistent/path/kea-leases4.csv")
	if err != nil {
		t.Fatalf("förväntade inget fel för saknad fil (DHCP kan ha startats nyss), fick: %v", err)
	}
	if len(leases) != 0 {
		t.Errorf("förväntade tom lista, fick %d", len(leases))
	}
}
