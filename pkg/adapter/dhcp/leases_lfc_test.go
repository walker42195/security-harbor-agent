package dhcp

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

const leaseHeader = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n"

func writeLeases(t *testing.T, path string, rows ...string) {
	t.Helper()
	content := leaseHeader
	for _, r := range rows {
		content += r + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("skriv %s: %v", path, err)
	}
}

func ips(leases []LeaseDetail) []string {
	out := make([]string, 0, len(leases))
	for _, l := range leases {
		out = append(out, l.IP)
	}
	sort.Strings(out)
	return out
}

// Kärnan i incidenten 2026-08-26: Kea körde LFC, flyttade den konsoliderade
// historiken till en syskonfil, och agenten — som bara läste den aktuella
// filen — visade två utlåningar i stället för ett femtiotal.
func TestParseLeasesReadsAllFilesAfterLFC(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "kea-leases4.csv")

	writeLeases(t, current+".2",
		"10.8.8.101,aa:aa:aa:aa:aa:01,,7200,1787743424,4,0,0,skrivare,0,,0",
		"10.8.8.102,aa:aa:aa:aa:aa:02,,7200,1787743424,4,0,0,kamera,0,,0",
		"10.8.8.103,aa:aa:aa:aa:aa:03,,7200,1787743424,4,0,0,shelly,0,,0",
	)
	writeLeases(t, current,
		"10.13.13.101,bb:bb:bb:bb:bb:01,,7200,1787743342,3,0,0,laptop,0,,0",
	)

	leases, err := ParseLeasesDetailed(current)
	if err != nil {
		t.Fatalf("ParseLeasesDetailed: %v", err)
	}
	got := ips(leases)
	want := []string{"10.13.13.101", "10.8.8.101", "10.8.8.102", "10.8.8.103"}
	if len(got) != len(want) {
		t.Fatalf("fick %v, ville ha %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("fick %v, ville ha %v", got, want)
		}
	}
}

// Den aktuella filen är nyast och måste vinna över LFC-historiken.
func TestCurrentFileWinsOverArchivedHistory(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "kea-leases4.csv")

	writeLeases(t, current+".completed",
		"10.8.8.101,aa:aa:aa:aa:aa:01,,7200,1787743424,4,0,0,gammalt-namn,0,,0")
	writeLeases(t, current,
		"10.8.8.101,aa:aa:aa:aa:aa:01,,7200,1787750000,4,0,0,nytt-namn,0,,0")

	leases, err := ParseLeasesDetailed(current)
	if err != nil {
		t.Fatalf("ParseLeasesDetailed: %v", err)
	}
	if len(leases) != 1 || leases[0].Hostname != "nytt-namn" {
		t.Fatalf("den aktuella filen vann inte: %+v", leases)
	}
}

// En frisläppt adress i den aktuella filen ska ta bort den aktiva raden ur
// arkivet — annars ligger den kvar i DNS-zonen.
func TestReleasedLeaseRemovesArchivedActiveRow(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "kea-leases4.csv")

	writeLeases(t, current+".2",
		"10.8.8.101,aa:aa:aa:aa:aa:01,,7200,1787743424,4,0,0,skrivare,0,,0")
	writeLeases(t, current,
		"10.8.8.101,aa:aa:aa:aa:aa:01,,0,1787743424,4,0,0,skrivare,2,,0")

	leases, err := ParseLeasesDetailed(current)
	if err != nil {
		t.Fatalf("ParseLeasesDetailed: %v", err)
	}
	if len(leases) != 0 {
		t.Fatalf("frisläppt lease låg kvar: %+v", leases)
	}

	// Samma sak för DNS-varianten, som tidigare hade en egen (felaktig) kopia
	// av tolkningen och lät den frisläppta adressen ligga kvar.
	named, err := ParseLeaseFile(current)
	if err != nil {
		t.Fatalf("ParseLeaseFile: %v", err)
	}
	if len(named) != 0 {
		t.Fatalf("frisläppt lease låg kvar i DNS-registreringen: %+v", named)
	}
}

func TestParseLeaseFileOnlyReturnsNamedLeases(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "kea-leases4.csv")
	writeLeases(t, current,
		"10.8.8.101,aa:aa:aa:aa:aa:01,,7200,1787743424,4,0,0,skrivare,0,,0",
		"10.8.8.102,aa:aa:aa:aa:aa:02,,7200,1787743424,4,0,0,,0,,0",
	)
	named, err := ParseLeaseFile(current)
	if err != nil {
		t.Fatalf("ParseLeaseFile: %v", err)
	}
	if len(named) != 1 || named[0].Hostname != "skrivare" {
		t.Fatalf("fick %+v", named)
	}
}

func TestMissingLeaseFilesAreNotAnError(t *testing.T) {
	leases, err := ParseLeasesDetailed(filepath.Join(t.TempDir(), "finns-inte.csv"))
	if err != nil {
		t.Fatalf("en saknad lease-fil ska inte vara ett fel: %v", err)
	}
	if len(leases) != 0 {
		t.Fatalf("fick %+v", leases)
	}
}

// Filerna kan vara skrivna av olika Kea-versioner, så kolumnordningen läses
// per fil och inte en gång för alla.
func TestDifferentColumnOrderPerFile(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "kea-leases4.csv")

	if err := os.WriteFile(current+".2",
		[]byte("hostname,address,state\nskrivare,10.8.8.101,0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeLeases(t, current,
		"10.8.8.102,aa:aa:aa:aa:aa:02,,7200,1787743424,4,0,0,kamera,0,,0")

	leases, err := ParseLeasesDetailed(current)
	if err != nil {
		t.Fatalf("ParseLeasesDetailed: %v", err)
	}
	if len(leases) != 2 {
		t.Fatalf("fick %+v", leases)
	}
}
