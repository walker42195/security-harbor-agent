package traffic

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsRandomizedMAC(t *testing.T) {
	cases := map[string]bool{
		"b2:f4:9a:7e:0d:9e": true,  // b2 = 1011_0010, lokalt administrerad bit satt
		"36:23:d5:40:db:c4": true,  // 36 = 0011_0110
		"f4:39:09:1a:39:a1": false, // riktig OUI
		"68:27:19:3c:ed:c6": false,
		"":                  false,
		"zz":                false,
	}
	for mac, want := range cases {
		if got := isRandomizedMAC(mac); got != want {
			t.Errorf("%q: fick %v, ville ha %v", mac, got, want)
		}
	}
}

func TestIsOnline(t *testing.T) {
	// STALE måste räknas som online — annars blinkar varje enhet som varit
	// tyst några sekunder till offline i gränssnittet.
	if !isOnline([]string{"STALE"}) {
		t.Error("STALE ska räknas som online")
	}
	if !isOnline([]string{"REACHABLE"}) {
		t.Error("REACHABLE ska vara online")
	}
	if isOnline([]string{"FAILED"}) {
		t.Error("FAILED ska vara offline")
	}
	if isOnline([]string{"INCOMPLETE"}) {
		t.Error("INCOMPLETE ska vara offline")
	}
	if isOnline(nil) {
		t.Error("okänt tillstånd ska inte räknas som online")
	}
}

func TestReadLeases(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "kea-leases4.csv")
	// Verklig header från Kea på maskinen.
	content := `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
10.0.0.103,68:27:19:3C:ED:C6,,7200,1787857224,1,0,0,myenergihub,0,,0
10.8.8.107,08:f9:e0:ff:02:78,01:08:f9:e0:ff:02:78,7200,1787850038,4,0,0,,2,,0
`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	leases := readLeases(p)
	// MAC ska normaliseras till gemener, annars matchar den aldrig ip neigh.
	if got := leases["68:27:19:3c:ed:c6"]; got != "myenergihub" {
		t.Errorf("värdnamn = %q, ville ha myenergihub", got)
	}
	// Tomt värdnamn ska inte ge en tom post.
	if _, ok := leases["08:f9:e0:ff:02:78"]; ok {
		t.Error("en lease utan värdnamn togs med")
	}
	// Saknad fil är inte ett fel.
	if got := readLeases(filepath.Join(dir, "finns-inte.csv")); len(got) != 0 {
		t.Error("saknad fil gav poster")
	}
}

func TestVendorLookup(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "oui.txt")
	content := "\n" +
		"F4-39-09   (hex)\t\tHewlett Packard\n" +
		"68-27-19   (hex)\t\tAzureWave Technology Inc.\n" +
		"skräprad utan hex\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	old := ouiPaths
	ouiPaths = []string{p}
	defer func() { ouiPaths = old }()

	inv := NewInventory(filepath.Join(dir, "state.json"))
	if got := inv.vendorOf("f4:39:09:1a:39:a1"); got != "Hewlett Packard" {
		t.Errorf("tillverkare = %q", got)
	}
	if got := inv.vendorOf("68:27:19:3c:ed:c6"); got != "AzureWave Technology Inc." {
		t.Errorf("tillverkare = %q", got)
	}
	// Okänd OUI ska ge tom sträng, inte fel.
	if got := inv.vendorOf("00:11:22:33:44:55"); got != "" {
		t.Errorf("okänd OUI gav %q", got)
	}
}

func TestFirstSeenSurvivesRestart(t *testing.T) {
	// Utan persistens ser varje enhet ut som ny efter en omstart, och
	// "ny enhet"-signalen blir meningslös.
	dir := t.TempDir()
	p := filepath.Join(dir, "first_seen.json")

	inv := NewInventory(p)
	inv.firstSeen["aa:bb:cc:dd:ee:ff"] = 1_700_000_000
	if err := inv.SaveFirstSeen(); err != nil {
		t.Fatal(err)
	}

	inv2 := NewInventory(p)
	inv2.LoadFirstSeen()
	if got := inv2.firstSeen["aa:bb:cc:dd:ee:ff"]; got != 1_700_000_000 {
		t.Errorf("first_seen = %d efter omstart", got)
	}
}

func TestHostnameForPrefersStaticRecord(t *testing.T) {
	statics := map[string]string{"10.7.7.7": "nx4.novabase.se"}
	leases := map[string]string{"aa:bb:cc:dd:ee:ff": "fran-dhcp"}

	// Manuell post vinner över DHCP-namnet: den är ett medvetet val, medan
	// lease-namnet är vad klienten själv råkade skicka.
	if got := hostnameFor("10.7.7.7", "aa:bb:cc:dd:ee:ff", statics, leases); got != "nx4.novabase.se" {
		t.Errorf("fick %q, ville ha nx4.novabase.se", got)
	}
	// Utan manuell post används DHCP-namnet.
	if got := hostnameFor("10.0.0.5", "aa:bb:cc:dd:ee:ff", statics, leases); got != "fran-dhcp" {
		t.Errorf("fick %q, ville ha fran-dhcp", got)
	}
	// Varken eller: tom sträng, så GUI:t visar IP.
	if got := hostnameFor("10.0.0.9", "11:22:33:44:55:66", statics, leases); got != "" {
		t.Errorf("fick %q, ville ha tom sträng", got)
	}
	// En enhet som bara finns som statisk post, utan lease alls — exakt fallet
	// som saknade namn i vyn innan.
	if got := hostnameFor("10.7.7.7", "", statics, nil); got != "nx4.novabase.se" {
		t.Errorf("fick %q", got)
	}
}
