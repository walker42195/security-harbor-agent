package suricata

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// Utdrag i samma form som suricata-update skriver: aktiva regler börjar med
// "alert", avstängda kommenteras ut med "# alert" — de tas alltså INTE bort.
const sampleRules = `# Kommentar som inte är en regel
alert dns $HOME_NET any -> any any (msg:"ET DYN_DNS Query to a *.no-ip domain"; sid:2012811; rev:5;)
alert dns $HOME_NET any -> any any (msg:"ET DYN_DNS Query to a *.ddns domain"; sid:2012812; rev:2;)
# alert http any any -> any any (msg:"ET DYN_DNS Avstängd sedan tidigare"; sid:2012813; rev:1;)
alert http $HOME_NET any -> any any (msg:"ET MALWARE Trojan CnC Checkin"; sid:2020001; rev:3;)
alert pkthdr any any -> any any (msg:"SURICATA Ethertype unknown"; decode-event:ethernet.unknown_ethertype; sid:2200121; rev:2;)
drop tcp any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; sid:2100498; rev:8;)
`

func TestListCategoriesCountsEnabledAndDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suricata.rules")
	if err := os.WriteFile(path, []byte(sampleRules), 0644); err != nil {
		t.Fatal(err)
	}

	cats, err := ListCategories(path)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]Category{}
	for _, c := range cats {
		got[c.Name] = c
	}

	// ET DYN_DNS: tre regler, varav en redan utkommenterad.
	if c := got["ET DYN_DNS"]; c.Total != 3 || c.Enabled != 2 {
		t.Errorf("ET DYN_DNS = %d/%d, ville ha 2 aktiva av 3", c.Enabled, c.Total)
	}
	if c := got["ET MALWARE"]; c.Total != 1 || c.Enabled != 1 {
		t.Errorf("ET MALWARE = %d/%d, ville ha 1/1", c.Enabled, c.Total)
	}
	// Suricatas egna decoder-händelser har bara ett ledord i msg.
	if c := got["SURICATA"]; c.Total != 1 || c.Enabled != 1 {
		t.Errorf("SURICATA = %d/%d, ville ha 1/1", c.Enabled, c.Total)
	}
	if c := got["GPL ATTACK_RESPONSE"]; c.Total != 1 {
		t.Errorf("GPL ATTACK_RESPONSE saknas eller fel: %+v", c)
	}
	// Största kategorin först, så att brusigast hamnar överst i GUI:t.
	if cats[0].Name != "ET DYN_DNS" {
		t.Errorf("första kategorin = %q, ville ha ET DYN_DNS (störst)", cats[0].Name)
	}
	// Kommentarraden överst får inte räknas som regel.
	if _, ok := got["Kommentar"]; ok {
		t.Error("en icke-regelrad räknades som regel")
	}
}

func TestLookupSignature(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suricata.rules")
	if err := os.WriteFile(path, []byte(sampleRules), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := LookupSignature(path, 2200121)
	if err != nil {
		t.Fatal(err)
	}
	if got != "SURICATA Ethertype unknown" {
		t.Errorf("fick %q", got)
	}
	// Okänt SID ska ge tom sträng, inte fel.
	got, err = LookupSignature(path, 999999)
	if err != nil || got != "" {
		t.Errorf("okänt SID gav (%q, %v), ville ha (\"\", nil)", got, err)
	}
}

func TestGenerateDisableConf(t *testing.T) {
	ids := &config.IDSConfig{
		DisabledCategories: []string{"ET DYN_DNS", "ET INFO"},
		DisabledSignatures: []config.DisabledSignature{
			{SID: 2200121, Signature: `SURICATA Ethertype unknown`},
			{SID: 2012811},
			{SID: 0}, // ogiltigt, ska hoppas över
		},
	}
	out := GenerateDisableConf(ids)

	// Kategorier ankras mot msg-prefixet, annars träffar "ET INFO" även
	// regler vars beskrivning råkar innehålla orden längre in.
	if !strings.Contains(out, `re:msg:"ET DYN_DNS `) {
		t.Errorf("kategoriregex saknas eller är oankrat:\n%s", out)
	}
	if !strings.Contains(out, "2200121\n") || !strings.Contains(out, "2012811\n") {
		t.Errorf("SID saknas:\n%s", out)
	}
	if strings.Contains(out, "\n0\n") {
		t.Errorf("SID 0 skrevs ut trots att det är ogiltigt:\n%s", out)
	}
	// Signaturtexten ska med som kommentar, för läsbarhet på maskinen.
	if !strings.Contains(out, "# SURICATA Ethertype unknown") {
		t.Errorf("signaturkommentar saknas:\n%s", out)
	}
}

func TestGenerateDisableConfEmptyIsSafe(t *testing.T) {
	// Ingen IDS-config alls får ge en fil som stänger av NOLL regler — inte
	// en tom fil som suricata-update kan misstolka, och absolut inte något
	// som råkar matcha allt.
	for _, ids := range []*config.IDSConfig{nil, {}} {
		out := GenerateDisableConf(ids)
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			t.Errorf("tom konfiguration gav en aktiv rad %q — det hade stängt av regler:\n%s", line, out)
		}
	}
}

// TestDisableConfPathIsAgentWritable vaktar buggen från 2026-08-27: filen låg
// i /etc/suricata, en katalog som ägs av root med 0755. Agenten kan ändra
// suricata.yaml där (install.sh gruppskriver den FILEN) men aldrig skapa
// något nytt, så den atomiska skrivningen föll på
// "open /etc/suricata/disable.conf.tmp: permission denied".
//
// systemd-enhetens ReadWritePaths=/etc/suricata räcker inte — den lyfter bara
// den skrivskyddade monteringen, inte filrättigheterna.
func TestDisableConfPathIsAgentWritable(t *testing.T) {
	if strings.HasPrefix(DisableConfPath, "/etc/") {
		t.Fatalf("DisableConfPath = %q ligger under /etc — agenten kan inte skapa filer där", DisableConfPath)
	}
	const dataDir = "/var/lib/security-harbor/"
	if !strings.HasPrefix(DisableConfPath, dataDir) {
		t.Errorf("DisableConfPath = %q, ville ha något under %s (agentens egen katalog, som finns i ReadWritePaths)", DisableConfPath, dataDir)
	}
}

// TestWriteDisableConfIsAtomic bevisar att skrivningen går via en temp-fil i
// SAMMA katalog — det är själva anledningen att katalogen måste vara skrivbar,
// och det som gjorde att buggen ovan syntes som ".tmp: permission denied".
func TestWriteDisableConfIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "disable.conf")

	if err := WriteDisableConf(path, "2200121\n"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "2200121\n" {
		t.Fatalf("innehåll = %q, err = %v", string(got), err)
	}
	// Ingen temp-fil ska ligga kvar efter en lyckad skrivning.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp-filen %q lämnades kvar", e.Name())
		}
	}
	// Skrivning nummer två ska ersätta, inte lägga till.
	if err := WriteDisableConf(path, "x\n"); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(path)
	if string(got) != "x\n" {
		t.Errorf("andra skrivningen gav %q", string(got))
	}
}
