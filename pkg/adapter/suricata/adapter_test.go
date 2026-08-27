package suricata

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleYaml = `%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16]"

af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
  - interface: default
    cluster-id: 98

pcap:
  - interface: eth0
`

func TestSetInterfaceReplacesOnlyFirstAfPacketEntry(t *testing.T) {
	updated, err := SetInterface([]byte(sampleYaml), "ens19")
	if err != nil {
		t.Fatalf("SetInterface misslyckades: %v", err)
	}
	s := string(updated)

	if !strings.Contains(s, "af-packet:\n  - interface: ens19\n") {
		t.Fatalf("förväntade att af-packet-sektionens första interface uppdaterats till ens19, fick:\n%s", s)
	}
	if !strings.Contains(s, "- interface: default\n") {
		t.Fatalf("det andra af-packet-listobjektet ('default') ska INTE röras, fick:\n%s", s)
	}
	if !strings.Contains(s, "pcap:\n  - interface: eth0\n") {
		t.Fatalf("pcap-sektionens interface-rad ska INTE röras (annan topp-nyckel), fick:\n%s", s)
	}
}

func TestSetInterfaceMissingSection(t *testing.T) {
	if _, err := SetInterface([]byte("vars:\n  x: 1\n"), "ens19"); err == nil {
		t.Fatal("förväntade fel när af-packet-sektionen saknas, fick nil")
	}
}

// TestReadRecentAlertsReadsTailNotWholeFile vaktar prestandafixen från
// 2026-08-27: eve.json mättes till 1,47 GB på en skarp installation och
// funktionen anropas var 5:e sekund av IDS-vyn plus var 30:e sekund av
// auto-blockeringen. Tidigare skannades hela filen vid varje anrop.
func TestReadRecentAlertsReadsTailNotWholeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Fyllnad större än startfönstret, så att en implementation som läser
	// från början tvingas igenom allt.
	filler := strings.Repeat("x", 512)
	for i := 0; i < 40000; i++ {
		fmt.Fprintf(f, `{"event_type":"flow","pad":"%s"}`+"\n", filler)
	}
	// Larmen ligger SIST — bara en svansläsning hittar dem utan att läsa allt.
	for i := 0; i < 5; i++ {
		fmt.Fprintf(f, `{"timestamp":"2026-08-27T18:0%d:00.0+0200","event_type":"alert","src_ip":"10.0.0.%d","alert":{"signature":"TEST-%d","category":"Test","severity":2}}`+"\n", i, i, i)
	}
	f.Close()

	st, _ := os.Stat(path)
	if st.Size() <= eveTailInitialWindow {
		t.Fatalf("testfilen (%d B) måste vara större än startfönstret (%d B) för att säga något", st.Size(), eveTailInitialWindow)
	}

	events, err := ReadRecentAlerts(path, 1000)
	if err != nil {
		t.Fatalf("ReadRecentAlerts: %v", err)
	}
	if len(events) != 5 {
		t.Fatalf("fick %d larm, ville ha 5", len(events))
	}
	// Ordning: äldst till nyast, som filen själv.
	if events[0].Signature != "TEST-0" || events[4].Signature != "TEST-4" {
		t.Errorf("fel ordning: första=%q sista=%q", events[0].Signature, events[4].Signature)
	}
}

// TestReadRecentAlertsSmallFile — en fil mindre än fönstret ska läsas helt,
// utan att första raden kastas som avhuggen.
func TestReadRecentAlertsSmallFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	content := `{"timestamp":"2026-08-27T18:00:00.0+0200","event_type":"alert","src_ip":"10.0.0.1","alert":{"signature":"FÖRSTA","category":"Test","severity":1}}
{"event_type":"flow"}
{"timestamp":"2026-08-27T18:01:00.0+0200","event_type":"alert","src_ip":"10.0.0.2","alert":{"signature":"SISTA","category":"Test","severity":3}}
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	events, err := ReadRecentAlerts(path, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("fick %d larm, ville ha 2 (första raden får INTE kastas i en liten fil)", len(events))
	}
	if events[0].Signature != "FÖRSTA" {
		t.Errorf("första larmet = %q, ville ha FÖRSTA", events[0].Signature)
	}
}
