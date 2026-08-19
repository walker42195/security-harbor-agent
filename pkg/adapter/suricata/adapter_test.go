package suricata

import (
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
