package threatfeed

import (
	"bufio"
	"strings"
	"testing"
)

func TestParseSpamhaus(t *testing.T) {
	input := `; Spamhaus DROP List
; Last updated ...
;
1.2.3.0/24 ; SBL123456
5.6.7.8/32 ; SBL987654
`
	got := parseSpamhaus(bufio.NewScanner(strings.NewReader(input)))
	want := []string{"1.2.3.0/24", "5.6.7.8/32"}
	if len(got) != len(want) {
		t.Fatalf("fel antal poster: fick %v, ville ha %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("post %d: fick %q, ville ha %q", i, got[i], want[i])
		}
	}
}

func TestParseTorExitList(t *testing.T) {
	input := "# Tor exit list\n1.1.1.1\n2.2.2.2\n\n3.3.3.3\n"
	got := parseTorExitList(bufio.NewScanner(strings.NewReader(input)))
	want := []string{"1.1.1.1/32", "2.2.2.2/32", "3.3.3.3/32"}
	if len(got) != len(want) {
		t.Fatalf("fel antal poster: fick %v, ville ha %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("post %d: fick %q, ville ha %q", i, got[i], want[i])
		}
	}
}

func TestParseHostsFileDomains(t *testing.T) {
	input := `# Title: StevenBlack hosts
127.0.0.1 localhost
127.0.0.1 localhost.localdomain
::1 ip6-localhost
0.0.0.0 malware.example.com
0.0.0.0 tracker.example.net
127.0.0.1 ads.example.org
`
	got := parseHostsFileDomains(bufio.NewScanner(strings.NewReader(input)))
	want := []string{"malware.example.com", "tracker.example.net", "ads.example.org"}
	if len(got) != len(want) {
		t.Fatalf("fel antal domäner (loopback-poster ska hoppas över): fick %v, ville ha %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("post %d: fick %q, ville ha %q", i, got[i], want[i])
		}
	}
}

func TestParseGenericCIDRList(t *testing.T) {
	input := "# comment\n10.0.0.0/8\n; also comment\n192.168.1.0/24\ninvalid-line\n"
	got := parseGenericCIDRList(bufio.NewScanner(strings.NewReader(input)))
	want := []string{"10.0.0.0/8", "192.168.1.0/24"}
	if len(got) != len(want) {
		t.Fatalf("fel antal poster (ogiltiga rader ska hoppas över): fick %v, ville ha %v", got, want)
	}
}
