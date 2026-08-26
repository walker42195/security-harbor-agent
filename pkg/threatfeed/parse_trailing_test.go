package threatfeed

import (
	"bufio"
	"strings"
	"testing"
)

func parse(t *testing.T, body string) []string {
	t.Helper()
	return parseGenericCIDRList(bufio.NewScanner(strings.NewReader(body)))
}

// Formatet som fick hela listan att ge noll poster: kommentaren ligger EFTER
// värdet, inte på en egen rad (borestad/blocklist-abuseipdb, 2026-08-26).
func TestTrailingCommentAfterValue(t *testing.T) {
	got := parse(t, `#
# Aggregated Blocklist for AbuseIPDB
#
1.0.164.165      # TH  AS23969   TOT Public Company Limited
1.0.200.1        # TH  AS23969   TOT Public Company Limited
185.220.101.0/24 # DE  AS60729   Tor exit
`)
	want := []string{"1.0.164.165/32", "1.0.200.1/32", "185.220.101.0/24"}
	if len(got) != len(want) {
		t.Fatalf("fick %d poster: %v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("post %d: fick %q, ville ha %q", i, got[i], want[i])
		}
	}
}

func TestSemicolonCommentAfterValue(t *testing.T) {
	// Spamhaus-stilen: värde, semikolon, referens.
	got := parse(t, "1.2.3.0/24 ; SBL123456\n4.5.6.0/24;SBL999\n")
	if len(got) != 2 || got[0] != "1.2.3.0/24" || got[1] != "4.5.6.0/24" {
		t.Fatalf("fick %v", got)
	}
}

// En del listor skriver metadata efter värdet helt utan kommentarstecken.
func TestWhitespaceSeparatedMetadata(t *testing.T) {
	got := parse(t, "8.8.8.8 US Google\n")
	if len(got) != 1 || got[0] != "8.8.8.8/32" {
		t.Fatalf("fick %v", got)
	}
}

func TestFullLineCommentsAndBlanksStillSkipped(t *testing.T) {
	got := parse(t, "\n# rubrik\n; annan kommentar\n\n9.9.9.9\n")
	if len(got) != 1 || got[0] != "9.9.9.9/32" {
		t.Fatalf("fick %v", got)
	}
}

// Skräp ska hoppas över, inte fälla hela hämtningen.
func TestGarbageIsSkipped(t *testing.T) {
	got := parse(t, "inte-en-ip\n999.999.999.999\n10.0.0.1\n<html>\n")
	if len(got) != 1 || got[0] != "10.0.0.1/32" {
		t.Fatalf("fick %v", got)
	}
}
