package api

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Regressionstest för den strömmande journalläsningen (0.43.0). Ett fejkat
// journalctl tidigare i PATH matar in RIKTIGA loggrader från en skarp
// brandvägg (testdata_fwlog.txt), så testet fångar både argumenthantering,
// strömningen och ringbufferten — inte bara regexen.
func withFakeJournalctl(t *testing.T, output string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\ncat " + filepath.Join(dir, "out.txt") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "out.txt"), []byte(output), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestParseFirewallLogWindowStreamsEntries(t *testing.T) {
	raw, err := os.ReadFile("testdata_fwlog.txt")
	if err != nil {
		t.Skip("ingen testdata")
	}
	withFakeJournalctl(t, string(raw))

	entries, truncated := parseFirewallLogWindow("5m")
	if len(entries) == 0 {
		t.Fatalf("inga poster tolkade ur %d bytes riktig journaldata", len(raw))
	}
	if truncated {
		t.Errorf("truncated=true för en liten indata")
	}
	for i, e := range entries {
		if e.SrcIP == "" || e.Timestamp == "" || e.Action == "" {
			t.Errorf("post %d ofullständig: %+v", i, e)
		}
	}
	t.Logf("tolkade %d poster", len(entries))
}

// Fler poster än taket: verifierar att ringbufferten behåller de NYASTE
// posterna, i rätt ordning, och sätter truncated. Den första versionen av
// ringbufferten var korrekt men O(n) per post (memmove av hela bufferten),
// vilket pinnade en kärna på långa fönster — testet nedan kör tillräckligt
// många rader att en sådan implementation blir mätbart långsam.
func TestParseFirewallLogWindowRingBuffer(t *testing.T) {
	raw, err := os.ReadFile("testdata_fwlog.txt")
	if err != nil {
		t.Skip("ingen testdata")
	}
	tmpl := strings.SplitN(strings.TrimRight(string(raw), "\n"), "\n", 2)[0]

	var b strings.Builder
	const n = firewallLogMaxEntries + 2000
	for i := 0; i < n; i++ {
		// Unik käll-IP per rad så vi kan se exakt vilka som behölls.
		line := strings.Replace(tmpl, "SRC=10.0.0.139",
			fmt.Sprintf("SRC=10.%d.%d.%d", i/65536%256, i/256%256, i%256), 1)
		b.WriteString(line)
		b.WriteByte('\n')
	}
	withFakeJournalctl(t, b.String())

	start := time.Now()
	entries, truncated := parseFirewallLogWindow("7d")
	elapsed := time.Since(start)

	if len(entries) != firewallLogMaxEntries {
		t.Fatalf("fick %d poster, ville ha %d", len(entries), firewallLogMaxEntries)
	}
	if !truncated {
		t.Error("truncated ska vara true när indata överstiger taket")
	}
	// Äldsta kvarvarande posten ska vara rad (n - tak), nyaste rad (n-1).
	wantFirst := fmt.Sprintf("SRC=10.%d.%d.%d", (n-firewallLogMaxEntries)/65536%256, (n-firewallLogMaxEntries)/256%256, (n-firewallLogMaxEntries)%256)
	wantFirst = strings.TrimPrefix(wantFirst, "SRC=")
	if entries[0].SrcIP != wantFirst {
		t.Errorf("äldsta kvarvarande = %q, ville ha %q (fel ordning i ringbufferten?)", entries[0].SrcIP, wantFirst)
	}
	wantLast := fmt.Sprintf("10.%d.%d.%d", (n-1)/65536%256, (n-1)/256%256, (n-1)%256)
	if entries[len(entries)-1].SrcIP != wantLast {
		t.Errorf("nyaste = %q, ville ha %q", entries[len(entries)-1].SrcIP, wantLast)
	}
	t.Logf("%d rader -> %d poster på %s", n, len(entries), elapsed)
}
