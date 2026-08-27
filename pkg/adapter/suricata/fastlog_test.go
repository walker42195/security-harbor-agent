package suricata

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFastLogLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantTS   string
		wantSID  int
		wantSig  string
		wantCat  string
		wantSev  int
		wantSrc  string
		wantSP   int
		wantDst  string
		wantDP   int
		wantProto string
	}{
		{
			name:      "Standard TCP alert",
			line:      "08/27/2026-22:22:10.077338  [**] [1:2003068:7] ET SCAN Potential SSH Scan OUTBOUND [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.0.0.139:51508 -> 107.152.37.150:22",
			wantTS:    "2026-08-27T22:22:10.077338",
			wantSID:   2003068,
			wantSig:   "ET SCAN Potential SSH Scan OUTBOUND",
			wantCat:   "Attempted Information Leak",
			wantSev:   2,
			wantSrc:   "10.0.0.139",
			wantSP:    51508,
			wantDst:   "107.152.37.150",
			wantDP:    22,
			wantProto: "TCP",
		},
		{
			name:      "Null classification",
			line:      "08/27/2026-22:37:07.809536  [**] [1:2210059:2] SURICATA STREAM pkt seen on wrong thread [**] [Classification: (null)] [Priority: 3] {TCP} 188.114.97.1:443 -> 10.13.13.13:51716",
			wantTS:    "2026-08-27T22:37:07.809536",
			wantSID:   2210059,
			wantSig:   "SURICATA STREAM pkt seen on wrong thread",
			wantCat:   "",
			wantSev:   3,
			wantSrc:   "188.114.97.1",
			wantSP:    443,
			wantDst:   "10.13.13.13",
			wantDP:    51716,
			wantProto: "TCP",
		},
		{
			name:      "DNS lookup UDP alert",
			line:      "08/27/2026-22:38:00.081269  [**] [1:2033966:2] ET HUNTING Telegram API Domain in DNS Lookup [**] [Classification: Misc activity] [Priority: 3] {UDP} 10.0.0.59:7069 -> 216.239.36.107:53",
			wantTS:    "2026-08-27T22:38:00.081269",
			wantSID:   2033966,
			wantSig:   "ET HUNTING Telegram API Domain in DNS Lookup",
			wantCat:   "Misc activity",
			wantSev:   3,
			wantSrc:   "10.0.0.59",
			wantSP:    7069,
			wantDst:   "216.239.36.107",
			wantDP:    53,
			wantProto: "UDP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := ParseFastLogLine(tt.line)
			if err != nil {
				t.Fatalf("ParseFastLogLine error: %v", err)
			}
			if ev.Timestamp != tt.wantTS {
				t.Errorf("Timestamp = %q, want %q", ev.Timestamp, tt.wantTS)
			}
			if ev.SID != tt.wantSID {
				t.Errorf("SID = %d, want %d", ev.SID, tt.wantSID)
			}
			if ev.Signature != tt.wantSig {
				t.Errorf("Signature = %q, want %q", ev.Signature, tt.wantSig)
			}
			if ev.Category != tt.wantCat {
				t.Errorf("Category = %q, want %q", ev.Category, tt.wantCat)
			}
			if ev.Severity != tt.wantSev {
				t.Errorf("Severity = %d, want %d", ev.Severity, tt.wantSev)
			}
			if ev.SrcIP != tt.wantSrc || ev.SrcPort != tt.wantSP {
				t.Errorf("Src = %s:%d, want %s:%d", ev.SrcIP, ev.SrcPort, tt.wantSrc, tt.wantSP)
			}
			if ev.DstIP != tt.wantDst || ev.DstPort != tt.wantDP {
				t.Errorf("Dst = %s:%d, want %s:%d", ev.DstIP, ev.DstPort, tt.wantDst, tt.wantDP)
			}
			if ev.Protocol != tt.wantProto {
				t.Errorf("Protocol = %q, want %q", ev.Protocol, tt.wantProto)
			}
		})
	}
}

func TestReadFastLogAlerts(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "fast.log")
	content := "08/27/2026-22:20:00.100000  [**] [1:1001:1] Alert 1 [**] [Priority: 1] {TCP} 10.0.0.1:10 -> 10.0.0.2:20\n" +
		"08/27/2026-22:21:00.200000  [**] [1:1002:1] Alert 2 [**] [Priority: 2] {UDP} 10.0.0.3:30 -> 10.0.0.4:40\n" +
		"08/27/2026-22:22:00.300000  [**] [1:1003:1] Alert 3 Noise [**] [Priority: 3] {TCP} 10.0.0.5:50 -> 10.0.0.6:60\n"

	if err := os.WriteFile(logFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// 1. All events
	events, err := ReadFastLogAlerts(logFile, 10, 0)
	if err != nil {
		t.Fatalf("ReadFastLogAlerts error: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("Got %d events, want 3", len(events))
	}

	// 2. Only blocking/severity 1 & 2
	blockingEvents, err := ReadFastLogAlerts(logFile, 10, 2)
	if err != nil {
		t.Fatalf("ReadFastLogAlerts error: %v", err)
	}
	if len(blockingEvents) != 2 {
		t.Fatalf("Got %d blocking events, want 2", len(blockingEvents))
	}
	if blockingEvents[0].Signature != "Alert 2" || blockingEvents[1].Signature != "Alert 1" {
		t.Errorf("Unexpected blocking events order: %+v", blockingEvents)
	}
}
