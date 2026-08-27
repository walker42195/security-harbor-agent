package suricata

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// fastLogRegex matchar en rad ur Suricatas fast.log.
// Exempel:
// 08/27/2026-22:22:10.077338  [**] [1:2003068:7] ET SCAN Potential SSH Scan OUTBOUND [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.0.0.139:51508 -> 107.152.37.150:22
var fastLogRegex = regexp.MustCompile(`^(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[\d+:(\d+):\d+\]\s+(.*?)\s+\[\*\*\](?:\s+\[Classification:\s*(.*?)\])?\s+\[Priority:\s*(\d+)\]\s+\{([^}]+)\}\s+(\S+)\s+->\s+(\S+)`)

// parseFastLogTimestamp konverterar "08/27/2026-22:22:10.077338" till ISO "2026-08-27T22:22:10.077338"
func parseFastLogTimestamp(raw string) string {
	if len(raw) < 26 {
		return raw
	}
	// raw: MM/DD/YYYY-HH:MM:SS.uuuuuu
	mm := raw[0:2]
	dd := raw[3:5]
	yyyy := raw[6:10]
	rest := raw[11:]
	return fmt.Sprintf("%s-%s-%sT%s", yyyy, mm, dd, rest)
}

func parseHostPort(hp string) (string, int) {
	if idx := strings.LastIndex(hp, ":"); idx != -1 {
		ip := hp[:idx]
		port, err := strconv.Atoi(hp[idx+1:])
		if err == nil {
			return ip, port
		}
	}
	return hp, 0
}

// ParseFastLogLine parsar en enskild rad ur fast.log till SecurityEvent.
func ParseFastLogLine(line string) (*config.SecurityEvent, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("tom rad")
	}
	m := fastLogRegex.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Errorf("okänt format: %s", line)
	}

	ts := parseFastLogTimestamp(m[1])
	sid, _ := strconv.Atoi(m[2])
	signature := strings.TrimSpace(m[3])
	category := strings.TrimSpace(m[4])
	if category == "(null)" {
		category = ""
	}
	priority, _ := strconv.Atoi(m[5])
	proto := strings.ToUpper(strings.TrimSpace(m[6]))
	srcIP, srcPort := parseHostPort(m[7])
	dstIP, dstPort := parseHostPort(m[8])

	return &config.SecurityEvent{
		Timestamp: ts,
		Severity:  priority,
		Signature: signature,
		SID:       sid,
		Category:  category,
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		DstIP:     dstIP,
		DstPort:   dstPort,
		Protocol:  proto,
	}, nil
}

// ReadFastLogAlerts läser larm ur fast.log bakifrån.
// Om maxSeverity > 0 (t.ex. 2 för Severity 1 och 2) filtreras lägre
// allvarlighetsgrader (som L2/decoder/stream-brus på Severity 3) bort
// under skanningen så att alla relevanta säkerhetslarm i hela loggens
// historik samlas in.
func ReadFastLogAlerts(fastLogPath string, maxLines int, maxSeverity int) ([]config.SecurityEvent, error) {
	if maxLines <= 0 {
		maxLines = 1000
	}
	f, err := os.Open(fastLogPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []config.SecurityEvent{}, nil
		}
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if size == 0 {
		return []config.SecurityEvent{}, nil
	}

	const chunkSize = 512 * 1024
	var events []config.SecurityEvent
	var leftover []byte

	offset := size
	for offset > 0 && len(events) < maxLines {
		readSize := int64(chunkSize)
		if offset < readSize {
			readSize = offset
		}
		offset -= readSize

		buf := make([]byte, readSize)
		if _, err := f.ReadAt(buf, offset); err != nil {
			break
		}

		if len(leftover) > 0 {
			buf = append(buf, leftover...)
			leftover = nil
		}

		for {
			lastNL := strings.LastIndexByte(string(buf), '\n')
			if lastNL == -1 {
				if offset > 0 {
					leftover = buf
				} else {
					line := strings.TrimSpace(string(buf))
					if line != "" {
						if ev, err := ParseFastLogLine(line); err == nil {
							if maxSeverity <= 0 || ev.Severity <= maxSeverity {
								events = append(events, *ev)
							}
						}
					}
				}
				break
			}

			line := strings.TrimSpace(string(buf[lastNL+1:]))
			buf = buf[:lastNL]

			if line == "" {
				continue
			}

			ev, err := ParseFastLogLine(line)
			if err != nil {
				continue
			}

			if maxSeverity > 0 && ev.Severity > maxSeverity {
				continue
			}

			events = append(events, *ev)
			if len(events) >= maxLines {
				break
			}
		}
	}

	return events, nil
}
