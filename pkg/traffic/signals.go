package traffic

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
)

// Signals är säkerhetsrelaterade räknare per enhet. Det är de här som gör
// vyn till en BRANDVÄGGS-dashboard och inte en generisk trafikmätare: vem
// knackar på stängda dörrar, och vem har utlöst IDS-larm.
type Signals struct {
	BlockedConnections int `json:"blocked_connections"`
	IDSAlerts          int `json:"ids_alerts"`
}

// maxDenyLines är taket för hur många loggrader som läses per uppdatering.
//
// Brandväggen loggar i storleksordningen hundratusen SH-DENY-rader per dygn
// (uppmätt: 1 008 rader på tio minuter). Att läsa ett helt dygn för att räkna
// per enhet vore samma misstag som logg-endpointen gjorde innan den fixades
// — den svalde hela journalctl-utdatan i minnet. Här läses en BEGRÄNSAD
// svans, och siffran presenteras som "senaste N rader", inte som en total.
const maxDenyLines = 20000

// CountBlockedPerDevice räknar SH-DENY-rader per käll-IP.
//
// journalctl anropas med -n för att kapa FÖRE utdata skapas, och utdatan
// strömmas rad för rad i stället för att buffras i sin helhet.
func CountBlockedPerDevice(ctx context.Context, window string) (map[string]int, error) {
	args := []string{"-k", "--no-pager", "-o", "cat", "-g", "SH-DENY", "-n", itoa(maxDenyLines)}
	if window != "" {
		args = append(args, "--since", "-"+window)
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	counts := map[string]int{}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
	for scanner.Scan() {
		if ip := extractSrc(scanner.Text()); ip != "" {
			counts[ip]++
		}
	}
	// Töm röret innan Wait, annars kan processen blockera på en full buffert.
	_ = cmd.Wait()
	return counts, nil
}

// extractSrc plockar ut SRC=<ip> ur en nftables-loggrad.
func extractSrc(line string) string {
	const key = "SRC="
	i := strings.Index(line, key)
	if i < 0 {
		return ""
	}
	rest := line[i+len(key):]
	if j := strings.IndexByte(rest, ' '); j >= 0 {
		rest = rest[:j]
	}
	// IPv6-adresser loggas med nollor utskrivna och hör inte hemma i en
	// IPv4-baserad enhetsvy — de skulle aldrig matcha en enhets IP ändå.
	if strings.Contains(rest, ":") {
		return ""
	}
	return rest
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
