// Package threatfeed hämtar och tolkar externa hot-listor och GeoIP-
// landsblock (Fas 5) och skriver om dem till platta CIDR-listor som kan
// användas direkt som Object.Values (och därmed matchas i nftables-
// adaptern precis som en manuellt inmatad IP-lista).
package threatfeed

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	KindSpamhausDROP  = "spamhaus_drop"
	KindSpamhausEDROP = "spamhaus_edrop"
	KindTorExitNodes  = "tor_exit_nodes"
	KindCustomURL     = "custom_url"
	KindGeoIPCountry  = "geoip_country"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

// Fetch hämtar och tolkar en källa till en lista av CIDR/IP-strängar,
// baserat på Kind. url och countryCode används bara för respektive Kind.
func Fetch(kind, url, countryCode string) ([]string, error) {
	switch kind {
	case KindSpamhausDROP:
		return fetchLines("https://www.spamhaus.org/drop/drop.txt", parseSpamhaus)
	case KindSpamhausEDROP:
		return fetchLines("https://www.spamhaus.org/drop/edrop.txt", parseSpamhaus)
	case KindTorExitNodes:
		return fetchLines("https://check.torproject.org/torbulkexitlist", parseTorExitList)
	case KindCustomURL:
		if url == "" {
			return nil, fmt.Errorf("custom_url kräver en URL")
		}
		return fetchLines(url, parseGenericCIDRList)
	case KindGeoIPCountry:
		cc := strings.ToLower(strings.TrimSpace(countryCode))
		if cc == "" {
			return nil, fmt.Errorf("geoip_country kräver en landskod (ISO 3166-1 alpha-2)")
		}
		return fetchLines(fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/countries/%s.zone", cc), parseGenericCIDRList)
	default:
		return nil, fmt.Errorf("okänd hot-listekälla: %q", kind)
	}
}

func fetchLines(url string, parse func(*bufio.Scanner) []string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "security-harbor-agent/threatfeed")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hämtning av %s misslyckades: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hämtning av %s gav HTTP %d", url, resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	values := parse(scanner)
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("misslyckades läsa svar från %s: %w", url, err)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%s gav en tom lista — avbryter för att inte ersätta en fungerande hot-lista med tom data", url)
	}
	return values, nil
}

// parseSpamhaus tolkar Spamhaus DROP/EDROP-formatet: "CIDR ; SBLxxxxx",
// kommentarer inleds med ';' på egen rad.
func parseSpamhaus(scanner *bufio.Scanner) []string {
	var out []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		cidr := strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
		if isValidCIDROrIP(cidr) {
			out = append(out, normalizeCIDR(cidr))
		}
	}
	return out
}

// parseTorExitList tolkar torbulkexitlist-formatet: en IPv4-adress per rad,
// kommentarer inleds med '#'.
func parseTorExitList(scanner *bufio.Scanner) []string {
	var out []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if isValidCIDROrIP(line) {
			out = append(out, normalizeCIDR(line))
		}
	}
	return out
}

// parseGenericCIDRList tolkar en enkel textfil med en CIDR/IP per rad
// (används både för anpassade blocklistor och ipdeny.com:s landszonfiler).
// Kommentarer (#, ;) och tomma rader hoppas över.
func parseGenericCIDRList(scanner *bufio.Scanner) []string {
	var out []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if isValidCIDROrIP(line) {
			out = append(out, normalizeCIDR(line))
		}
	}
	return out
}

func isValidCIDROrIP(s string) bool {
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

func normalizeCIDR(s string) string {
	if strings.Contains(s, "/") {
		return s
	}
	ip := net.ParseIP(s)
	if ip.To4() != nil {
		return s + "/32"
	}
	return s + "/128"
}
