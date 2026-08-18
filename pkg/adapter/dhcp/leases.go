package dhcp

import (
	"encoding/csv"
	"os"
)

// Lease är en aktiv DHCP-utlåning enligt Kea:s lease-memfile (CSV).
type Lease struct {
	IP       string
	Hostname string
}

// ParseLeaseFile läser Kea:s "memfile"-lease-databas (CSV, se
// LeaseDatabase.Name i adapter.go) och returnerar aktiva utlåningar som
// har ett värdnamn — de utan värdnamn (klienten skickade inget DHCP
// option 12) kan inte registreras i DNS och hoppas över.
//
// Kolumnordningen läses ur CSV-headern istället för att antas, eftersom
// den kan skilja mellan Kea-versioner.
func ParseLeaseFile(path string) ([]Lease, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}

	col := map[string]int{}
	for i, name := range records[0] {
		col[name] = i
	}
	addrIdx, ok1 := col["address"]
	hostIdx, ok2 := col["hostname"]
	if !ok1 || !ok2 {
		return nil, nil
	}
	stateIdx, hasState := col["state"]

	// Senare rader för samma IP skriver över tidigare (Kea memfile
	// innehåller lease-historik, inte bara aktuellt tillstånd).
	byIP := map[string]Lease{}
	for _, row := range records[1:] {
		if addrIdx >= len(row) || hostIdx >= len(row) {
			continue
		}
		hostname := row[hostIdx]
		if hostname == "" {
			continue
		}
		// state: 0 = default/active, 1 = declined, 2 = expired-reclaimed.
		if hasState && stateIdx < len(row) && row[stateIdx] != "" && row[stateIdx] != "0" {
			continue
		}
		byIP[row[addrIdx]] = Lease{IP: row[addrIdx], Hostname: hostname}
	}

	leases := make([]Lease, 0, len(byIP))
	for _, l := range byIP {
		leases = append(leases, l)
	}
	return leases, nil
}
