package dhcp

import (
	"encoding/csv"
	"os"
	"strconv"
)

// Lease är en aktiv DHCP-utlåning enligt Kea:s lease-memfile (CSV).
type Lease struct {
	IP       string
	Hostname string
}

// LeaseDetail är en aktiv DHCP-utlåning med alla fält som DHCP-klientvyn
// (GUI) behöver — till skillnad från Lease (som bara bär IP+Hostname för
// DNS-registrering). Interface fylls i av API-lagret genom att matcha IP
// mot gränssnittens subnät (finns inte i lease-filen).
type LeaseDetail struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Hostname  string `json:"hostname"`
	StartTS   int64  `json:"start_ts"`  // när leasen gavs (expire - valid_lifetime), unix-sek
	ExpireTS  int64  `json:"expire_ts"` // när leasen går ut, unix-sek
	Interface string `json:"interface"`
	Zone      string `json:"zone"`
}

// ParseLeasesDetailed läser Kea:s lease-memfile och returnerar ALLA aktiva
// utlåningar (även de utan värdnamn, till skillnad från ParseLeaseFile som
// bara tar med namngivna för DNS). Interface/Zone lämnas tomma — de fylls i
// av anroparen som har konfigurationen.
func ParseLeasesDetailed(path string) ([]LeaseDetail, error) {
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
	addrIdx, ok := col["address"]
	if !ok {
		return nil, nil
	}
	get := func(row []string, name string) string {
		if idx, ok := col[name]; ok && idx < len(row) {
			return row[idx]
		}
		return ""
	}

	// Senare rader för samma IP skriver över tidigare (memfile är historik).
	byIP := map[string]LeaseDetail{}
	for _, row := range records[1:] {
		if addrIdx >= len(row) || row[addrIdx] == "" {
			continue
		}
		// state: 0 = aktiv. Tomt behandlas också som aktivt.
		if st := get(row, "state"); st != "" && st != "0" {
			delete(byIP, row[addrIdx]) // en senare icke-aktiv rad tar bort en tidigare aktiv
			continue
		}
		parseInt := func(name string) int64 {
			if v, perr := strconv.ParseInt(get(row, name), 10, 64); perr == nil {
				return v
			}
			return 0
		}
		expire := parseInt("expire")
		validLifetime := parseInt("valid_lifetime")
		var start int64
		if expire > 0 && validLifetime > 0 {
			start = expire - validLifetime // Kea lagrar utgång + livslängd; startpunkten (cltt) är differensen
		}
		byIP[row[addrIdx]] = LeaseDetail{
			IP:       row[addrIdx],
			MAC:      get(row, "hwaddr"),
			Hostname: get(row, "hostname"),
			StartTS:  start,
			ExpireTS: expire,
		}
	}

	out := make([]LeaseDetail, 0, len(byIP))
	for _, l := range byIP {
		out = append(out, l)
	}
	return out, nil
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
