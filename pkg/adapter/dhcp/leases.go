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
	// Senare rader för samma IP skriver över tidigare (memfile är historik).
	byIP := map[string]LeaseDetail{}

	err := forEachLeaseRow(path, func(get func(string) string) {
		addr := get("address")
		if addr == "" {
			return
		}
		// state: 0 = aktiv. Tomt behandlas också som aktivt.
		if st := get("state"); st != "" && st != "0" {
			delete(byIP, addr) // en senare icke-aktiv rad tar bort en tidigare aktiv
			return
		}
		parseInt := func(name string) int64 {
			if v, perr := strconv.ParseInt(get(name), 10, 64); perr == nil {
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
		byIP[addr] = LeaseDetail{
			IP:       addr,
			MAC:      get("hwaddr"),
			Hostname: get("hostname"),
			StartTS:  start,
			ExpireTS: expire,
		}
	})
	if err != nil {
		return nil, err
	}

	out := make([]LeaseDetail, 0, len(byIP))
	for _, l := range byIP {
		out = append(out, l)
	}
	return out, nil
}

// leaseFiles returnerar de filer som TILLSAMMANS utgör Kea:s lease-databas,
// i ÄLDST-FÖRST-ordning.
//
// Kea:s memfile-backend kör periodiskt LFC (Lease File Cleanup): den aktuella
// filen döps om, en ny tom skapas, och den konsoliderade historiken skrivs
// till en syskonfil. Under och efter en sådan städning ligger utlåningarna
// alltså i FLERA filer samtidigt.
//
// Att bara läsa kea-leases4.csv gav då bilden att nästan alla utlåningar
// försvunnit — skarpt 2026-08-26: LFC körde 11:15 och GUI:t visade två
// leasar i stället för ett femtiotal, både under DHCP-klienter och under
// automatiskt registrerade DNS-enheter (som läser samma fil). Ingenting hade
// gått förlorat; agenten läste bara en fjärdedel av databasen.
//
// Ordningen är viktig: den aktuella filen läses SIST så att dess rader vinner
// över äldre historik för samma adress.
func leaseFiles(path string) []string {
	return []string{
		path + ".completed", // färdig LFC-utdata, väntar på att laddas in
		path + ".2",         // LFC-utdata under skrivning (eller avbruten körning)
		path + ".1",         // LFC-indata: den tidigare aktuella filen
		path,                // aktuell fil - nyast, vinner
	}
}

// forEachLeaseRow läser samtliga lease-filer och anropar fn för varje rad.
//
// Kolumnuppslagningen görs per FIL, inte en gång för alla: filerna kan vara
// skrivna av olika Kea-versioner med olika kolumnordning, och en LFC-utdata
// behöver inte ha samma header som den aktuella filen.
//
// En fil som saknas är inget fel (LFC-filerna finns bara ibland). Ett riktigt
// läsfel på EN fil stoppar inte de övriga — hellre en delvis lista än ingen.
func forEachLeaseRow(path string, fn func(get func(string) string)) error {
	var firstErr error
	for _, p := range leaseFiles(path) {
		f, err := os.Open(p)
		if err != nil {
			if !os.IsNotExist(err) && firstErr == nil {
				firstErr = err
			}
			continue
		}
		r := csv.NewReader(f)
		r.FieldsPerRecord = -1
		records, err := r.ReadAll()
		f.Close()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if len(records) < 2 {
			continue
		}
		col := map[string]int{}
		for i, name := range records[0] {
			col[name] = i
		}
		for _, row := range records[1:] {
			fn(func(name string) string {
				if idx, ok := col[name]; ok && idx < len(row) {
					return row[idx]
				}
				return ""
			})
		}
	}
	return firstErr
}

// ParseLeaseFile returnerar de aktiva utlåningar som har ett värdnamn — de
// utan (klienten skickade ingen DHCP option 12) kan inte registreras i DNS.
//
// Bygger på ParseLeasesDetailed i stället för att tolka filerna en gång till.
// Den egna kopian hade ett fel de detaljerade utlåningarna inte hade: en
// senare rad med icke-aktivt tillstånd HOPPADES ÖVER i stället för att ta
// bort den tidigare aktiva raden, så en frisläppt adress kunde ligga kvar i
// DNS-zonen tills agenten startades om.
func ParseLeaseFile(path string) ([]Lease, error) {
	details, err := ParseLeasesDetailed(path)
	if err != nil {
		return nil, err
	}
	leases := make([]Lease, 0, len(details))
	for _, d := range details {
		if d.Hostname == "" {
			continue
		}
		leases = append(leases, Lease{IP: d.IP, Hostname: d.Hostname})
	}
	return leases, nil
}
