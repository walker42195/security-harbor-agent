package traffic

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
)

// eveRecord är de fält vi bryr oss om ur eve.json. Allt annat ignoreras —
// posterna är stora och vi läser dem i strömmande takt.
type eveRecord struct {
	EventType string `json:"event_type"`
	FlowID    int64  `json:"flow_id"`
	SrcIP     string `json:"src_ip"`
	DestIP    string `json:"dest_ip"`
	TLS       *struct {
		SNI string `json:"sni"`
	} `json:"tls"`
	QUIC *struct {
		SNI string `json:"sni"`
	} `json:"quic"`
	HTTP *struct {
		Hostname string `json:"hostname"`
	} `json:"http"`
	DNS *struct {
		Type    string `json:"type"`
		Queries []struct {
			RRName string `json:"rrname"`
		} `json:"queries"`
	} `json:"dns"`
	Flow *struct {
		BytesToServer uint64 `json:"bytes_toserver"`
		BytesToClient uint64 `json:"bytes_toclient"`
	} `json:"flow"`
}

// flowNames binder ett flow_id till det domännamn som sågs i handskakningen.
//
// Behövs eftersom namnet och byten kommer i SKILDA poster: SNI:t syns i
// tls/quic-posten när anslutningen öppnas, medan byten rapporteras först i
// flow-posten när den stängs. Kartan är därför en kort mellanlagring mellan
// de två, inte ett register.
type flowNames struct {
	mu    sync.Mutex
	names map[int64]string
	// max hindrar kartan från att växa obegränsat om flow-poster uteblir
	// (t.ex. långlivade anslutningar som aldrig stängs). Vid taket töms den
	// helt: att tappa namnet på pågående flöden ger några felklassificerade
	// poster, medan en obegränsad karta är en läcka.
	max int
}

func newFlowNames(max int) *flowNames {
	return &flowNames{names: map[int64]string{}, max: max}
}

func (f *flowNames) put(id int64, name string) {
	if id == 0 || name == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.names) >= f.max {
		f.names = map[int64]string{}
	}
	f.names[id] = name
}

func (f *flowNames) take(id int64) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.names[id]
	delete(f.names, id)
	return n
}

// CategoryHit är ett klassificerat flöde.
type CategoryHit struct {
	IP       string
	Category Category
	Domain   string
	Rx       uint64 // byte TILL enheten
	Tx       uint64 // byte FRÅN enheten
}

// EveReader läser eve.json inkrementellt.
//
// Positionen sparas mellan anropen, så bara det som tillkommit sedan förra
// gången läses. Rotation upptäcks genom att filen blivit MINDRE än vår
// position — då börjar vi om från början av den nya filen. Utan det hade
// läsaren tystnat efter första logrotate.
type EveReader struct {
	path   string
	offset int64
	size   int64
	flows  *flowNames
	// localPrefixes avgör vilka adresser som räknas som "enhet". Utan dem
	// hade även fjärrsidan av varje flöde bokförts som en lokal enhet.
	isLocal func(ip string) bool
}

func NewEveReader(path string, isLocal func(string) bool) *EveReader {
	return &EveReader{path: path, flows: newFlowNames(20000), isLocal: isLocal}
}

// maxEveBytesPerRead är taket per anrop. Har filen vuxit mer än så sedan
// förra läsningen hoppar vi fram till slutet i stället för att läsa ikapp:
// klassificeringen ska aldrig kunna bli en I/O-storm efter ett driftstopp.
const maxEveBytesPerRead = 32 << 20

// Read returnerar de flöden som tillkommit sedan förra anropet.
func (r *EveReader) Read() ([]CategoryHit, error) {
	f, err := os.Open(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()

	if size < r.offset {
		// Filen har roterats eller trunkerats.
		r.offset = 0
	}
	if size-r.offset > maxEveBytesPerRead {
		r.offset = size - maxEveBytesPerRead
	}
	if size == r.offset {
		return nil, nil
	}
	if _, err := f.Seek(r.offset, 0); err != nil {
		return nil, err
	}

	var hits []CategoryHit
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	read := r.offset
	for scanner.Scan() {
		line := scanner.Bytes()
		read += int64(len(line)) + 1
		if h, ok := r.consume(line); ok {
			hits = append(hits, h)
		}
	}
	r.offset = read
	r.size = size
	return hits, scanner.Err()
}

func (r *EveReader) consume(line []byte) (CategoryHit, bool) {
	var rec eveRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		return CategoryHit{}, false
	}

	switch rec.EventType {
	case "tls":
		if rec.TLS != nil {
			r.flows.put(rec.FlowID, rec.TLS.SNI)
		}
	case "quic":
		if rec.QUIC != nil {
			r.flows.put(rec.FlowID, rec.QUIC.SNI)
		}
	case "http":
		if rec.HTTP != nil {
			r.flows.put(rec.FlowID, rec.HTTP.Hostname)
		}
	case "dns":
		// Bara förfrågningar, inte svar: annars bokförs varje uppslag två
		// gånger, och svaret har dessutom resolvern som källa.
		if rec.DNS != nil && rec.DNS.Type == "query" && len(rec.DNS.Queries) > 0 {
			r.flows.put(rec.FlowID, rec.DNS.Queries[0].RRName)
		}
	case "flow":
		if rec.Flow == nil {
			return CategoryHit{}, false
		}
		domain := r.flows.take(rec.FlowID)

		// Riktningen avgörs av vilken sida som är lokal. Ett flöde där
		// brandväggen själv är källa (t.ex. dess egna uppdateringar) hör inte
		// till någon enhet på nätet.
		var ip string
		var rx, tx uint64
		switch {
		case r.isLocal(rec.SrcIP):
			ip, rx, tx = rec.SrcIP, rec.Flow.BytesToClient, rec.Flow.BytesToServer
		case r.isLocal(rec.DestIP):
			ip, rx, tx = rec.DestIP, rec.Flow.BytesToServer, rec.Flow.BytesToClient
		default:
			return CategoryHit{}, false
		}
		if rx == 0 && tx == 0 {
			return CategoryHit{}, false
		}
		return CategoryHit{
			IP: ip, Category: Classify(domain), Domain: domain, Rx: rx, Tx: tx,
		}, true
	}
	return CategoryHit{}, false
}
