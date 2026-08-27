package nftables

// JSONRoot representerar rotstrukturen för nftables JSON API (nft -j).
type JSONRoot struct {
	Nftables []NFTElement `json:"nftables"`
}

type NFTElement struct {
	Metainfo *MetaInfo `json:"metainfo,omitempty"`
	Table    *Table    `json:"table,omitempty"`
	Chain    *Chain    `json:"chain,omitempty"`
	Rule     *Rule     `json:"rule,omitempty"`
	Flush    *Flush    `json:"flush,omitempty"`
	Set      *Set      `json:"set,omitempty"`
}

// Set är en NAMNGIVEN nftables-mängd. Stora IP-listor (hot-flöden, GeoIP)
// deklareras en gång som en namngiven mängd och refereras sedan med "@namn"
// från reglerna, i stället för att inlineas som anonym mängd i varje regel.
//
// Bakgrund: en anonym mängd dupliceras per regel. Refererades samma
// AbuseIPDB-lista (>126 000 poster) från flera policies byggdes hela listan
// om en gång per regel som JSON i Go-minne — agenten mättes till 1,4 GB RSS
// på en skarp installation 2026-08-27, mer än Suricata själv.
//
// Deklarationen måste ligga FÖRE de regler som refererar den i samma
// nft-transaktion (se spliceSets i adapter.go).
type Set struct {
	Family string        `json:"family"`          // "inet"
	Table  string        `json:"table"`           // "security_harbor"
	Name   string        `json:"name"`            // nft-identifierare, se setNameFor
	Type   string        `json:"type"`            // "ipv4_addr"
	Flags  []string      `json:"flags,omitempty"` // "interval" krävs för prefix
	Elem   []interface{} `json:"elem,omitempty"`
}

type MetaInfo struct {
	Version string `json:"version"`
	Release string `json:"release_name"`
}

type Flush struct {
	Ruleset interface{} `json:"ruleset"`
}

type Table struct {
	Family string `json:"family"` // "inet", "ip", "ip6"
	Name   string `json:"name"`   // t.ex. "security_harbor"
}

type Chain struct {
	Family string `json:"family"`         // "inet"
	Table  string `json:"table"`          // "security_harbor"
	Name   string `json:"name"`           // "input", "forward", "output", "prerouting", "postrouting"
	Type   string `json:"type,omitempty"` // "filter", "nat"
	Hook   string `json:"hook,omitempty"` // "input", "forward", "output", "prerouting", "postrouting"
	// Prio SAKNAR omitempty MED FLIT. Standardprioriteten för ett filter-hook
	// (input/forward/output) är 0, vilket är Go-nollvärdet för int — med
	// omitempty försvann "prio"-fältet helt ur JSON:en för dessa kedjor, och
	// `nft -j` skapar då en kedja som INTE hookas in i netfilter alls (varken
	// fel eller varning, bara en overksam, oanvänd kedja). Upptäckt vid skarp
	// testning mot brandväggsservern 2026-08-17: INPUT/FORWARD-filtreringen
	// har aldrig faktiskt varit aktiv trots att audit_fas2 markerade den som
	// PASSED (testet tolkade en TCP RST från kärnan som "stängd port", inte
	// som beviset på att paketet aldrig filtrerades). Se
	// TestRenderJSONHooksChainsWithPriority i adapter_test.go.
	Prio   int    `json:"prio"`
	Policy string `json:"policy,omitempty"` // "drop", "accept"
}

type Rule struct {
	Family  string        `json:"family"`
	Table   string        `json:"table"`
	Chain   string        `json:"chain"`
	Expr    []interface{} `json:"expr"`
	Handle  int           `json:"handle,omitempty"`
	Comment string        `json:"comment,omitempty"`
}
