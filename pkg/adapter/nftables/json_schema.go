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
	Family   string `json:"family"`   // "inet"
	Table    string `json:"table"`    // "security_harbor"
	Name     string `json:"name"`     // "input", "forward", "output", "prerouting", "postrouting"
	Type     string `json:"type,omitempty"`     // "filter", "nat"
	Hook     string `json:"hook,omitempty"`     // "input", "forward", "output", "prerouting", "postrouting"
	Prio     int    `json:"prio,omitempty"`     // Priority
	Policy   string `json:"policy,omitempty"`   // "drop", "accept"
}

type Rule struct {
	Family string        `json:"family"`
	Table  string        `json:"table"`
	Chain  string        `json:"chain"`
	Expr   []interface{} `json:"expr"`
	Handle int           `json:"handle,omitempty"`
	Comment string       `json:"comment,omitempty"`
}
