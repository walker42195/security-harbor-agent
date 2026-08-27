package traffic

import (
	"sync"
	"time"
)

// Counters är kumulativa byte för en enhet, som kärnan rapporterar dem.
type Counters struct {
	RxBytes uint64
	TxBytes uint64
}

// Rate är ögonblicksbandbredd i byte per sekund.
type Rate struct {
	RxBps uint64 `json:"rx_bps"`
	TxBps uint64 `json:"tx_bps"`
}

// Collector omvandlar kumulativa kärnräknare till deltan och matar Store.
//
// Räknarna kan nollställas när som helst: huvudregelsetet renderas med
// "flush ruleset" vid varje policyändring, mängdelement har timeout, och
// lådan kan startas om. Ett värde som SJUNKIT sedan förra avläsningen tolkas
// därför som en nollställning, och det nya värdet räknas i sin helhet — att
// i stället beräkna cur-prev hade gett ett gigantiskt negativt tal som
// wrappat runt till flera exabyte.
type Collector struct {
	mu    sync.Mutex
	store *Store
	prev  map[string]Counters
	last  time.Time
	rates map[string]Rate
}

func NewCollector(store *Store) *Collector {
	return &Collector{store: store, prev: map[string]Counters{}, rates: map[string]Rate{}}
}

// Sample bokför en avläsning. cur är kumulativa värden per IP.
func (c *Collector) Sample(now time.Time, cur map[string]Counters) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elapsed := now.Sub(c.last).Seconds()
	first := c.last.IsZero()
	rates := make(map[string]Rate, len(cur))

	for ip, cc := range cur {
		p, seen := c.prev[ip]
		rx, tx := delta(cc.RxBytes, p.RxBytes, seen), delta(cc.TxBytes, p.TxBytes, seen)

		// Vid FÖRSTA avläsningen efter uppstart vet vi inte hur lång tid
		// räknarna byggts upp under — de kan vara timmar gamla. Att bokföra
		// dem som trafik "nu" hade gett en falsk spik i grafen, så första
		// avläsningen används bara för att sätta utgångsläget.
		if !first {
			c.store.Add(now, ip, rx, tx)
			if elapsed > 0 {
				rates[ip] = Rate{
					RxBps: uint64(float64(rx) / elapsed),
					TxBps: uint64(float64(tx) / elapsed),
				}
			}
		}
	}

	c.prev = cur
	c.last = now
	if !first {
		c.rates = rates
	}
}

// delta hanterar nollställning: ett värde som sjunkit betyder att räknaren
// startat om, och då är hela det nya värdet ny trafik.
func delta(cur, prev uint64, seen bool) uint64 {
	if !seen || cur < prev {
		return cur
	}
	return cur - prev
}

// Rates returnerar senaste uppmätta bandbredd per IP.
func (c *Collector) Rates() map[string]Rate {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]Rate, len(c.rates))
	for ip, r := range c.rates {
		out[ip] = r
	}
	return out
}
