package engine

import (
	"context"
	"sort"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/nftables"
	"github.com/walker42195/security-harbor-agent/pkg/traffic"
)

const (
	// trafficSampleInterval styr både realtidssiffrorna och hur finkornig
	// minutupplösningen blir. 10 s ger läsbar realtid utan att avläsningen
	// (en nft-listning av två mängder) blir en märkbar last.
	trafficSampleInterval = 10 * time.Second
	// trafficSaveInterval: historiken sparas sällan, eftersom Save är en
	// no-op när inget ändrats och en full omskrivning när något har det.
	trafficSaveInterval = 2 * time.Minute
	// trafficRetention: enheter som inte synts på så här länge tas bort helt.
	// Ringbuffertarna är fasta i storlek, men det finns en per enhet — utan
	// den här städningen växer ANTALET enheter obegränsat på en låda som
	// sett tusentals kortlivade DHCP-adresser genom åren.
	trafficRetention = 180 * 24 * time.Hour

	// dhcpLeasePath speglar pkg/adapter/dhcp.defaultLeaseDBPath (opublicerad
	// där). Används bara för att slå upp värdnamn — saknas filen visas
	// enheterna med IP och tillverkare i stället.
	dhcpLeasePath = "/var/lib/kea/kea-leases4.csv"
)

// StartTrafficCollection kör avläsning, sparning och städning tills ctx avbryts.
func (e *Engine) StartTrafficCollection(ctx context.Context) {
	e.ensureAccounting(ctx)

	sample := time.NewTicker(trafficSampleInterval)
	save := time.NewTicker(trafficSaveInterval)
	prune := time.NewTicker(24 * time.Hour)
	defer sample.Stop()
	defer save.Stop()
	defer prune.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = e.trafficStore.Save()
			_ = e.inventory.SaveFirstSeen()
			return
		case <-sample.C:
			e.sampleTraffic(ctx)
		case <-save.C:
			_ = e.trafficStore.Save()
			_ = e.inventory.SaveFirstSeen()
		case <-prune.C:
			e.trafficStore.Prune(time.Now(), trafficRetention)
		}
	}
}

// ensureAccounting (åter)skapar mättabellen. Måste köras efter varje
// applicering av huvudregelsetet: det renderas med "flush ruleset", vilket
// tar bort ALLA tabeller — även den här.
func (e *Engine) ensureAccounting(ctx context.Context) {
	cfg := e.store.GetRunningConfig()
	if cfg == nil {
		return
	}
	_ = nftables.ApplyAccounting(ctx, cfg, "inet")
}

func (e *Engine) sampleTraffic(ctx context.Context) {
	counters, err := nftables.ReadAccountingCounters(ctx, "inet")
	if err != nil {
		return
	}
	// Tom avläsning betyder oftast att tabellen försvunnit i en flush —
	// återskapa den och ta nästa varv.
	if len(counters) == 0 {
		e.ensureAccounting(ctx)
		return
	}
	cur := make(map[string]traffic.Counters, len(counters))
	for ip, c := range counters {
		cur[ip] = traffic.Counters{RxBytes: c.RxBytes, TxBytes: c.TxBytes}
	}
	e.trafficColl.Sample(time.Now(), cur)
}

// DeviceStat är en rad i dashboardens enhetstabell.
type DeviceStat struct {
	traffic.Device
	RxBps uint64 `json:"rx_bps"`
	TxBps uint64 `json:"tx_bps"`
	// Totalt under det valda fönstret.
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
	traffic.Signals
	// Sparkline är de senaste punkterna i minutupplösning, för minigrafen
	// i tabellraden.
	Sparkline []traffic.Point `json:"sparkline,omitempty"`
	// IsNew markerar enheter som setts första gången det senaste dygnet.
	IsNew bool `json:"is_new"`
}

// DashboardData är hela svaret till dashboarden.
type DashboardData struct {
	Devices []DeviceStat `json:"devices"`
	// Zones summerar per zon, så man ser vilket segment som drar mest.
	Zones map[string]traffic.Point `json:"zones"`
	// Totals är summan över alla enheter i fönstret.
	Totals traffic.Point `json:"totals"`
	// TotalRxBps/TxBps är summan av realtidshastigheterna.
	TotalRxBps uint64 `json:"total_rx_bps"`
	TotalTxBps uint64 `json:"total_tx_bps"`
	Resolution string `json:"resolution"`
	SampledAt  int64  `json:"sampled_at"`
}

// GetDashboard bygger dashboardens data för en given upplösning
// ("1m", "5m", "1h", "1d").
func (e *Engine) GetDashboard(ctx context.Context, resolution string, sparklinePoints int) DashboardData {
	if resolution == "" {
		resolution = "5m"
	}
	cfg := e.store.GetRunningConfig()
	zoneOf := func(dev string) string {
		if cfg == nil {
			return ""
		}
		for _, i := range cfg.Interfaces {
			if i.Device == dev {
				return i.Zone
			}
		}
		return ""
	}

	devices := e.inventory.Scan(ctx, dhcpLeasePath, zoneOf)
	totals := e.trafficStore.Totals(resolution)
	rates := e.trafficColl.Rates()
	blocked, _ := traffic.CountBlockedPerDevice(ctx, "1h")
	alerts := e.idsAlertsPerDevice()

	now := time.Now().Unix()
	out := DashboardData{
		Zones:      map[string]traffic.Point{},
		Resolution: resolution,
		SampledAt:  now,
	}

	for _, d := range devices {
		t := totals[d.IP]
		r := rates[d.IP]
		st := DeviceStat{
			Device:  d,
			RxBps:   r.RxBps,
			TxBps:   r.TxBps,
			RxBytes: t.Rx,
			TxBytes: t.Tx,
			Signals: traffic.Signals{
				BlockedConnections: blocked[d.IP],
				IDSAlerts:          alerts[d.IP],
			},
			IsNew: d.FirstSeen > 0 && now-d.FirstSeen < 24*3600,
		}
		if sparklinePoints > 0 {
			st.Sparkline = e.trafficStore.History("1m", d.IP, sparklinePoints)
		}
		out.Devices = append(out.Devices, st)

		z := out.Zones[d.Zone]
		z.Rx += t.Rx
		z.Tx += t.Tx
		out.Zones[d.Zone] = z

		out.Totals.Rx += t.Rx
		out.Totals.Tx += t.Tx
		out.TotalRxBps += r.RxBps
		out.TotalTxBps += r.TxBps
	}

	// Störst nedladdning först — den ordning man vill se listan i innan man
	// själv sorterar om på någon annan kolumn.
	sort.Slice(out.Devices, func(i, j int) bool {
		if out.Devices[i].RxBytes != out.Devices[j].RxBytes {
			return out.Devices[i].RxBytes > out.Devices[j].RxBytes
		}
		return out.Devices[i].IP < out.Devices[j].IP
	})
	if out.Devices == nil {
		out.Devices = []DeviceStat{}
	}
	return out
}

// idsAlertsPerDevice räknar Suricata-larm per käll-IP.
func (e *Engine) idsAlertsPerDevice() map[string]int {
	counts := map[string]int{}
	events, err := e.GetSecurityEvents(1000)
	if err != nil {
		return counts
	}
	for _, ev := range events {
		if ev.SrcIP != "" {
			counts[ev.SrcIP]++
		}
	}
	return counts
}

// DeviceHistory returnerar historiken för EN enhet.
func (e *Engine) DeviceHistory(resolution, ip string, points int) []traffic.Point {
	return e.trafficStore.History(resolution, ip, points)
}
