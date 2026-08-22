package nftables

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// logSlug gör ett policy-namn säkert att stoppa in i ett nftables
// `log prefix`-fält. Kärnans log-prefix parsas av
// pkg/api/server.go:parseFirewallLog via ett "SH-ACTION-CHAIN-NAMN: "-
// mönster — ett ":" i namnet skulle göra den gränsen tvetydig, så det är
// det enda tecknet som behöver bytas ut. Mellanslag är OK och behålls för
// läsbarhetens skull (namnet visas som det är i GUI:t).
func logSlug(name string) string {
	return strings.ReplaceAll(name, ":", "-")
}

// portMatchExpr bygger ett dport-matchningsuttryck för ETT portnummer
// eller ett portintervall ("8000-8100"). Returnerar ok=false för allt
// annat, så anroparen kan skilja "kunde inte tolkas" från "ANY".
func portMatchExpr(proto, spec string) (expr map[string]interface{}, ok bool) {
	left := map[string]interface{}{"payload": map[string]interface{}{"protocol": proto, "field": "dport"}}

	if lo, hi, isRange := strings.Cut(spec, "-"); isRange {
		loNum, errLo := strconv.Atoi(strings.TrimSpace(lo))
		hiNum, errHi := strconv.Atoi(strings.TrimSpace(hi))
		if errLo != nil || errHi != nil || !validPort(loNum) || !validPort(hiNum) || loNum > hiNum {
			return nil, false
		}
		return map[string]interface{}{
			"match": map[string]interface{}{
				"op":    "==",
				"left":  left,
				"right": map[string]interface{}{"range": []int{loNum, hiNum}},
			},
		}, true
	}

	portNum, err := strconv.Atoi(spec)
	if err != nil || !validPort(portNum) {
		return nil, false
	}
	return map[string]interface{}{
		"match": map[string]interface{}{"op": "==", "left": left, "right": portNum},
	}, true
}

// validPort: 1-65535. Den gamla koden kollade bara > 0, så t.ex. port
// 99999 slank igenom hela vägen till nft (som avvisar den vid apply — ett
// obegripligt lågnivåfel istället för ett tydligt valideringsfel).
func validPort(p int) bool { return p >= 1 && p <= 65535 }

// serviceMatchExpr bygger nftables match-uttryck för en Service-sträng, t.ex.
// "ANY", "ICMP", "22", "UDP:53", "TCP:8000-8100". Delas mellan FORWARD-kedjans
// policies och INPUT-kedjans lokala åtkomstpolicies för att undvika dubblerad
// parsning.
//
// Returnerar (nil, true) för "ANY"/tomt = medvetet ingen portbegränsning, och
// (nil, false) om strängen inte gick att tolka. Den skillnaden är viktig:
// tidigare returnerade funktionen bara nil i BÅDA fallen, vilket gjorde en
// oläslig tjänstesträng (t.ex. "80,443" eller en felstavning) till en regel
// HELT UTAN portbegränsning — en accept-regel avsedd för en enda port
// öppnade då tyst alla portar. Fail-open i en brandvägg; upptäckt vid
// kodgranskning 2026-08-20. Anroparen hoppar nu över regeln istället, och
// engine.ValidateCandidate ger användaren ett begripligt fel innan det ens
// går så långt.
func serviceMatchExpr(service string) (expr []interface{}, ok bool) {
	svcUpper := strings.ToUpper(strings.TrimSpace(service))
	if svcUpper == "ANY" || svcUpper == "" {
		return nil, true
	}
	if svcUpper == "ICMP" || svcUpper == "PING" {
		return []interface{}{
			map[string]interface{}{
				"match": map[string]interface{}{
					"op":    "==",
					"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "l4proto"}},
					"right": "icmp",
				},
			},
		}, true
	}

	for _, p := range []string{"udp", "tcp"} {
		prefix := strings.ToUpper(p)
		if !strings.HasPrefix(svcUpper, prefix) {
			continue
		}
		portStr := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(svcUpper, prefix), ":"))
		if portStr == "" || portStr == "ANY" {
			// Rent "TCP"/"UDP" utan port = hela protokollet.
			return []interface{}{
				map[string]interface{}{
					"match": map[string]interface{}{
						"op":    "==",
						"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "l4proto"}},
						"right": p,
					},
				},
			}, true
		}
		m, valid := portMatchExpr(p, portStr)
		if !valid {
			return nil, false
		}
		return []interface{}{m}, true
	}

	// Rent portnummer/-intervall utan protokollprefix tolkas som TCP.
	m, valid := portMatchExpr("tcp", svcUpper)
	if !valid {
		return nil, false
	}
	return []interface{}{m}, true
}

// scheduleMatchExpr bygger ett nftables match-uttryck som begränsar en
// policy till ett givet veckodags-/klockslagsintervall (Fas 7 — Schema/
// tidsbaserade regler). Verifierat mot skarp `nft -c -j` 2026-08-18:
// `meta day` kräver en mängd ("set") av engelska veckodagsnamn (inte en
// bitmask/array), och `meta hour` matchas med en "range" av "HH:MM"-
// strängar. Returnerar nil om schemat är ospecificerat/inaktiverat
// (policyn gäller då alltid, som tidigare).
func scheduleMatchExpr(sched *config.PolicySchedule) []interface{} {
	if sched == nil || !sched.Enabled {
		return nil
	}
	var expr []interface{}
	if len(sched.Days) > 0 {
		expr = append(expr, map[string]interface{}{
			"match": map[string]interface{}{
				"op":    "==",
				"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "day"}},
				"right": map[string]interface{}{"set": sched.Days},
			},
		})
	}
	if sched.StartTime != "" && sched.EndTime != "" {
		expr = append(expr, map[string]interface{}{
			"match": map[string]interface{}{
				"op":    "==",
				"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "hour"}},
				"right": map[string]interface{}{"range": []string{sched.StartTime, sched.EndTime}},
			},
		})
	}
	return expr
}

// resolveServiceMatchExprSets slår upp en Policy.Service-referens och
// returnerar en eller flera möjliga match-uttryckslistor (Fas 7 — Service
// Groups). Flera set uppstår bara för en Service med Protocol=="group":
// eftersom nftables inte har ett direkt sätt att uttrycka "ELLER" mellan
// obesläktade match-satser i en och samma regel, genererar anroparen
// istället EN regel per set (alla med samma action/kommentar) — samma
// mönster som redan används för IP-objekt (se objectMatchExpr).
// visited förhindrar en oändlig loop om grupper råkar peka på varandra.
// Returnerar (sets, false) om NÅGON del av tjänsten inte gick att tolka —
// anroparen ska då hoppa över policyn helt istället för att generera en
// regel utan portbegränsning (se serviceMatchExpr om varför).
func resolveServiceMatchExprSets(cfg *config.Config, serviceRef string, visited map[string]bool) (sets [][]interface{}, ok bool) {
	trimmed := strings.TrimSpace(serviceRef)
	if trimmed == "" || strings.EqualFold(trimmed, "ANY") {
		return [][]interface{}{nil}, true
	}
	if visited[trimmed] {
		return nil, true
	}
	visited[trimmed] = true

	for _, svc := range cfg.Services {
		if svc.ID != trimmed {
			continue
		}
		if svc.Protocol == "group" {
			for _, memberID := range svc.Members {
				memberSets, memberOK := resolveServiceMatchExprSets(cfg, memberID, visited)
				if !memberOK {
					return nil, false
				}
				sets = append(sets, memberSets...)
			}
			return sets, true
		}
		if len(svc.Ports) == 0 {
			expr, exprOK := serviceMatchExpr(svc.Protocol)
			if !exprOK {
				return nil, false
			}
			return [][]interface{}{expr}, true
		}
		for _, port := range svc.Ports {
			ref := port
			if svc.Protocol != "" && !strings.EqualFold(svc.Protocol, "any") {
				ref = strings.ToUpper(svc.Protocol) + ":" + port
			}
			expr, exprOK := serviceMatchExpr(ref)
			if !exprOK {
				return nil, false
			}
			sets = append(sets, expr)
		}
		return sets, true
	}

	// Inget Service-ID matchade -> tolka som en preset-sträng direkt
	// (bakåtkompatibelt med hur GUI:t sparade Policy.Service innan Fas 7).
	expr, exprOK := serviceMatchExpr(trimmed)
	if !exprOK {
		return nil, false
	}
	return [][]interface{}{expr}, true
}

// resolveObjectCIDRs slår upp ett Object-ID mot cfg.Objects och returnerar
// dess konkreta IP/CIDR-lista. "group"-objekt kan innehålla andra objekt-ID:n
// i Values (se kommentaren på config.Object) och löses upp en nivå rekursivt
// — visited förhindrar en oändlig loop om två grupper råkar peka på varandra.
// host/network/iplist/geoip har alla samma form: Values är redan konkreta
// IP/CIDR-strängar (för iplist/geoip fyllda av pkg/threatfeed, Fas 5).
func resolveObjectCIDRs(cfg *config.Config, objID string, visited map[string]bool) []string {
	if objID == "" || strings.EqualFold(objID, "ANY") || visited[objID] {
		return nil
	}
	visited[objID] = true

	for _, obj := range cfg.Objects {
		if obj.ID != objID {
			continue
		}
		if obj.Type != config.ObjectTypeGroup {
			return obj.Values
		}
		var out []string
		for _, memberID := range obj.Values {
			out = append(out, resolveObjectCIDRs(cfg, memberID, visited)...)
		}
		return out
	}
	return nil
}

// objectMatchExpr bygger ett nftables match-uttryck som begränsar en policy
// till trafik vars käll- eller mål-IP finns i det angivna Object:ets
// IP/CIDR-lista (via en anonym mängd, `ip saddr/daddr { ... }`). Returnerar
// (nil, true) om objektet är "ANY" (ingen begränsning ska läggas till), och
// (nil, false) om objektet är satt men löste upp till en TOM lista — det
// senare måste anroparen hantera genom att INTE lägga till en tandlös regel
// (annars matchar "match ingenting" == matcha allt i nftables semantik för
// en tom uttryckslista, vilket är motsatsen till vad en tom hot-lista ska
// betyda).
func objectMatchExpr(cfg *config.Config, objID, field string) (expr []interface{}, isAny bool) {
	if objID == "" || strings.EqualFold(objID, "ANY") {
		return nil, true
	}
	cidrs := resolveObjectCIDRs(cfg, objID, map[string]bool{})
	elements := cidrsToSetElements(cidrs)
	if len(elements) == 0 {
		return nil, false
	}
	return []interface{}{
		map[string]interface{}{
			"match": map[string]interface{}{
				"op":    "==",
				"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": "ip", "field": field}},
				"right": map[string]interface{}{"set": elements},
			},
		},
	}, false
}

// cidrsToSetElements omvandlar en lista av IP/CIDR-strängar till nftables
// JSON-mängdelement. En bar CIDR-sträng som "1.2.3.0/24" är INTE giltig
// direkt i "set"-listan — nft -j försöker då tolka den som ett hostnamn att
// DNS-slå upp (`Could not resolve hostname`), upptäckt vid skarp testning
// mot 10.0.0.163 med en riktig Spamhaus DROP-lista (1693 poster) 2026-08-18.
// CIDR-poster måste uttryckas som {"prefix":{"addr":..,"len":..}} — enstaka
// IP-adresser utan "/" fungerar dock fint som råa strängar.
func cidrsToSetElements(cidrs []string) []interface{} {
	var elements []interface{}
	for _, c := range cidrs {
		if !strings.Contains(c, "/") {
			elements = append(elements, c)
			continue
		}
		addr, lenStr, ok := strings.Cut(c, "/")
		length, err := strconv.Atoi(lenStr)
		if !ok || err != nil {
			continue
		}
		elements = append(elements, map[string]interface{}{
			"prefix": map[string]interface{}{"addr": addr, "len": length},
		})
	}
	return elements
}

// zoneMatchExpr bygger ett nftables match-uttryck som begränsar en policy
// till trafik som passerar in/ut via ett gränssnitt i den angivna zonen
// (via `meta iifname`/`oifname` mot en mängd device-namn). Samma
// (nil,true)/(nil,false)-kontrakt som objectMatchExpr ovan: (nil,true) =
// zoneSpec är "ANY"/tomt, ingen begränsning; (nil,false) = zoneSpec var
// satt men matchade INGET aktiverat gränssnitt (t.ex. en felstavad zon) —
// anroparen MÅSTE då hoppa över regeln helt, annars blir en tom
// uttryckslista "matcha allt" i nftables semantik (samma fälla som
// objectMatchExpr redan skyddar mot för tomma objekt-listor).
//
// zoneSpec kan vara kommaseparerad ("LAN, SERVERS") eftersom GUI:t skriver
// flervalda zoner så — se policies_screen.dart:s resolveObjOrZones. Två
// syntetiska GUI-strängar hanteras särskilt eftersom de inte matchar något
// riktigt Zone.Name: "Any-External (WAN)" → wanDevices, "Any-Trusted
// (LAN)" → samma icke-WAN-katalog som lanDevices redan beräknas som.
//
// Upptäckt 2026-08-19: SourceZone/DestZone sattes av GUI:t men lästes
// ALDRIG av FORWARD-kedjans regelgenerering — en zon-begränsad policy utan
// ett valt objekt blev i praktiken en ANY-till-ANY-regel i den skarpa
// rulesetet, en riktig säkerhetslucka, inte bara en kosmetisk GUI-detalj.
func zoneMatchExpr(cfg *config.Config, zoneSpec, metaKey string, wanDevices, lanDevices []string) (expr []interface{}, isAny bool) {
	trimmed := strings.TrimSpace(zoneSpec)
	if trimmed == "" || strings.EqualFold(trimmed, "ANY") {
		return nil, true
	}
	// "ANY" NÅGONSTANS i en kommaseparerad lista betyder "ingen
	// begränsning" — samma tolkning som validatePolicyZone
	// (pkg/engine/engine.go) använder, se den funktionens kommentar.
	for _, part := range strings.Split(trimmed, ",") {
		if strings.EqualFold(strings.TrimSpace(part), "ANY") {
			return nil, true
		}
	}

	seen := map[string]bool{}
	var devices []string
	addDevice := func(d string) {
		if d != "" && !seen[d] {
			seen[d] = true
			devices = append(devices, d)
		}
	}

	for _, part := range strings.Split(trimmed, ",") {
		zoneName := strings.TrimSpace(part)
		if zoneName == "" {
			continue
		}
		switch zoneName {
		case "Any-External (WAN)":
			for _, d := range wanDevices {
				addDevice(d)
			}
		case "Any-Trusted (LAN)":
			for _, d := range lanDevices {
				addDevice(d)
			}
		default:
			for _, iface := range cfg.Interfaces {
				if iface.Enabled && iface.Zone == zoneName && iface.Device != "" {
					addDevice(iface.Device)
				}
			}
		}
	}

	if len(devices) == 0 {
		return nil, false
	}
	return []interface{}{
		map[string]interface{}{
			"match": map[string]interface{}{
				"op":    "==",
				"left":  map[string]interface{}{"meta": map[string]interface{}{"key": metaKey}},
				"right": map[string]interface{}{"set": devices},
			},
		},
	}, false
}

// actionVerdictExpr översätter en PolicyAction till nftables terminala
// verdikt-uttryck, plus det log-prefix-ord ("ACCEPT"/"DENY") som
// pkg/api/server.go:parseFirewallLog förväntar sig.
//
// Upptäckt vid kodgranskning 2026-08-20: INPUT-kedjans loop för lokala
// policies (pol.Local) lade tidigare ALLTID till {"accept": nil} utan att
// ens titta på pol.Action — en lokal regel som administratören satt till
// "Denied (Drop)" i GUI:t renderades alltså som en ACCEPT-regel, alltså
// raka motsatsen till vad som visades. FORWARD-kedjan läste visserligen
// Action, men kände bara igen accept/drop: en "reject"-policy (finns i
// config.ActionReject och kan komma via API/backup-återläsning) föll
// igenom helt utan att generera NÅGON regel, dvs tyst verkningslös.
// Båda ställena går nu via den här gemensamma funktionen.
//
// ok=false betyder att verdiktet inte hör hemma i en filterkedja
// (dnat/snat/masquerade hanteras i NAT-kedjorna) — anroparen ska då hoppa
// över regeln istället för att generera en regel utan verdikt (som skulle
// bli en ren "räkna och fortsätt"-regel, inte det användaren bad om).
func actionVerdictExpr(action config.PolicyAction) (verdict map[string]interface{}, logWord string, ok bool) {
	switch action {
	case config.ActionAccept:
		return map[string]interface{}{"accept": nil}, "ACCEPT", true
	case config.ActionDrop:
		return map[string]interface{}{"drop": nil}, "DENY", true
	case config.ActionReject:
		// icmpx/admin-prohibited ger ett tydligt "nekad"-svar till
		// avsändaren istället för drop:ens tystnad — verifierat mot skarp
		// `nft -j -c` 2026-08-20.
		return map[string]interface{}{"reject": map[string]interface{}{"type": "icmpx", "expr": "admin-prohibited"}}, "DENY", true
	default:
		return nil, "", false
	}
}

type Adapter struct {
	tableName string
	family    string
}

func NewAdapter() *Adapter {
	return &Adapter{
		tableName: "security_harbor",
		family:    "inet",
	}
}

// RenderJSON omvandlar en deklarativ Config till nftables JSON-format.
func (a *Adapter) RenderJSON(cfg *config.Config) ([]byte, error) {
	root := JSONRoot{
		Nftables: []NFTElement{
			{Metainfo: &MetaInfo{Version: "1.1.6"}},
			{Flush: &Flush{Ruleset: nil}},
			{Table: &Table{Family: a.family, Name: a.tableName}},
		},
	}

	// hostMode: enkelkorts-/värddator-läge (Fas 13) — bara INPUT/OUTPUT-
	// hårdning, inga FORWARD/NAT-kedjor alls. En administratör som granskar
	// regelsetet på sin bärbara dator ska inte se en tom "forward"-tabell.
	hostMode := cfg.IsHostMode()

	// 1. Chains
	chains := []Chain{
		{Family: a.family, Table: a.tableName, Name: "input", Type: "filter", Hook: "input", Prio: 0, Policy: "drop"},
		{Family: a.family, Table: a.tableName, Name: "output", Type: "filter", Hook: "output", Prio: 0, Policy: "accept"},
	}
	if !hostMode {
		chains = append(chains,
			Chain{Family: a.family, Table: a.tableName, Name: "forward", Type: "filter", Hook: "forward", Prio: 0, Policy: "drop"},
			Chain{Family: a.family, Table: a.tableName, Name: "prerouting", Type: "nat", Hook: "prerouting", Prio: -100},
			Chain{Family: a.family, Table: a.tableName, Name: "postrouting", Type: "nat", Hook: "postrouting", Prio: 100},
		)
	}

	for _, c := range chains {
		ch := c
		root.Nftables = append(root.Nftables, NFTElement{Chain: &ch})
	}

	// Hitta WAN-interfacer och LAN-interfacer
	var wanDevices []string
	var lanDevices []string
	for _, iface := range cfg.Interfaces {
		if !iface.Enabled {
			continue
		}
		if iface.Zone == "WAN" && iface.Device != "" {
			wanDevices = append(wanDevices, iface.Device)
		} else if iface.Device != "" {
			lanDevices = append(lanDevices, iface.Device)
		}
	}

	// 2. INPUT CHAIN
	// Input 1: Loopback accept
	root.Nftables = append(root.Nftables, NFTElement{
		Rule: &Rule{
			Family:  a.family,
			Table:   a.tableName,
			Chain:   "input",
			Comment: "Allow loopback interface",
			Expr: []interface{}{
				map[string]interface{}{
					"match": map[string]interface{}{
						"op":    "==",
						"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "iifname"}},
						"right": "lo",
					},
				},
				map[string]interface{}{"accept": nil},
			},
		},
	})

	// Input 2: Established / Related accept (Stateful)
	root.Nftables = append(root.Nftables, NFTElement{
		Rule: &Rule{
			Family:  a.family,
			Table:   a.tableName,
			Chain:   "input",
			Comment: "Allow established/related connections",
			Expr: []interface{}{
				map[string]interface{}{
					"match": map[string]interface{}{
						"op":    "in",
						"left":  map[string]interface{}{"ct": map[string]interface{}{"key": "state"}},
						"right": []string{"established", "related"},
					},
				},
				map[string]interface{}{"accept": nil},
			},
		},
	})

	// Input 2.5: Tillåt inkommande WireGuard (UDP) på WAN, om aktiverat.
	// Måste ligga FÖRE Input 3 (HARD WAN DROP) annars är VPN:en meningslös.
	if cfg.WireGuard != nil && cfg.WireGuard.Enabled && cfg.WireGuard.ListenPort > 0 {
		for _, wanDev := range wanDevices {
			root.Nftables = append(root.Nftables, NFTElement{
				Rule: &Rule{
					Family:  a.family,
					Table:   a.tableName,
					Chain:   "input",
					Comment: fmt.Sprintf("Allow WireGuard (UDP %d) on WAN %s", cfg.WireGuard.ListenPort, wanDev),
					Expr: []interface{}{
						map[string]interface{}{
							"match": map[string]interface{}{
								"op":    "==",
								"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "iifname"}},
								"right": wanDev,
							},
						},
						map[string]interface{}{
							"match": map[string]interface{}{
								"op":    "==",
								"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": "udp", "field": "dport"}},
								"right": cfg.WireGuard.ListenPort,
							},
						},
						map[string]interface{}{"accept": nil},
					},
				},
			})
		}
	}

	// Input 2.6: Tillåt inkommande OpenVPN på WAN, om aktiverat (Fas 4).
	// Måste ligga FÖRE Input 3 (HARD WAN DROP) annars är VPN:en meningslös.
	if cfg.OpenVPN != nil && cfg.OpenVPN.Enabled && cfg.OpenVPN.ListenPort > 0 {
		proto := cfg.OpenVPN.Protocol
		if proto == "" {
			proto = "udp"
		}
		for _, wanDev := range wanDevices {
			root.Nftables = append(root.Nftables, NFTElement{
				Rule: &Rule{
					Family:  a.family,
					Table:   a.tableName,
					Chain:   "input",
					Comment: fmt.Sprintf("Allow OpenVPN (%s %d) on WAN %s", strings.ToUpper(proto), cfg.OpenVPN.ListenPort, wanDev),
					Expr: []interface{}{
						map[string]interface{}{
							"match": map[string]interface{}{
								"op":    "==",
								"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "iifname"}},
								"right": wanDev,
							},
						},
						map[string]interface{}{
							"match": map[string]interface{}{
								"op":    "==",
								"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": proto, "field": "dport"}},
								"right": cfg.OpenVPN.ListenPort,
							},
						},
						map[string]interface{}{"accept": nil},
					},
				},
			})
		}
	}

	// Input 3: HARD WAN DROP ALL INCOMING (Placeras FÖRE alla övriga accept-regler!)
	for _, wanDev := range wanDevices {
		root.Nftables = append(root.Nftables, NFTElement{
			Rule: &Rule{
				Family:  a.family,
				Table:   a.tableName,
				Chain:   "input",
				Comment: fmt.Sprintf("HARD WAN DROP ALL INCOMING on %s", wanDev),
				Expr: []interface{}{
					map[string]interface{}{
						"match": map[string]interface{}{
							"op":    "==",
							"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "iifname"}},
							"right": wanDev,
						},
					},
					map[string]interface{}{"drop": nil},
				},
			},
		})
	}

	// Input 4: Lokala åtkomstpolicies (t.ex. SSH) mot brandväggen själv,
	// ENDAST på LAN/VLAN-gränssnitt. Dessa är vanliga, konfigurerbara
	// Policy-objekt (pol.Local == true) och kan alltså stängas av i GUI:t —
	// se cfg.Policies i store.go för default-policyn "sys-ssh-lan".
	for _, pol := range cfg.Policies {
		if !pol.Local || !pol.Enabled {
			continue
		}
		// Verdiktet MÅSTE följa pol.Action — se actionVerdictExpr för den
		// bugg som gjorde att en lokal drop-policy renderades som accept.
		// Ett tomt Action-fält på en LOKAL policy behandlas som accept —
		// exakt det beteende INPUT-kedjan hade före den här ändringen. Att
		// istället hoppa över regeln hade riskerat att tyst ta bort en
		// befintlig SSH-åtkomstregel i en äldre konfiguration och låsa ute
		// administratören. (FORWARD-kedjan hoppade redan över tomt Action
		// och fortsätter göra det — där hade ett accept-default istället
		// ÖPPNAT trafik som tidigare var stängd.)
		localAction := pol.Action
		if localAction == "" {
			localAction = config.ActionAccept
		}
		verdict, logWord, ok := actionVerdictExpr(localAction)
		if !ok {
			continue
		}
		svcSets, svcOK := resolveServiceMatchExprSets(cfg, pol.Service, map[string]bool{})
		if !svcOK {
			continue
		}
		for _, lanDev := range lanDevices {
			for _, svcExpr := range svcSets {
				rule := &Rule{
					Family:  a.family,
					Table:   a.tableName,
					Chain:   "input",
					Comment: fmt.Sprintf("%s on LAN %s", pol.Name, lanDev),
					Expr: []interface{}{
						map[string]interface{}{
							"match": map[string]interface{}{
								"op":    "==",
								"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "iifname"}},
								"right": lanDev,
							},
						},
					},
				}
				rule.Expr = append(rule.Expr, scheduleMatchExpr(pol.Schedule)...)
				rule.Expr = append(rule.Expr, svcExpr...)
				rule.Expr = append(rule.Expr, map[string]interface{}{"counter": nil})
				rule.Expr = append(rule.Expr, map[string]interface{}{"log": map[string]interface{}{"prefix": fmt.Sprintf("SH-%s-INPUT-%s: ", logWord, logSlug(pol.Name))}})
				rule.Expr = append(rule.Expr, verdict)
				root.Nftables = append(root.Nftables, NFTElement{Rule: rule})
			}
		}
	}

	// Management API: alltid nåbar på LAN/VLAN — detta är INTE en
	// konfigurerbar policy (till skillnad från SSH ovan), eftersom det är
	// den enda vägen in i GUI:t. Att kunna stänga av den skulle riskera att
	// låsa ute administratören helt, utan en text-baserad reservväg som SSH.
	for _, lanDev := range lanDevices {
		root.Nftables = append(root.Nftables, NFTElement{
			Rule: &Rule{
				Family:  a.family,
				Table:   a.tableName,
				Chain:   "input",
				Comment: fmt.Sprintf("Allow Management API on LAN %s", lanDev),
				Expr: []interface{}{
					map[string]interface{}{
						"match": map[string]interface{}{
							"op":    "==",
							"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "iifname"}},
							"right": lanDev,
						},
					},
					map[string]interface{}{
						"match": map[string]interface{}{
							"op":    "==",
							"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": "tcp", "field": "dport"}},
							"right": cfg.Settings.APIPort,
						},
					},
					map[string]interface{}{"accept": nil},
				},
			},
		})
	}

	// Input 4b: Tillåt DNS (UDP+TCP 53) till brandväggen själv från LAN/VLAN
	// när den lokala resolvern är aktiverad (Fas 6). Precis som Management
	// API ovan är detta INTE en konfigurerbar policy — den följer bara
	// DNS.Enabled automatiskt, samma mönster som WAN-allow-reglerna för
	// WireGuard/OpenVPN (Fas 3/4) följer sina respektive Enabled-flaggor.
	if cfg.DNS != nil && cfg.DNS.Enabled {
		for _, lanDev := range lanDevices {
			for _, proto := range []string{"udp", "tcp"} {
				root.Nftables = append(root.Nftables, NFTElement{
					Rule: &Rule{
						Family:  a.family,
						Table:   a.tableName,
						Chain:   "input",
						Comment: fmt.Sprintf("Allow DNS (%s 53) on LAN %s", strings.ToUpper(proto), lanDev),
						Expr: []interface{}{
							map[string]interface{}{
								"match": map[string]interface{}{
									"op":    "==",
									"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "iifname"}},
									"right": lanDev,
								},
							},
							map[string]interface{}{
								"match": map[string]interface{}{
									"op":    "==",
									"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": proto, "field": "dport"}},
									"right": 53,
								},
							},
							map[string]interface{}{"accept": nil},
						},
					},
				})
			}
		}
	}

	// Input 5: Logga och neka allt annat inkommande (synliggör blockerad
	// trafik i GUI:t via /api/v1/diagnostics/firewall-log). Kedjans policy
	// ("drop") är fortfarande fail-safe-spärren om denna regel av någon
	// anledning saknas.
	root.Nftables = append(root.Nftables, NFTElement{
		Rule: &Rule{
			Family:  a.family,
			Table:   a.tableName,
			Chain:   "input",
			Comment: "Log & deny all other input",
			Expr: []interface{}{
				map[string]interface{}{"log": map[string]interface{}{"prefix": "SH-DENY-INPUT-DefaultDeny: "}},
				map[string]interface{}{"drop": nil},
			},
		},
	})

	// 3.–5. FORWARDING/NAT-kedjorna hoppas över helt i host-läge (Fas 13) —
	// de kräver ingen enda kedja/regel att fungera korrekt, se hostMode-
	// deklarationen ovan.
	if !hostMode {
		// 3. FORWARDING CHAIN (Stateful & Inter-VLAN Policies)
		root.Nftables = append(root.Nftables, NFTElement{
			Rule: &Rule{
				Family:  a.family,
				Table:   a.tableName,
				Chain:   "forward",
				Comment: "Allow established/related forwarding",
				Expr: []interface{}{
					map[string]interface{}{
						"match": map[string]interface{}{
							"op":    "in",
							"left":  map[string]interface{}{"ct": map[string]interface{}{"key": "state"}},
							"right": []string{"established", "related"},
						},
					},
					map[string]interface{}{"accept": nil},
				},
			},
		})

		// Användarpolicies
		for _, pol := range cfg.Policies {
			if !pol.Enabled || pol.Local {
				continue
			}

			// Om detta är en Port Forwarding (DNAT) policy sköts den i prerouting/forward
			if pol.Action == config.ActionDNAT && pol.NAT != nil {
				// Följeregeln som släpper igenom den DNAT:ade trafiken i
				// FORWARD-kedjan måste matcha EXAKT den vidarebefordrade
				// tjänsten — inte bara mål-IP:n.
				//
				// Upptäckt vid kodgranskning 2026-08-20: regeln matchade
				// tidigare BARA `ip daddr == InternalIP` och accepterade.
				// En port forward av t.ex. TCP 443 till 192.168.10.10 öppnade
				// i praktiken ALLA portar och ALLA protokoll mot den interna
				// värden, från VILKEN källa som helst (inklusive andra interna
				// zoner som annars stoppas av Default Deny Inter-VLAN) — en
				// långt bredare öppning än den enda port administratören bad
				// om. Nu matchas protokoll + INTERN målport (porten efter
				// DNAT-översättningen, eftersom prerouting redan skrivit om
				// paketet när det når forward-kedjan).
				dnatProto := "tcp"
				if pol.NAT.Protocol != "" {
					dnatProto = pol.NAT.Protocol
				}
				dnatExpr := []interface{}{
					map[string]interface{}{
						"match": map[string]interface{}{
							"op":    "==",
							"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": "ip", "field": "daddr"}},
							"right": pol.NAT.InternalIP,
						},
					},
				}
				if pol.NAT.InternalPort > 0 {
					dnatExpr = append(dnatExpr, map[string]interface{}{
						"match": map[string]interface{}{
							"op":    "==",
							"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": dnatProto, "field": "dport"}},
							"right": pol.NAT.InternalPort,
						},
					})
				}
				dnatExpr = append(dnatExpr,
					map[string]interface{}{"counter": nil},
					map[string]interface{}{"log": map[string]interface{}{"prefix": fmt.Sprintf("SH-ACCEPT-FWD-%s: ", logSlug(pol.Name))}},
					map[string]interface{}{"accept": nil},
				)
				root.Nftables = append(root.Nftables, NFTElement{
					Rule: &Rule{
						Family:  a.family,
						Table:   a.tableName,
						Chain:   "forward",
						Comment: fmt.Sprintf("Allow DNAT forwarding for %s", pol.Name),
						Expr:    dnatExpr,
					},
				})
				continue
			}

			// Käll-/mål-objekt (t.ex. GeoIP-landsblock eller en hot-lista från
			// Spamhaus/Tor, Fas 5): en satt (icke-"ANY") SourceObj/DestObj som
			// löser upp till en TOM lista (källan har inte hämtats än, eller
			// misslyckades) hoppar över hela regeln — annars skulle en trasig
			// hot-lista av misstag matcha ALL trafik (tom uttryckslista i
			// nftables = "matcha allt"), vilket är motsatsen till avsikten.
			srcExpr, srcIsAny := objectMatchExpr(cfg, pol.SourceObj, "saddr")
			if !srcIsAny && srcExpr == nil {
				continue
			}
			dstExpr, dstIsAny := objectMatchExpr(cfg, pol.DestObj, "daddr")
			if !dstIsAny && dstExpr == nil {
				continue
			}

			// Zon-begränsning (se zoneMatchExpr-dokumentationen ovan för
			// bakgrunden till varför detta behövdes) — samma tomt-mängd-
			// skydd som för objekten ovan.
			srcIfaceExpr, srcZoneIsAny := zoneMatchExpr(cfg, pol.SourceZone, "iifname", wanDevices, lanDevices)
			if !srcZoneIsAny && srcIfaceExpr == nil {
				continue
			}
			dstIfaceExpr, dstZoneIsAny := zoneMatchExpr(cfg, pol.DestZone, "oifname", wanDevices, lanDevices)
			if !dstZoneIsAny && dstIfaceExpr == nil {
				continue
			}

			// Samma gemensamma verdikt-översättning som INPUT-kedjan ovan —
			// täcker nu även config.ActionReject, som tidigare föll igenom
			// utan att generera någon regel alls.
			verdict, logWord, ok := actionVerdictExpr(pol.Action)
			if !ok {
				continue
			}
			svcSets, svcOK := resolveServiceMatchExprSets(cfg, pol.Service, map[string]bool{})
			if !svcOK {
				continue
			}

			for _, svcExpr := range svcSets {
				rule := &Rule{
					Family:  a.family,
					Table:   a.tableName,
					Chain:   "forward",
					Comment: fmt.Sprintf("%s (%s)", pol.Name, pol.Service),
				}

				rule.Expr = append(rule.Expr, scheduleMatchExpr(pol.Schedule)...)
				rule.Expr = append(rule.Expr, srcIfaceExpr...)
				rule.Expr = append(rule.Expr, dstIfaceExpr...)
				rule.Expr = append(rule.Expr, srcExpr...)
				rule.Expr = append(rule.Expr, dstExpr...)
				rule.Expr = append(rule.Expr, svcExpr...)
				rule.Expr = append(rule.Expr, map[string]interface{}{"counter": nil})
				rule.Expr = append(rule.Expr, map[string]interface{}{"log": map[string]interface{}{"prefix": fmt.Sprintf("SH-%s-FWD-%s: ", logWord, logSlug(pol.Name))}})
				rule.Expr = append(rule.Expr, verdict)
				root.Nftables = append(root.Nftables, NFTElement{Rule: rule})
			}
		}

		// Forward: logga och neka allt annat mellan zoner/VLAN som inte
		// matchade en explicit policy ovan (Default Deny Inter-VLAN, se avsnitt
		// 2.4 i genomförandeplanen), så att det syns i firewall-loggen.
		root.Nftables = append(root.Nftables, NFTElement{
			Rule: &Rule{
				Family:  a.family,
				Table:   a.tableName,
				Chain:   "forward",
				Comment: "Log & deny all other forwarding",
				Expr: []interface{}{
					map[string]interface{}{"log": map[string]interface{}{"prefix": "SH-DENY-FWD-DefaultDeny: "}},
					map[string]interface{}{"drop": nil},
				},
			},
		})

		// 4. NAT PREROUTING CHAIN (Port Forwarding / DNAT, samt 1:1 NAT — Fas 7)
		for _, pol := range cfg.Policies {
			if pol.Enabled && pol.Action == config.ActionDNAT && pol.NAT != nil {
				proto := "tcp"
				if pol.NAT.Protocol != "" {
					proto = pol.NAT.Protocol
				}
				expr := []interface{}{}
				// 1:1 NAT (statisk NAT, Fas 7): om NAT.ExternalIP är satt gäller
				// vidarebefordringen bara den specifika WAN-IP:n, inte alla
				// IP:er på WAN-interfacet.
				if pol.NAT.ExternalIP != "" {
					expr = append(expr, map[string]interface{}{
						"match": map[string]interface{}{
							"op":    "==",
							"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": "ip", "field": "daddr"}},
							"right": pol.NAT.ExternalIP,
						},
					})
				}
				expr = append(expr,
					map[string]interface{}{
						"match": map[string]interface{}{
							"op":    "==",
							"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": proto, "field": "dport"}},
							"right": pol.NAT.ExternalPort,
						},
					},
					map[string]interface{}{
						"dnat": map[string]interface{}{
							"family": "ip",
							"addr":   pol.NAT.InternalIP,
							"port":   pol.NAT.InternalPort,
						},
					},
				)
				root.Nftables = append(root.Nftables, NFTElement{
					Rule: &Rule{
						Family:  a.family,
						Table:   a.tableName,
						Chain:   "prerouting",
						Comment: fmt.Sprintf("Port Forwarding (DNAT): %s", pol.Name),
						Expr:    expr,
					},
				})
			}
		}

		// 4b. NAT POSTROUTING: SNAT-overrides (Fas 7 — Avancerad NAT). Måste
		// ligga FÖRE den generella masquerade-loopen nedan: nftables nat-
		// kedjor applicerar bara EN nat-åtgärd per anslutning, så den första
		// matchande regeln (i regelordning) avgör — en specifik SNAT-override
		// måste alltså komma före den generella masquerade-regeln för att
		// någonsin få effekt.
		for _, pol := range cfg.Policies {
			if !pol.Enabled || pol.Action != config.ActionSNAT || pol.NAT == nil || pol.NAT.ExternalIP == "" {
				continue
			}
			srcExpr, srcIsAny := objectMatchExpr(cfg, pol.SourceObj, "saddr")
			if !srcIsAny && srcExpr == nil {
				continue
			}
			expr := append([]interface{}{}, srcExpr...)
			expr = append(expr, map[string]interface{}{"snat": map[string]interface{}{"addr": pol.NAT.ExternalIP}})
			root.Nftables = append(root.Nftables, NFTElement{
				Rule: &Rule{
					Family:  a.family,
					Table:   a.tableName,
					Chain:   "postrouting",
					Comment: fmt.Sprintf("SNAT override: %s", pol.Name),
					Expr:    expr,
				},
			})
		}

		// 4c. NAT-reflektion / hairpin (NAT loopback): en INTERN klient som
		// slår upp en extern DNS-post som pekar på brandväggens WAN-IP och
		// ansluter dit ska nå den DNAT:ade interna servern — och få svaret
		// tillbaka. DNAT:en i prerouting (4) skriver redan om målet, men om
		// klient och server ligger i SAMMA subnät svarar servern direkt till
		// klienten (förbi brandväggen) med sin interna IP i stället för
		// WAN-IP:n klienten anslöt mot → anslutningen bryts. Lösningen är att
		// maskera den hairpinnade trafiken så servern svarar tillbaka via
		// brandväggen (som då kan skriva tillbaka WAN-IP:n).
		//
		// Regeln matchar trafik som INTE kom in på WAN (iifname != wanDevices
		// = internt ursprung) och är på väg till den interna serverns
		// IP:internport — alltså exakt de hairpinnade paketen, inte äkta
		// inkommande WAN-trafik (den lämnas omaskerad så servern ser
		// klientens riktiga käll-IP). Kräver minst ett WAN-device för att
		// "icke-WAN" ska vara meningsfullt.
		if len(wanDevices) > 0 {
			for _, pol := range cfg.Policies {
				if !pol.Enabled || pol.Action != config.ActionDNAT || pol.NAT == nil || pol.NAT.InternalIP == "" {
					continue
				}
				proto := "tcp"
				if pol.NAT.Protocol != "" {
					proto = pol.NAT.Protocol
				}
				expr := []interface{}{
					map[string]interface{}{
						"match": map[string]interface{}{
							"op":    "!=",
							"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "iifname"}},
							"right": map[string]interface{}{"set": wanDevices},
						},
					},
					map[string]interface{}{
						"match": map[string]interface{}{
							"op":    "==",
							"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": "ip", "field": "daddr"}},
							"right": pol.NAT.InternalIP,
						},
					},
				}
				if pol.NAT.InternalPort > 0 {
					expr = append(expr, map[string]interface{}{
						"match": map[string]interface{}{
							"op":    "==",
							"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": proto, "field": "dport"}},
							"right": pol.NAT.InternalPort,
						},
					})
				}
				expr = append(expr, map[string]interface{}{"masquerade": nil})
				root.Nftables = append(root.Nftables, NFTElement{
					Rule: &Rule{
						Family:  a.family,
						Table:   a.tableName,
						Chain:   "postrouting",
						Comment: fmt.Sprintf("NAT-reflektion (hairpin) för %s", pol.Name),
						Expr:    expr,
					},
				})
			}
		}

		// 5. NAT POSTROUTING CHAIN (Outbound Masquerade för alla interna nät mot WAN)
		for _, wanDev := range wanDevices {
			root.Nftables = append(root.Nftables, NFTElement{
				Rule: &Rule{
					Family:  a.family,
					Table:   a.tableName,
					Chain:   "postrouting",
					Comment: fmt.Sprintf("Outbound NAT Masquerade on %s", wanDev),
					Expr: []interface{}{
						map[string]interface{}{
							"match": map[string]interface{}{
								"op":    "==",
								"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "oifname"}},
								"right": wanDev,
							},
						},
						map[string]interface{}{"masquerade": nil},
					},
				},
			})
		}
	} // !hostMode

	return json.MarshalIndent(root, "", "  ")
}

// ApplyConfig applicerar eller dry-run validerar en konfiguration.
// Om dryRun == true körs nft -j -c -f - (check mode utan att ändra kärnan).
func (a *Adapter) ApplyConfig(ctx context.Context, cfg *config.Config, dryRun bool) ([]byte, error) {
	rulesetJSON, err := a.RenderJSON(cfg)
	if err != nil {
		return nil, fmt.Errorf("kunde inte rendera nftables JSON: %w", err)
	}

	args := []string{"-j"}
	if dryRun {
		args = append(args, "-c") // Check / dry-run mode
	}
	args = append(args, "-f", "-")

	cmd := exec.CommandContext(ctx, "nft", args...)
	cmd.Stdin = bytes.NewReader(rulesetJSON)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("nft misslyckades (dryRun=%v): %w - output: %s", dryRun, err, string(out))
	}

	return rulesetJSON, nil
}

// PolicyServiceIsParseable exponerar tjänste-/portparsningen för
// pkg/engine:s ValidateCandidate, så validering och rendering garanterat
// använder EXAKT samma tolkning (annars kan validering säga OK om något
// renderingen sedan hoppar över, eller tvärtom).
func PolicyServiceIsParseable(cfg *config.Config, serviceRef string) bool {
	_, ok := resolveServiceMatchExprSets(cfg, serviceRef, map[string]bool{})
	return ok
}
