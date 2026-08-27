package nftables

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
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

// parsePortOrRange tolkar ETT portnummer eller ETT portintervall
// ("8000-8100") till dess nftables-representation (ett rått int för en
// enskild port, {"range": [lo, hi]} för ett intervall). Delas mellan
// portMatchExpr (en enda port/intervall, eller flera av SAMMA protokoll i
// en mängd) och parseMultiProtocolServiceSets (flera portar/intervall som
// kan spänna över BÅDE TCP och UDP i samma policy).
func parsePortOrRange(part string) (interface{}, bool) {
	part = strings.TrimSpace(part)
	if lo, hi, isRange := strings.Cut(part, "-"); isRange {
		loNum, errLo := strconv.Atoi(strings.TrimSpace(lo))
		hiNum, errHi := strconv.Atoi(strings.TrimSpace(hi))
		if errLo != nil || errHi != nil || !validPort(loNum) || !validPort(hiNum) || loNum > hiNum {
			return nil, false
		}
		return map[string]interface{}{"range": []int{loNum, hiNum}}, true
	}
	portNum, err := strconv.Atoi(part)
	if err != nil || !validPort(portNum) {
		return nil, false
	}
	return portNum, true
}

// portMatchExpr bygger ett dport-matchningsuttryck för ETT portnummer, ett
// portintervall ("8000-8100"), eller en kommaseparerad lista av valfri
// blandning av båda ("80,443,8000-8100") — då byggs en nftables anonym
// mängd (`{"set": [...]}`), som stöder blandade enskilda portar och
// intervall i samma mängd, men bara för ETT protokoll (proto-parametern
// gäller alla). Se parseMultiProtocolServiceSets för TCP+UDP blandat i
// samma policy. Returnerar ok=false för allt annat, så anroparen kan
// skilja "kunde inte tolkas" från "ANY".
func portMatchExpr(proto, spec string) (expr map[string]interface{}, ok bool) {
	left := map[string]interface{}{"payload": map[string]interface{}{"protocol": proto, "field": "dport"}}

	if strings.Contains(spec, ",") {
		parts := strings.Split(spec, ",")
		elements := make([]interface{}, 0, len(parts))
		for _, part := range parts {
			if strings.TrimSpace(part) == "" {
				continue
			}
			el, valid := parsePortOrRange(part)
			if !valid {
				return nil, false
			}
			elements = append(elements, el)
		}
		if len(elements) == 0 {
			return nil, false
		}
		return map[string]interface{}{
			"match": map[string]interface{}{"op": "==", "left": left, "right": map[string]interface{}{"set": elements}},
		}, true
	}

	el, valid := parsePortOrRange(spec)
	if !valid {
		return nil, false
	}
	return map[string]interface{}{
		"match": map[string]interface{}{"op": "==", "left": left, "right": el},
	}, true
}

// parseMultiProtocolServiceSets tolkar en kommaseparerad tjänstesträng där
// OLIKA delar kan höra till OLIKA protokoll, t.ex.
// "tcp:53,tcp:80,udp:53,udp:5353" eller "80,443,udp:53" (en del utan eget
// protokollprefix ärver det SENAST angivna protokollet i listan, eller
// "tcp" om inget angetts alls — samma regel som "en bar siffra = tcp" i
// serviceMatchExpr). TCP och UDP kan INTE blandas i EN nftables-matchning
// (protokollet är en del av själva matchningsvillkoret,
// payload.protocol) — varje protokoll blir därför en EGEN uppsättning
// (ett eget element i den returnerade listan), som adaptern sedan
// renderar som en EGEN regel per element (OR-semantik via flera regler,
// se anropsstället i RenderJSON).
//
// Efterfrågat av en administratör 2026-08-24: "TCP:53,TCP:80,TCP:433,UDP:53"
// gav tidigare bara ett obegripligt "går inte att tolka", eftersom
// portMatchExpr antog ETT protokoll för hela listan.
func parseMultiProtocolServiceSets(spec string) (sets [][]interface{}, ok bool) {
	segments := strings.Split(spec, ",")
	var protoOrder []string
	byProto := map[string][]interface{}{}
	currentProto := ""
	for _, seg := range segments {
		seg = strings.ToUpper(strings.TrimSpace(seg))
		if seg == "" {
			continue
		}
		proto := currentProto
		rest := seg
		for _, p := range []string{"TCP", "UDP"} {
			if after, found := strings.CutPrefix(seg, p+":"); found {
				proto = strings.ToLower(p)
				rest = after
				break
			}
		}
		if proto == "" {
			proto = "tcp"
		}
		currentProto = proto

		el, valid := parsePortOrRange(rest)
		if !valid {
			return nil, false
		}
		if _, seen := byProto[proto]; !seen {
			protoOrder = append(protoOrder, proto)
		}
		byProto[proto] = append(byProto[proto], el)
	}
	if len(protoOrder) == 0 {
		return nil, false
	}

	for _, proto := range protoOrder {
		elements := byProto[proto]
		left := map[string]interface{}{"payload": map[string]interface{}{"protocol": proto, "field": "dport"}}
		var right interface{}
		if len(elements) == 1 {
			right = elements[0]
		} else {
			right = map[string]interface{}{"set": elements}
		}
		sets = append(sets, []interface{}{
			map[string]interface{}{"match": map[string]interface{}{"op": "==", "left": left, "right": right}},
		})
	}
	return sets, true
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
// scheduleMatchExpr returnerar (uttryck, ok). ok=false betyder att schemat
// är AKTIVERAT men saknar allt som skulle kunna begränsa regeln i tid —
// anroparen måste då hoppa över regeln helt.
//
// Kodgranskning 2026-08-25: funktionen returnerade tidigare bara ett
// (möjligen tomt) uttryck. Ett aktiverat schema utan dagar OCH utan
// kompletta tider gav då nil, vilket renderade regeln HELT UTAN
// tidsbegränsning — den gällde dygnet runt. För en Allow-policy är det en
// tyst utvidgning av precis den begränsning administratören trodde sig ha
// satt (och läget går att nå från GUI:t genom att avmarkera alla dagar).
// Nu failar det stängt, och validatePolicySchedule i pkg/engine avvisar
// dessutom kombinationen redan vid Apply med ett begripligt felmeddelande.
func scheduleMatchExpr(sched *config.PolicySchedule) (expr []interface{}, ok bool) {
	if sched == nil || !sched.Enabled {
		return nil, true
	}
	if len(sched.Days) == 0 && (sched.StartTime == "" || sched.EndTime == "") {
		return nil, false
	}
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
	return expr, true
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
	//
	// En kommaseparerad lista kan blanda TCP- och UDP-delar
	// ("TCP:53,TCP:80,UDP:53") - det kräver parseMultiProtocolServiceSets
	// (flera regler, en per protokoll) i stället för serviceMatchExpr
	// (som bara kan producera EN regel och därför bara stödjer en lista
	// av SAMMA protokoll).
	if strings.Contains(trimmed, ",") {
		multiSets, multiOK := parseMultiProtocolServiceSets(trimmed)
		if !multiOK {
			return nil, false
		}
		return multiSets, true
	}
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
// Stora listor (>= namedSetThreshold element) läggs i en NAMNGIVEN mängd via
// reg och refereras med "@namn"; små listor inlineas som anonym mängd som
// förut. reg får vara nil, vilket tvingar fram det gamla beteendet.
func objectMatchExpr(cfg *config.Config, objID, field string, reg *setRegistry) (expr []interface{}, isAny bool) {
	if objID == "" || strings.EqualFold(objID, "ANY") {
		return nil, true
	}
	cidrs := resolveObjectCIDRs(cfg, objID, map[string]bool{})
	elements := cidrsToSetElements(cidrs)
	if len(elements) == 0 {
		return nil, false
	}

	var right interface{} = map[string]interface{}{"set": elements}
	if reg != nil && len(elements) >= namedSetThreshold {
		right = "@" + reg.register(objID, elements)
	}

	return []interface{}{
		map[string]interface{}{
			"match": map[string]interface{}{
				"op":    "==",
				"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": "ip", "field": field}},
				"right": right,
			},
		},
	}, false
}

// ---------------------------------------------------------------------------
// Namngivna mängder för stora IP-listor
// ---------------------------------------------------------------------------

// namedSetThreshold är gränsen där en IP-lista slutar inlineas som anonym
// mängd och i stället deklareras som en namngiven mängd.
//
// Under gränsen är anonyma mängder att föredra: de syns direkt i regeln när
// en administratör läser `nft list ruleset`, och de flesta objekt (enskilda
// värdar, ett par nät) är små. Över gränsen dominerar kostnaden i stället:
// en anonym mängd byggs om per regel som refererar objektet, och hot-flöden
// har storleksordningen 10^5 poster.
const namedSetThreshold = 64

// setRegistry samlar de namngivna mängder som en enskild render behöver.
// Nyckeln är objekt-ID:t, så att samma lista refererad från flera policies —
// och från både saddr och daddr — delar EN deklaration.
type setRegistry struct {
	family string
	table  string
	order  []string                 // registreringsordning, för determinism
	byObj  map[string]string        // objekt-ID -> mängdnamn
	elems  map[string][]interface{} // mängdnamn -> element
	taken  map[string]bool          // mängdnamn -> upptaget
}

func newSetRegistry(family, table string) *setRegistry {
	return &setRegistry{
		family: family,
		table:  table,
		byObj:  map[string]string{},
		elems:  map[string][]interface{}{},
		taken:  map[string]bool{},
	}
}

// register returnerar mängdnamnet för ett objekt och deklarerar mängden
// första gången objektet ses.
func (r *setRegistry) register(objID string, elements []interface{}) string {
	if name, ok := r.byObj[objID]; ok {
		return name
	}
	name := r.uniqueName(objID)
	r.byObj[objID] = name
	r.elems[name] = elements
	r.taken[name] = true
	r.order = append(r.order, objID)
	return name
}

// uniqueName härleder en giltig nft-identifierare ur ett objekt-ID. Objekt-ID
// är fritt satta av användaren och kan innehålla tecken nft inte accepterar,
// så de saniteras och kortas — hashsuffixet gör att två ID som saniteras till
// samma sträng ändå får skilda mängdnamn.
func (r *setRegistry) uniqueName(objID string) string {
	var b strings.Builder
	for _, ch := range objID {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		default:
			b.WriteByte('_')
		}
	}
	stem := b.String()
	if len(stem) > 20 {
		stem = stem[:20]
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(objID))
	name := fmt.Sprintf("sh_%s_%07x", stem, h.Sum32()&0xfffffff)

	// Kollisionsvakt. Ska i praktiken aldrig slå till (hashen är på hela
	// objekt-ID:t) men en tyst namnkrock hade tystlåtet gett två objekt samma
	// hot-lista, vilket är exakt fel sorts bugg i en brandvägg.
	for i := 1; r.taken[name]; i++ {
		name = fmt.Sprintf("sh_%s_%07x_%d", stem, h.Sum32()&0xfffffff, i)
	}
	return name
}

// sets returnerar deklarationerna i registreringsordning.
func (r *setRegistry) sets() []Set {
	out := make([]Set, 0, len(r.order))
	for _, objID := range r.order {
		name := r.byObj[objID]
		out = append(out, Set{
			Family: r.family,
			Table:  r.table,
			Name:   name,
			// Enbart IPv4: matchuttrycken nedan är hårdkodade på
			// {"payload":{"protocol":"ip"}}, så en v6-mängd hade aldrig
			// kunnat refereras. Ändras det ska den här raden följa med.
			Type: "ipv4_addr",
			// "interval" krävs så snart något element är ett prefix
			// (CIDR) eller ett intervall — vilket hot-flöden alltid har.
			Flags: []string{"interval"},
			// Utan auto-merge avvisar nft HELA transaktionen så snart två
			// element överlappar, vilket hot-flöden alltid har.
			AutoMerge: true,
			Elem:      r.elems[name],
		})
	}
	return out
}

// cidrsToSetElements omvandlar en lista av IP/CIDR-strängar till nftables
// JSON-mängdelement. En bar CIDR-sträng som "1.2.3.0/24" är INTE giltig
// direkt i "set"-listan — nft -j försöker då tolka den som ett hostnamn att
// DNS-slå upp (`Could not resolve hostname`), upptäckt vid skarp testning
// mot 10.0.0.163 med en riktig Spamhaus DROP-lista (1693 poster) 2026-08-18.
// CIDR-poster måste uttryckas som {"prefix":{"addr":..,"len":..}} — enstaka
// IP-adresser utan "/" fungerar dock fint som råa strängar.
func cidrsToSetElements(cidrs []string) []interface{} {
	// Deduplicera. Samma IP förekommer nästan garanterat i flera hot-listor —
	// Tor-noder är t.ex. flitigt rapporterade till AbuseIPDB — och läggs två
	// listor i en grupp konkateneras deras värden rakt av.
	//
	// nftables klarar dubbletter av egen kraft (verifierat 2026-08-26, både
	// text- och JSON-syntaxen accepterar dem tyst), så det här är inte en
	// korrekthetsfix utan en storleksfix: en AbuseIPDB-lista har över 126 000
	// poster, och att skicka samma adress flera gånger gör bara regelsetet
	// större och appliceringen långsammare.
	//
	// Ordningen bevaras så att utskriften förblir deterministisk — annars ser
	// varje applicering ut som en ändring.
	seen := make(map[string]bool, len(cidrs))
	var elements []interface{}
	for _, c := range cidrs {
		if seen[c] {
			continue
		}
		seen[c] = true
		if !strings.Contains(c, "/") {
			elements = append(elements, c)
			continue
		}
		addr, lenStr, ok := strings.Cut(c, "/")
		length, err := strconv.Atoi(lenStr)
		if !ok || err != nil {
			continue
		}
		// En /32 (eller /128) ÄR en enskild adress. Skickas den som ett
		// prefix tvingas kärnan använda ett intervallträd i stället för en
		// hashtabell, och det kostar på riktigt: mätt på en AbuseIPDB-lista
		// med 126 616 poster (2026-08-26) tog prefixvarianten 31 MB kärnminne
		// och 407 ms att ladda, mot 7 MB och 333 ms som rena adresser.
		//
		// Hot-listor består nästan uteslutande av enskilda värdar, och
		// parsern normaliserar dem till /32 — utan det här hade varje sådan
		// lista blivit fyra gånger dyrare än nödvändigt.
		if (length == 32 && !strings.Contains(addr, ":")) ||
			(length == 128 && strings.Contains(addr, ":")) {
			elements = append(elements, addr)
			continue
		}
		elements = append(elements, map[string]interface{}{
			"prefix": map[string]interface{}{"addr": addr, "len": length},
		})
	}
	return elements
}

// implicitTail bygger svansen på en IMPLICIT regel: räknare, loggrad och
// verdikt.
//
// Implicita regler (loopback, established, VPN-portar på WAN, DNS, NTP,
// HARD WAN DROP) genereras direkt av adaptern och finns inte som Policy-
// objekt. De saknade tidigare både räknare och logg, vilket gjorde dem
// osynliga: man kunde inte svara på "vad är öppet mot brandväggen själv?"
// eller "frågar mina IoT-enheter faktiskt efter tid?" utan att logga in med
// SSH och läsa nft-utskriften.
//
// Loggprefixet följer samma konvention som policyreglerna
// (SH-ACCEPT/DENY-INPUT-namn:), så parseFirewallLog i pkg/api plockar upp
// dem utan ändring och de dyker upp i trafikloggen som allt annat.
func implicitTail(accept bool, name string) []interface{} {
	word := "DENY"
	verdict := map[string]interface{}{"drop": nil}
	if accept {
		word = "ACCEPT"
		verdict = map[string]interface{}{"accept": nil}
	}
	return []interface{}{
		map[string]interface{}{"counter": nil},
		map[string]interface{}{"log": map[string]interface{}{
			"prefix": fmt.Sprintf("SH-%s-INPUT-%s: ", word, logSlug(name)),
		}},
		verdict,
	}
}

// implicitCounterOnly är svansen för regler som ska RÄKNAS men aldrig loggas.
//
// Gäller loopback och established/related. De matchar varje paket i varje
// pågående anslutning — en loggrad per paket vore gigabyte per timme, hög
// CPU-last och en logg där de intressanta raderna dränks. Räknaren ger ändå
// svaret på "träffar den här regeln?", vilket är det man vill veta.
func implicitCounterOnly() []interface{} {
	return []interface{}{
		map[string]interface{}{"counter": nil},
		map[string]interface{}{"accept": nil},
	}
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
// primaryWANAddress plockar ut den konfigurerade IPv4-adressen (utan
// CIDR-prefix) för det första aktiverade WAN-gränssnittet. Används bara för
// NAT-reflektion (hairpin), där vi behöver veta brandväggens EXTERNA adress
// för att kunna matcha internt initierad trafik mot den — se
// prerouting-blocket i RenderJSON.
//
// Returnerar tom sträng om adressen inte går att fastställa (t.ex. ett
// DHCP-WAN vars adress ännu inte skrivits tillbaka till konfigurationen).
// Anroparen ska då hoppa över hairpin-regeln helt hellre än att generera en
// regel utan adressvillkor.
func primaryWANAddress(cfg *config.Config) string {
	for _, iface := range cfg.Interfaces {
		if !iface.Enabled || iface.Zone != "WAN" || iface.IPv4 == "" {
			continue
		}
		addr := iface.IPv4
		if host, _, found := strings.Cut(addr, "/"); found {
			addr = host
		}
		if net.ParseIP(strings.TrimSpace(addr)) != nil {
			return strings.TrimSpace(addr)
		}
	}
	return ""
}

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

	// Namngivna mängder för stora IP-listor. Fylls på medan reglerna byggs
	// och splitsas in efter tabelldeklarationen precis före marshalling —
	// nft kräver att en mängd deklareras före regeln som refererar den.
	reg := newSetRegistry(a.family, a.tableName)

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
	// Kort där brandväggen själv är DHCP-server. Skilt från lanDevices: en
	// klient ska inte kunna nå DHCP-porten på ett nät där ingen server finns.
	var dhcpDevices []string
	for _, iface := range cfg.Interfaces {
		if !iface.Enabled {
			continue
		}
		if iface.Zone == "WAN" && iface.Device != "" {
			wanDevices = append(wanDevices, iface.Device)
		} else if iface.Device != "" {
			lanDevices = append(lanDevices, iface.Device)
			if iface.DHCP != nil && iface.DHCP.Enabled {
				dhcpDevices = append(dhcpDevices, iface.Device)
			}
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
			Expr: append([]interface{}{
				map[string]interface{}{
					"match": map[string]interface{}{
						"op":    "==",
						"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "iifname"}},
						"right": "lo",
					},
				},
			}, implicitCounterOnly()...),
		},
	})

	// Input 2: Established / Related accept (Stateful)
	root.Nftables = append(root.Nftables, NFTElement{
		Rule: &Rule{
			Family:  a.family,
			Table:   a.tableName,
			Chain:   "input",
			Comment: "Allow established/related connections",
			Expr: append([]interface{}{
				map[string]interface{}{
					"match": map[string]interface{}{
						"op":    "in",
						"left":  map[string]interface{}{"ct": map[string]interface{}{"key": "state"}},
						"right": []string{"established", "related"},
					},
				},
			}, implicitCounterOnly()...),
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
					// implicitTail nedan: räknare + logg, så VPN-anslutningar
					// syns i trafikloggen som all annan trafik.
					Expr: append([]interface{}{
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
					}, implicitTail(true, "WireGuard VPN")...),
				},
			})
		}
	}

	// Input 2.6: Tillåt inkommande OpenVPN på WAN, om aktiverat (Fas 4).
	// Måste ligga FÖRE Input 3 (HARD WAN DROP) annars är VPN:en meningslös.
	//
	// Undantag: om OpenVPN frontas av en SNI-rutt (port-delning) lyssnar
	// OpenVPN bara på loopback och HAProxy äger den publika porten — då ska
	// ingen WAN-öppning för OpenVPN:s egen port skapas (SNI-ruttens
	// ListenPort öppnas i stället, se Input 2.7 nedan).
	ovpnFronted, _ := cfg.OpenVPNFrontedBySNI()
	if cfg.OpenVPN != nil && cfg.OpenVPN.Enabled && cfg.OpenVPN.ListenPort > 0 && !ovpnFronted {
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
					Expr: append([]interface{}{
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
					}, implicitTail(true, "OpenVPN")...),
				},
			})
		}
	}

	// Input 2.7: Tillåt inkommande SNI-rutt-portar på WAN (HAProxy lyssnar på
	// brandväggen själv — INTE DNAT). Måste ligga FÖRE Input 3 (HARD WAN
	// DROP). TLS-passthrough är alltid TCP.
	for _, r := range cfg.SNIRoutes {
		if !r.Enabled || !validPort(r.ListenPort) {
			continue
		}
		for _, wanDev := range wanDevices {
			root.Nftables = append(root.Nftables, NFTElement{
				Rule: &Rule{
					Family:  a.family,
					Table:   a.tableName,
					Chain:   "input",
					Comment: fmt.Sprintf("Allow SNI route %q (TCP %d) on WAN %s", r.Name, r.ListenPort, wanDev),
					Expr: append([]interface{}{
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
								"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": "tcp", "field": "dport"}},
								"right": r.ListenPort,
							},
						},
					}, implicitTail(true, "SNI-routning")...),
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
				Expr: append([]interface{}{
					map[string]interface{}{
						"match": map[string]interface{}{
							"op":    "==",
							"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "iifname"}},
							"right": wanDev,
						},
					},
				}, implicitTail(false, "WAN Drop")...),
			},
		})
	}

	// Input 4: Lokala åtkomstpolicies (t.ex. SSH, Management API) mot
	// brandväggen själv, ENDAST på LAN/VLAN-gränssnitt. Dessa är
	// konfigurerbara Policy-objekt (pol.Local == true) — se cfg.Policies i
	// store.go för default-policyerna "sys-ssh-lan" och
	// config.MgmtAPIPolicyID ("sys-mgmt-api-lan").
	//
	// Management API-policyn är dessutom Protected: den kan stängas av i
	// GUI:t (Enabled/Action) i en gammal/manuellt redigerad running.json som
	// slunkit förbi valideringen, men Apply blockeras alltid av
	// validatePolicies om den skulle vara inaktiverad eller saknas — se den
	// kommentaren för resonemanget. Renderingen här litar därför på
	// Enabled/Action som vanligt (ingen tyst override), men PORTEN hämtas
	// alltid från Settings.APIPort istället för Service-fältet, eftersom det
	// är den faktiska lyssningsporten och inte får komma ur synk med den.
	for _, pol := range cfg.Policies {
		if !pol.Local || !pol.Enabled {
			continue
		}
		isMgmtAPI := pol.ID == config.MgmtAPIPolicyID
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
		var svcSets [][]interface{}
		svcOK := true
		if isMgmtAPI {
			svcSets = [][]interface{}{{
				map[string]interface{}{
					"match": map[string]interface{}{
						"op":    "==",
						"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": "tcp", "field": "dport"}},
						"right": cfg.Settings.APIPort,
					},
				},
			}}
		} else {
			svcSets, svcOK = resolveServiceMatchExprSets(cfg, pol.Service, map[string]bool{})
		}
		if !svcOK {
			continue
		}
		// Ett aktiverat men tomt schema måste stoppa regeln, inte tyst göra
		// den dygnet-runt-gällande — se scheduleMatchExpr.
		schedExpr, schedOK := scheduleMatchExpr(pol.Schedule)
		if !schedOK {
			continue
		}
		// Källbegränsningen MÅSTE läsas här, precis som FORWARD-kedjan gör.
		//
		// Fram till 2026-08-26 byggdes en lokal regel av enbart iifname +
		// schema + tjänst — varken SourceZone eller SourceObj lästes. En
		// policy som i GUI:t stod som "Från: Allowed to Admin" eller
		// "Från: LAN" renderades därför som en regel HELT UTAN
		// källbegränsning, på SAMTLIGA interna kort.
		//
		// Skarpt: management-API:t (8443) och SSH var nåbara från IoT-VLAN:et
		// och från den internetexponerade DMZ:en, trots att administratören
		// hade begränsat dem till två nät. GUI:t visade en begränsning som
		// inte existerade i kärnan.
		//
		// Exakt samma buggklass rättades för FORWARD-kedjan 2026-08-19 (se
		// kommentaren på zoneMatchExpr); INPUT-kedjan glömdes bort då.
		srcObjExpr, srcObjIsAny := objectMatchExpr(cfg, pol.SourceObj, "saddr", reg)
		if !srcObjIsAny && len(srcObjExpr) == 0 {
			// Objektet är tomt eller kunde inte lösas upp. Att då släppa
			// igenom ALLT vore raka motsatsen till avsikten — hoppa över
			// regeln i stället.
			continue
		}

		// Zonen avgör VILKA kort regeln läggs på. Den uttrycks som ett
		// iifname-villkor i FORWARD, men här itererar vi redan över korten,
		// så den används för att filtrera listan i stället.
		devices := lanDevices
		if zoneDevices, zoneIsAny := localPolicyDevices(cfg, pol.SourceZone, wanDevices, lanDevices); !zoneIsAny {
			devices = zoneDevices
		}

		for _, lanDev := range devices {
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
				rule.Expr = append(rule.Expr, srcObjExpr...)
				rule.Expr = append(rule.Expr, schedExpr...)
				rule.Expr = append(rule.Expr, svcExpr...)
				rule.Expr = append(rule.Expr, map[string]interface{}{"counter": nil})
				rule.Expr = append(rule.Expr, map[string]interface{}{"log": map[string]interface{}{"prefix": fmt.Sprintf("SH-%s-INPUT-%s: ", logWord, logSlug(pol.Name))}})
				rule.Expr = append(rule.Expr, verdict)
				root.Nftables = append(root.Nftables, NFTElement{Rule: rule})
			}
		}
	}

	// Input 4d: Tillåt DHCP (UDP 67) till brandväggen själv på de kort där
	// den ÄR DHCP-server.
	//
	// Att den här regeln saknades märktes länge inte, och det är värt att
	// förstå varför: Kea binder en RAW-socket för att kunna ta emot
	// broadcast-förfrågningar från klienter som ännu inte har någon adress,
	// och raw-sockets plockar paketet innan det når INPUT-kedjan. Den
	// inledande DISCOVER/OFFER-handskakningen fungerade därför utmärkt.
	//
	// En klient som redan HAR en lease förnyar den däremot med unicast direkt
	// till servern (RFC 2131, RENEWING vid T1) — ett heltvanligt UDP-paket som
	// går genom INPUT och nekades av DefaultDeny. Klienten fick inget svar,
	// väntade till T2 och föll tillbaka på broadcast REBIND, som gick igenom.
	// Nätet fungerade alltså, men varje förnyelse tog en onödig omväg och
	// fyllde loggen med DENY-rader (rapporterat 2026-08-26).
	//
	// ENDAST kort med DHCP påslaget, aldrig WAN.
	for _, dev := range dhcpDevices {
		root.Nftables = append(root.Nftables, NFTElement{
			Rule: &Rule{
				Family:  a.family,
				Table:   a.tableName,
				Chain:   "input",
				Comment: fmt.Sprintf("Allow DHCP (UDP 67) on LAN %s", dev),
				Expr: append([]interface{}{
					map[string]interface{}{
						"match": map[string]interface{}{
							"op":    "==",
							"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "iifname"}},
							"right": dev,
						},
					},
					map[string]interface{}{
						"match": map[string]interface{}{
							"op":    "==",
							"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": "udp", "field": "dport"}},
							"right": 67,
						},
					},
				}, implicitTail(true, "DHCP till brandvaggen")...),
			},
		})
	}

	// Input 4c: Tillåt NTP (UDP 123) till brandväggen själv från LAN/VLAN när
	// NTP-servern är påslagen. Följer NTP.Enabled automatiskt, samma mönster
	// som DNS-regeln nedan.
	//
	// ENDAST interna kort. En NTP-server nåbar från WAN är ett klassiskt
	// förstärkningsverktyg för DDoS (NTP amplification) — den får aldrig
	// hamna där, och lanDevices innehåller per definition inga WAN-kort.
	if cfg.NTP != nil && cfg.NTP.Enabled {
		for _, lanDev := range lanDevices {
			root.Nftables = append(root.Nftables, NFTElement{
				Rule: &Rule{
					Family:  a.family,
					Table:   a.tableName,
					Chain:   "input",
					Comment: fmt.Sprintf("Allow NTP (UDP 123) on LAN %s", lanDev),
					Expr: append([]interface{}{
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
								"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": "udp", "field": "dport"}},
								"right": 123,
							},
						},
					}, implicitTail(true, "NTP till brandvaggen")...),
				},
			})
		}
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
						Expr: append([]interface{}{
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
						}, implicitTail(true, "DNS till brandvaggen")...),
					},
				})
			}
		}
	}

	// Input 4c: Tillåt SNI-rutt-portar även på LAN/VLAN så interna klienter
	// (och hairpin-fallet: en intern klient som slår upp ett namn som pekar
	// på brandväggen) når HAProxy på samma port. Alltid TCP.
	for _, r := range cfg.SNIRoutes {
		if !r.Enabled || !validPort(r.ListenPort) {
			continue
		}
		for _, lanDev := range lanDevices {
			root.Nftables = append(root.Nftables, NFTElement{
				Rule: &Rule{
					Family:  a.family,
					Table:   a.tableName,
					Chain:   "input",
					Comment: fmt.Sprintf("Allow SNI route %q (TCP %d) on LAN %s", r.Name, r.ListenPort, lanDev),
					Expr: append([]interface{}{
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
								"right": r.ListenPort,
							},
						},
					}, implicitTail(true, "SNI-routning")...),
				},
			})
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
				//
				// Kodgranskning 2026-08-25: KÄLLAN var fortfarande obegränsad
				// efter den fixen — regeln accepterade trafik mot
				// InternalIP:InternalPort oavsett vilket gränssnitt den kom
				// in på, så en klient i en isolerad zon (IoT/gäst) nådde
				// DNAT-målet förbi Default Deny mellan zoner. Att i stället
				// låsa regeln till WAN-gränssnittet hade brutit
				// NAT-reflektion (hairpin), där paketet kommer in på LAN.
				// `ct status dnat` matchar exakt de paket prerouting-kedjan
				// FAKTISKT översatte — alltså både äkta WAN-inkommande och
				// hairpinnad trafik, men ingenting annat som råkar vara
				// adresserat till samma IP och port.
				dnatProto := "tcp"
				if pol.NAT.Protocol != "" {
					dnatProto = pol.NAT.Protocol
				}
				dnatExpr := []interface{}{
					map[string]interface{}{
						"match": map[string]interface{}{
							"op":    "in",
							"left":  map[string]interface{}{"ct": map[string]interface{}{"key": "status"}},
							"right": "dnat",
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
			srcExpr, srcIsAny := objectMatchExpr(cfg, pol.SourceObj, "saddr", reg)
			if !srcIsAny && srcExpr == nil {
				continue
			}
			dstExpr, dstIsAny := objectMatchExpr(cfg, pol.DestObj, "daddr", reg)
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
			// Aktiverat men tomt schema = hoppa över regeln (fail closed),
			// se scheduleMatchExpr.
			schedExpr, schedOK := scheduleMatchExpr(pol.Schedule)
			if !schedOK {
				continue
			}

			for _, svcExpr := range svcSets {
				rule := &Rule{
					Family:  a.family,
					Table:   a.tableName,
					Chain:   "forward",
					Comment: fmt.Sprintf("%s (%s)", pol.Name, pol.Service),
				}

				rule.Expr = append(rule.Expr, schedExpr...)
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
		//
		// Kodgranskning 2026-08-25 (ALLVARLIG): regeln matchade tidigare BARA
		// destinationsporten (plus ev. ExternalIP) — utan någon
		// iifname-begränsning. Eftersom GUI:t aldrig sätter ExternalIP
		// (dialogen har inget sådant fält) blev varje port forward skapad via
		// gränssnittet en regel av formen "tcp dport 443 dnat to 10.0.0.5:443"
		// i prerouting, UTAN gränssnittsvillkor. Det innebar att ALL trafik
		// mot den porten — även LAN-klienters utgående HTTPS mot godtyckliga
		// externa servrar — omdirigerades till den interna värden, och att
		// isolerade zoner nådde DNAT-målet förbi Default Deny.
		//
		// Regeln delas därför i två uttryckliga fall:
		//   a) Äkta inkommande: iifname == WAN-devices.
		//   b) NAT-reflektion (hairpin): trafik från icke-WAN som är
		//      adresserad till brandväggens EXTERNA adress. Kräver att vi
		//      faktiskt vet den adressen (NAT.ExternalIP, annars WAN-kortets
		//      konfigurerade IPv4). Går den inte att avgöra genereras ingen
		//      hairpin-regel alls — hairpin slutar då fungera, vilket är rätt
		//      felmod jämfört med att kapa all trafik på porten.
		for _, pol := range cfg.Policies {
			if pol.Enabled && pol.Action == config.ActionDNAT && pol.NAT != nil {
				proto := "tcp"
				if pol.NAT.Protocol != "" {
					proto = pol.NAT.Protocol
				}
				dnatVerdict := map[string]interface{}{
					"dnat": map[string]interface{}{
						"family": "ip",
						"addr":   pol.NAT.InternalIP,
						"port":   pol.NAT.InternalPort,
					},
				}
				dportMatch := map[string]interface{}{
					"match": map[string]interface{}{
						"op":    "==",
						"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": proto, "field": "dport"}},
						"right": pol.NAT.ExternalPort,
					},
				}
				// 1:1 NAT (statisk NAT, Fas 7): om NAT.ExternalIP är satt gäller
				// vidarebefordringen bara den specifika WAN-IP:n, inte alla
				// IP:er på WAN-interfacet.
				var extDaddrMatch map[string]interface{}
				if pol.NAT.ExternalIP != "" {
					extDaddrMatch = map[string]interface{}{
						"match": map[string]interface{}{
							"op":    "==",
							"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": "ip", "field": "daddr"}},
							"right": pol.NAT.ExternalIP,
						},
					}
				}

				// a) Äkta inkommande trafik på WAN.
				if len(wanDevices) > 0 {
					expr := []interface{}{
						map[string]interface{}{
							"match": map[string]interface{}{
								"op":    "==",
								"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "iifname"}},
								"right": map[string]interface{}{"set": wanDevices},
							},
						},
					}
					if extDaddrMatch != nil {
						expr = append(expr, extDaddrMatch)
					}
					expr = append(expr, dportMatch, dnatVerdict)
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

				// b) NAT-reflektion (hairpin) — bara om den externa adressen
				// går att fastställa (se blockkommentaren ovan).
				hairpinAddr := pol.NAT.ExternalIP
				if hairpinAddr == "" {
					hairpinAddr = primaryWANAddress(cfg)
				}
				if hairpinAddr == "" || len(wanDevices) == 0 {
					continue
				}
				root.Nftables = append(root.Nftables, NFTElement{
					Rule: &Rule{
						Family:  a.family,
						Table:   a.tableName,
						Chain:   "prerouting",
						Comment: fmt.Sprintf("NAT-reflektion (hairpin) DNAT: %s", pol.Name),
						Expr: []interface{}{
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
									"right": hairpinAddr,
								},
							},
							dportMatch,
							dnatVerdict,
						},
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
			srcExpr, srcIsAny := objectMatchExpr(cfg, pol.SourceObj, "saddr", reg)
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

	root.Nftables = spliceSets(root.Nftables, reg)

	return json.MarshalIndent(root, "", "  ")
}

// spliceSets lägger in mängddeklarationerna direkt efter tabelldeklarationen.
// nft avvisar en regel som refererar en mängd som inte deklarerats tidigare i
// samma transaktion, så positionen är inte kosmetisk.
func spliceSets(elems []NFTElement, reg *setRegistry) []NFTElement {
	sets := reg.sets()
	if len(sets) == 0 {
		return elems
	}
	insertAt := 0
	for i, e := range elems {
		if e.Table != nil {
			insertAt = i + 1
			break
		}
	}
	out := make([]NFTElement, 0, len(elems)+len(sets))
	out = append(out, elems[:insertAt]...)
	for i := range sets {
		st := sets[i]
		out = append(out, NFTElement{Set: &st})
	}
	return append(out, elems[insertAt:]...)
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

// localPolicyDevices översätter en lokal policys källzon till de kort regeln
// ska läggas på.
//
// INPUT-kedjan itererar redan över korten (en regel per kort), så zonen kan
// inte uttryckas som ett extra iifname-villkor så som FORWARD gör — den
// används för att filtrera listan i stället. Resultatet blir detsamma:
// "Från: LAN" träffar bara kort vars zon faktiskt är LAN, inte varje internt
// kort på lådan.
//
// isAny=true betyder "ingen zonbegränsning" och anroparen ska då använda hela
// listan. En zon som inte matchar något kort ger en TOM lista — regeln läggs
// då inte på något kort alls, vilket är rätt: en policy för en zon som inte
// finns ska inte gälla överallt.
func localPolicyDevices(cfg *config.Config, zoneSpec string, wanDevices, lanDevices []string) (devices []string, isAny bool) {
	trimmed := strings.TrimSpace(zoneSpec)
	if trimmed == "" || strings.EqualFold(trimmed, "ANY") {
		return nil, true
	}

	allowed := map[string]bool{}
	for _, part := range strings.Split(trimmed, ",") {
		zoneName := strings.TrimSpace(part)
		if zoneName == "" {
			continue
		}
		if strings.EqualFold(zoneName, "ANY") {
			return nil, true
		}
		switch zoneName {
		case "Any-External (WAN)":
			for _, d := range wanDevices {
				allowed[d] = true
			}
		case "Any-Trusted (LAN)":
			for _, d := range lanDevices {
				allowed[d] = true
			}
		default:
			for _, iface := range cfg.Interfaces {
				if iface.Enabled && iface.Zone == zoneName && iface.Device != "" {
					allowed[iface.Device] = true
				}
			}
		}
	}

	// Behåll lanDevices ordning i stället för kartans, så regelverket blir
	// deterministiskt mellan appliceringar.
	for _, d := range lanDevices {
		if allowed[d] {
			devices = append(devices, d)
		}
	}
	return devices, false
}
