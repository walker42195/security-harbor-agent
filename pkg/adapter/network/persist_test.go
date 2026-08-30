package network

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// lanStatic är gränssnittet från den skarpa incidenten 2026-08-26: LAN-kortet
// som ska ligga fast på 10.0.0.9 men som tappade adressen till en DHCP-lease
// vid varje omstart av agenten.
// gatewayIfaces är en tvåkorts-gateway-konfiguration. Behövs som `all`-
// argument till renderarna: "internt kort" betyder numera "det finns ett
// WAN-kort som är att föredra för default-rutten", inte bara "zonen är inte
// WAN" — annars hade host-lägets enda kort felaktigt räknats som internt och
// blivit av med både default-rutt och DNS (se CarriesDefaultRoute).
func gatewayIfaces() []config.Interface {
	return []config.Interface{
		{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
		lanStatic(),
	}
}

func lanStatic() config.Interface {
	return config.Interface{
		ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true,
		AddressType: "static", IPv4: "10.0.0.9/24",
		// Gateway/DNS pekar på brandväggen själv — det är vad den delar UT
		// till klienterna, inte vad den själv ska använda.
		Gateway: "10.0.0.9", DNSServers: []string{"10.0.0.9"},
	}
}

func wanDHCP() config.Interface {
	return config.Interface{
		ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp",
	}
}

func vlan9() config.Interface {
	return config.Interface{
		ID: "vlan9", Device: "ens19.9", Parent: "ens19", VLANID: 9, Zone: "VLAN 9",
		Enabled: true, AddressType: "static", IPv4: "10.9.9.1/24", MTU: 1500,
	}
}

func TestRenderNetplanStaticLANHasNoGatewayOrDNS(t *testing.T) {
	out, err := RenderNetplan([]config.Interface{lanStatic()})
	if err != nil {
		t.Fatalf("RenderNetplan: %v", err)
	}

	if !strings.Contains(out, "dhcp4: false") {
		t.Errorf("statiskt LAN måste stänga av dhcp4, fick:\n%s", out)
	}
	if !strings.Contains(out, "addresses: [10.0.0.9/24]") {
		t.Errorf("adressen saknas, fick:\n%s", out)
	}
	// Kärnan i incidenten: ett internt kort får ALDRIG en default-rutt, och
	// dess DNSServers-fält (= vad klienterna får) ska inte bli brandväggens
	// egen resolver.
	if strings.Contains(out, "routes:") || strings.Contains(out, "to: default") {
		t.Errorf("internt kort fick en default-rutt, fick:\n%s", out)
	}
	if strings.Contains(out, "nameservers:") {
		t.Errorf("internt korts DNSServers läckte in som brandväggens resolver, fick:\n%s", out)
	}
}

func TestRenderNetplanInternalDHCPNeverTakesRoutesOrDNS(t *testing.T) {
	lan := lanStatic()
	lan.AddressType = "dhcp"
	lan.IPv4 = ""

	// WAN måste finnas med: "internt kort" betyder att det finns ett WAN som
	// är att föredra för default-rutten. Ett ENSAMT kort utan WAN är
	// host-läge och ska tvärtom behålla rutt och DNS (se testet nedan).
	wan := config.Interface{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"}
	out, err := RenderNetplan([]config.Interface{wan, lan})
	if err != nil {
		t.Fatalf("RenderNetplan: %v", err)
	}
	for _, want := range []string{"dhcp4: true", "use-routes: false", "use-dns: false"} {
		if !strings.Contains(out, want) {
			t.Errorf("saknar %q, fick:\n%s", want, out)
		}
	}
}

func TestRenderNetplanWANKeepsGatewayAndDNS(t *testing.T) {
	wan := config.Interface{
		ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true,
		AddressType: "static", IPv4: "192.0.2.10/24", Gateway: "192.0.2.1",
		DNSServers: []string{"1.1.1.1", "8.8.8.8"},
	}
	out, err := RenderNetplan([]config.Interface{wan})
	if err != nil {
		t.Fatalf("RenderNetplan: %v", err)
	}
	for _, want := range []string{"to: default", "via: 192.0.2.1", "addresses: [1.1.1.1, 8.8.8.8]"} {
		if !strings.Contains(out, want) {
			t.Errorf("WAN saknar %q, fick:\n%s", want, out)
		}
	}

	// WAN i DHCP-läge ska INTE få overrides — det är det enda kort som ska
	// ta emot default-rutt och DNS från sin DHCP-server.
	out, err = RenderNetplan([]config.Interface{wanDHCP()})
	if err != nil {
		t.Fatalf("RenderNetplan: %v", err)
	}
	if strings.Contains(out, "use-routes: false") {
		t.Errorf("WAN ska ta emot DHCP-rutter, fick:\n%s", out)
	}
}

func TestRenderNetplanVLANSection(t *testing.T) {
	out, err := RenderNetplan([]config.Interface{lanStatic(), vlan9()})
	if err != nil {
		t.Fatalf("RenderNetplan: %v", err)
	}
	for _, want := range []string{"vlans:", "ens19.9:", "id: 9", "link: ens19", "mtu: 1500"} {
		if !strings.Contains(out, want) {
			t.Errorf("saknar %q, fick:\n%s", want, out)
		}
	}
}

func TestRenderNetplanDisabledInterfaces(t *testing.T) {
	// Avstängd VLAN ska inte skapas alls...
	off := vlan9()
	off.Enabled = false
	out, err := RenderNetplan([]config.Interface{lanStatic(), off})
	if err != nil {
		t.Fatalf("RenderNetplan: %v", err)
	}
	if strings.Contains(out, "ens19.9") {
		t.Errorf("avstängd VLAN skapades ändå, fick:\n%s", out)
	}

	// ...medan ett avstängt fysiskt kort finns kvar men inte tas upp.
	lan := lanStatic()
	lan.Enabled = false
	out, err = RenderNetplan([]config.Interface{lan})
	if err != nil {
		t.Fatalf("RenderNetplan: %v", err)
	}
	if !strings.Contains(out, "activation-mode: off") {
		t.Errorf("avstängt fysiskt kort saknar activation-mode, fick:\n%s", out)
	}
}

// Byte-identisk utskrift för identisk konfiguration är vad som gör
// "har filen ändrats?"-jämförelsen i Write meningsfull. Utan stabil ordning
// hade varje applicering sett ut som en ändring och rivit igång korten.
func TestRenderNetplanIsDeterministic(t *testing.T) {
	a, err := RenderNetplan([]config.Interface{lanStatic(), wanDHCP(), vlan9()})
	if err != nil {
		t.Fatalf("RenderNetplan: %v", err)
	}
	b, err := RenderNetplan([]config.Interface{vlan9(), lanStatic(), wanDHCP()})
	if err != nil {
		t.Fatalf("RenderNetplan: %v", err)
	}
	if a != b {
		t.Errorf("ordningen på gränssnitten ändrade utskriften:\n%s\n---\n%s", a, b)
	}
}

func TestRenderNetplanRejectsInjection(t *testing.T) {
	cases := []struct {
		name  string
		iface config.Interface
	}{
		{"enhetsnamn med YAML-brytning", config.Interface{
			ID: "x", Device: "ens19:\n      dhcp4: true", Zone: "LAN", Enabled: true, AddressType: "dhcp"}},
		{"bar IP utan prefix", config.Interface{
			ID: "x", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.9"}},
		{"ogiltig gateway", config.Interface{
			ID: "x", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "static",
			IPv4: "192.0.2.10/24", Gateway: "inte-en-ip"}},
		{"ogiltig MAC", config.Interface{
			ID: "x", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp",
			MACAddress: "00:11:22"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RenderNetplan([]config.Interface{tc.iface}); err == nil {
				t.Error("förväntade ett fel, fick inget")
			}
		})
	}
}

func TestRenderNetworkdFiles(t *testing.T) {
	files, err := renderNetworkdFiles([]config.Interface{lanStatic(), wanDHCP(), vlan9()})
	if err != nil {
		t.Fatalf("renderNetworkdFiles: %v", err)
	}

	// VLAN kräver BÅDE en .netdev som skapar kortet och en VLAN=-rad på
	// föräldern — utan den senare hänger networkd aldrig på subinterfacet.
	netdev, ok := files[networkdPrefix+"ens19.9.netdev"]
	if !ok {
		t.Fatalf("VLAN saknar .netdev, fick filerna: %v", keys(files))
	}
	if !strings.Contains(netdev, "Kind=vlan") || !strings.Contains(netdev, "Id=9") {
		t.Errorf(".netdev är ofullständig:\n%s", netdev)
	}
	parent := files[networkdPrefix+"ens19.network"]
	if !strings.Contains(parent, "VLAN=ens19.9") {
		t.Errorf("föräldern saknar VLAN=-rad:\n%s", parent)
	}

	// Samma garanti som i netplan: internt kort utan default-rutt.
	if strings.Contains(parent, "Gateway=") {
		t.Errorf("internt kort fick en gateway:\n%s", parent)
	}
	if !strings.Contains(parent, "Address=10.0.0.9/24") {
		t.Errorf("adressen saknas:\n%s", parent)
	}

	wan := files[networkdPrefix+"ens18.network"]
	if strings.Contains(wan, "UseRoutes=no") {
		t.Errorf("WAN ska ta emot DHCP-rutter:\n%s", wan)
	}
}

func TestRenderNetworkdInternalDHCPDropsRoutesAndDNS(t *testing.T) {
	lan := lanStatic()
	lan.AddressType = "dhcp"
	lan.IPv4 = ""

	// Se kommentaren i netplan-motsvarigheten: WAN måste finnas med för att
	// kortet ska räknas som internt.
	wan := config.Interface{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"}
	files, err := renderNetworkdFiles([]config.Interface{wan, lan})
	if err != nil {
		t.Fatalf("renderNetworkdFiles: %v", err)
	}
	body := files[networkdPrefix+"ens19.network"]
	for _, want := range []string{"DHCP=ipv4", "UseRoutes=no", "UseGateway=no", "UseDNS=no"} {
		if !strings.Contains(body, want) {
			t.Errorf("saknar %q:\n%s", want, body)
		}
	}
}

func TestNMSettingsNeverDefaultOnInternalInterfaces(t *testing.T) {
	s, err := nmSettingsFor(lanStatic(), "ens19", false, gatewayIfaces())
	if err != nil {
		t.Fatalf("nmSettingsFor: %v", err)
	}
	// never-default är NM:s motsvarighet till att utelämna routes: den
	// gäller både statisk gateway och DHCP-inlärd default-rutt.
	if s["ipv4.never-default"] != "yes" {
		t.Errorf("internt kort saknar never-default: %v", s)
	}
	if s["ipv4.ignore-auto-dns"] != "yes" {
		t.Errorf("internt kort saknar ignore-auto-dns: %v", s)
	}
	if s["ipv4.method"] != "manual" || s["ipv4.addresses"] != "10.0.0.9/24" {
		t.Errorf("fel adressläge: %v", s)
	}
	// Gateway-fältet är satt i configen (= vad klienterna får), men får inte
	// bli brandväggens egen default-rutt.
	if s["ipv4.gateway"] != "" {
		t.Errorf("internt kort fick en gateway: %q", s["ipv4.gateway"])
	}

	wan, err := nmSettingsFor(config.Interface{
		Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "static",
		IPv4: "192.0.2.10/24", Gateway: "192.0.2.1", DNSServers: []string{"1.1.1.1"},
	}, "ens18", false, gatewayIfaces())
	if err != nil {
		t.Fatalf("nmSettingsFor: %v", err)
	}
	if wan["ipv4.never-default"] != "no" || wan["ipv4.gateway"] != "192.0.2.1" {
		t.Errorf("WAN ska ha default-rutt: %v", wan)
	}
	if wan["ipv4.dns"] != "1.1.1.1" {
		t.Errorf("WAN saknar DNS: %v", wan)
	}
}

// Byter ett kort från statiskt till DHCP måste de statiska värdena
// NOLLSTÄLLAS explicit — annars ligger den gamla adressen kvar vid sidan om
// DHCP-leasen, precis den bugg som rapporterades 2026-08-25 för den
// imperativa vägen.
func TestNMSettingsClearStaleStaticValuesOnDHCP(t *testing.T) {
	lan := lanStatic()
	lan.AddressType = "dhcp"

	s, err := nmSettingsFor(lan, "ens19", false, gatewayIfaces())
	if err != nil {
		t.Fatalf("nmSettingsFor: %v", err)
	}
	if s["ipv4.method"] != "auto" {
		t.Errorf("fel metod: %v", s)
	}
	for _, key := range []string{"ipv4.addresses", "ipv4.gateway", "ipv4.dns"} {
		if s[key] != "" {
			t.Errorf("%s nollställdes inte: %q", key, s[key])
		}
	}
}

func TestNMValueEqualTreatsEmptyMarkerAsEmpty(t *testing.T) {
	// nmcli rapporterar en tom egenskap som "--". Utan normaliseringen hade
	// varje applicering sett tomma fält som ändrade och rivit upp kortet.
	if !nmValueEqual("--", "") {
		t.Error(`"--" ska räknas som tomt`)
	}
	if !nmValueEqual(" 10.0.0.9/24 ", "10.0.0.9/24") {
		t.Error("blanksteg ska normaliseras bort")
	}
	if nmValueEqual("10.0.0.9/24", "10.0.0.10/24") {
		t.Error("olika adresser ska inte vara lika")
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Ett avstängt kort ska aldrig väntas på: det får ingen adress, så en väntan
// hade bara bränt hela timeouten vid varje applicering.
func TestWaitForAddressSkipsDisabledInterface(t *testing.T) {
	off := lanStatic()
	off.Enabled = false

	done := make(chan error, 1)
	go func() { done <- waitForAddress(context.Background(), off, "ens19") }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("förväntade inget fel, fick: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waitForAddress väntade på ett avstängt kort")
	}
}

// hostIface är host-lägets seed: ETT kort, zon HOST, ingen WAN-zon någonstans.
func hostIface() config.Interface {
	return config.Interface{
		ID: "host0", Device: "ens19", Zone: "HOST", Enabled: true, AddressType: "dhcp",
	}
}

// Regression (skarpt 2026-08-30 på 10.0.0.152): i host-läge finns ingen
// WAN-zon, och villkoret `zone == "WAN"` gjorde att maskinens ENDA kort
// behandlades som ett internt gateway-kort. Alla tre persistenslagren satte
// då "ta inte emot default-rutt eller DNS" på den enda uppkoppling maskinen
// hade: default-rutten försvann och /etc/resolv.conf blev tom. Maskinen nådde
// sitt eget subnät men ingenting annat, och namnuppslag slutade fungera.
func TestHostModeInterfaceKeepsRouteAndDNS(t *testing.T) {
	host := hostIface()
	all := []config.Interface{host}

	if !CarriesDefaultRoute(host, all) {
		t.Fatal("host-lägets kort ska få bära default-rutt")
	}

	t.Run("netplan", func(t *testing.T) {
		out, err := RenderNetplan(all)
		if err != nil {
			t.Fatalf("RenderNetplan: %v", err)
		}
		for _, forbidden := range []string{"use-routes: false", "use-dns: false", "accept-ra: false"} {
			if strings.Contains(out, forbidden) {
				t.Errorf("host-lägets kort fick %q:\n%s", forbidden, out)
			}
		}
	})

	t.Run("networkd", func(t *testing.T) {
		files, err := renderNetworkdFiles(all)
		if err != nil {
			t.Fatalf("renderNetworkdFiles: %v", err)
		}
		body := files[networkdPrefix+"ens19.network"]
		for _, forbidden := range []string{"UseRoutes=no", "UseGateway=no", "UseDNS=no"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("host-lägets kort fick %q:\n%s", forbidden, body)
			}
		}
	})

	t.Run("networkmanager", func(t *testing.T) {
		s, err := nmSettingsFor(host, "ens19", false, all)
		if err != nil {
			t.Fatalf("nmSettingsFor: %v", err)
		}
		if s["ipv4.never-default"] != "no" {
			t.Errorf("host-lägets kort fick never-default: %v", s)
		}
		if s["ipv4.ignore-auto-dns"] != "no" {
			t.Errorf("host-lägets kort fick ignore-auto-dns: %v", s)
		}
	})
}

// Motsatsen måste fortfarande gälla: så fort det FINNS ett WAN-kort är alla
// andra kort interna och får varken default-rutt eller DHCP-DNS.
func TestGatewayInternalInterfaceStillLosesRouteAndDNS(t *testing.T) {
	all := gatewayIfaces()
	for _, iface := range all {
		want := strings.EqualFold(iface.Zone, "WAN")
		if got := CarriesDefaultRoute(iface, all); got != want {
			t.Errorf("%s (zon %s): CarriesDefaultRoute=%v, ville %v",
				iface.Device, iface.Zone, got, want)
		}
	}
}
