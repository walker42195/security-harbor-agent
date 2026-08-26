package nftables

import (
	"fmt"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// ImplicitRule beskriver en regel som adaptern genererar SJÄLV, utan att den
// finns som ett Policy-objekt.
//
// De här reglerna följer en funktions på/av-flagga (DNS.Enabled, NTP.Enabled,
// WireGuard.Enabled …) och ska inte gå att redigera eller ta bort — men de
// måste gå att SE. På en brandvägg ska varje regel som släpper in trafik
// synas någonstans i gränssnittet; annars kan man inte svara på "vad är
// egentligen öppet mot brandväggen själv?" utan att logga in med SSH och läsa
// nft-utskriften (rapporterat 2026-08-26).
type ImplicitRule struct {
	Name    string `json:"name"`
	Chain   string `json:"chain"`
	Action  string `json:"action"`
	Service string `json:"service"`
	From    string `json:"from"`
	To      string `json:"to"`
	Logged  bool   `json:"logged"`
	// Reason förklarar varför regeln finns och vad som styr den, så att den
	// som läser listan förstår varför den inte går att ta bort.
	Reason string `json:"reason"`
}

// DescribeImplicitRules beskriver de implicita INPUT-reglerna för en given
// konfiguration.
//
// MÅSTE hållas i synk med RenderJSON. TestImplicitRulesMatchRendered vaktar
// det: den renderar regelsetet och kontrollerar att varje beskriven regel
// faktiskt finns, och att ingen implicit regel saknar beskrivning.
func DescribeImplicitRules(cfg *config.Config) []ImplicitRule {
	if cfg == nil {
		return nil
	}
	var out []ImplicitRule

	out = append(out,
		ImplicitRule{
			Name: "Loopback", Chain: "input", Action: "accept", Service: "ANY",
			From: "lo", To: "SELF", Logged: false,
			Reason: "Brandväggens egna processer pratar med sig själva över loopback. Loggas inte — varje paket i varje anslutning skulle ge en loggrad.",
		},
		ImplicitRule{
			Name: "Etablerade anslutningar", Chain: "input", Action: "accept", Service: "ANY",
			From: "ANY", To: "SELF", Logged: false,
			Reason: "Svarstrafik på anslutningar brandväggen själv öppnat. Loggas inte — det skulle bli en loggrad per paket.",
		},
	)

	if cfg.WireGuard != nil && cfg.WireGuard.Enabled && cfg.WireGuard.ListenPort > 0 {
		out = append(out, ImplicitRule{
			Name: "WireGuard VPN", Chain: "input", Action: "accept",
			Service: fmt.Sprintf("UDP:%d", cfg.WireGuard.ListenPort),
			From:    "WAN", To: "SELF", Logged: true,
			Reason: "Öppnas automatiskt när WireGuard är aktiverat. Ligger före WAN-droppen, annars vore VPN:en oåtkomlig.",
		})
	}
	if cfg.OpenVPN != nil && cfg.OpenVPN.Enabled && cfg.OpenVPN.ListenPort > 0 {
		proto := "UDP"
		if cfg.OpenVPN.Protocol == "tcp" {
			proto = "TCP"
		}
		out = append(out, ImplicitRule{
			Name: "OpenVPN", Chain: "input", Action: "accept",
			Service: fmt.Sprintf("%s:%d", proto, cfg.OpenVPN.ListenPort),
			From:    "WAN", To: "SELF", Logged: true,
			Reason: "Öppnas automatiskt när OpenVPN är aktiverat. Ligger före WAN-droppen.",
		})
	}

	out = append(out, ImplicitRule{
		Name: "WAN Drop", Chain: "input", Action: "drop", Service: "ANY",
		From: "WAN", To: "SELF", Logged: true,
		Reason: "Allt annat inkommande från internet nekas. Ligger FÖRE alla LAN-regler, så ingen LAN-regel kan råka matcha WAN-trafik.",
	})

	// Beskrivs bara om något kort faktiskt kör DHCP-server.
	dhcpOn := false
	for _, iface := range cfg.Interfaces {
		if iface.Enabled && iface.Zone != "WAN" && iface.Device != "" &&
			iface.DHCP != nil && iface.DHCP.Enabled {
			dhcpOn = true
			break
		}
	}
	if dhcpOn {
		out = append(out, ImplicitRule{
			Name: "DHCP till brandväggen", Chain: "input", Action: "accept", Service: "UDP:67",
			From: "LAN / VLAN", To: "SELF", Logged: true,
			Reason: "Öppnas automatiskt på de kort där brandväggen är DHCP-server. Krävs för unicast-förnyelse av en befintlig lease (RFC 2131 RENEWING) — den första förfrågan tas emot via raw-socket och passerar aldrig den här kedjan.",
		})
	}

	if cfg.NTP != nil && cfg.NTP.Enabled {
		out = append(out, ImplicitRule{
			Name: "NTP till brandväggen", Chain: "input", Action: "accept", Service: "UDP:123",
			From: "LAN / VLAN", To: "SELF", Logged: true,
			Reason: "Öppnas automatiskt när NTP-servern är påslagen. Endast interna kort — en NTP-server nåbar från internet är ett förstärkningsverktyg för DDoS.",
		})
	}
	if cfg.DNS != nil && cfg.DNS.Enabled {
		out = append(out, ImplicitRule{
			Name: "DNS till brandväggen", Chain: "input", Action: "accept", Service: "UDP:53, TCP:53",
			From: "LAN / VLAN", To: "SELF", Logged: true,
			Reason: "Öppnas automatiskt när den lokala resolvern är påslagen.",
		})
	}
	return out
}
