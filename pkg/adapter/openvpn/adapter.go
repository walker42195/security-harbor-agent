// Package openvpn genererar OpenVPN-serverns konfiguration (Fas 4) och
// applicerar den genom att skriva /etc/openvpn/<instans>.conf + CA/cert/
// CRL-filerna och sedan starta/stoppa systemd-enheten openvpn@<instans>.
// Till skillnad från WireGuard-adaptern (Fas 3, som pratar direkt med
// kärnan via ip/wg) finns det ingen root-fri väg att skapa ett tun-device
// och hantera OpenVPN:s TLS-baserade kontrollkanal utan själva openvpn-
// daemonen — därför krävs en scoped polkit-regel för `systemctl restart
// openvpn@sh-server.service`, på samma sätt som redan gäller för Kea
// DHCP (se /etc/polkit-1/rules.d/49-security-harbor-agent.rules).
package openvpn

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

const InstanceName = "sh-server"

type Adapter struct {
	// dir är katalogen där server.conf/ca.crt/server.crt/server.key/crl.pem
	// skrivs, normalt /etc/openvpn.
	dir string
}

func NewAdapter(dir string) *Adapter {
	if dir == "" {
		dir = "/etc/openvpn"
	}
	return &Adapter{dir: dir}
}

// GenerateServerConfig renderar server.conf. "dh none" används medvetet
// istället för klassiska Diffie-Hellman-parametrar (`openssl dhparam`, som
// tar lång tid att generera) — från OpenVPN 2.4+ är detta säkert när
// ECDHE-cipher-sviter används, vilket är standard i moderna OpenSSL-bygen.
func GenerateServerConfig(cfg *config.Config) (string, error) {
	if cfg.OpenVPN == nil || !cfg.OpenVPN.Enabled {
		return "", nil
	}
	ovpn := cfg.OpenVPN

	network, netmask, err := networkAndMask(ovpn.Address)
	if err != nil {
		return "", fmt.Errorf("ogiltigt OpenVPN-subnät %q: %w", ovpn.Address, err)
	}

	protocol := ovpn.Protocol
	if protocol == "" {
		protocol = "udp"
	}

	var b bytes.Buffer
	// Om en SNI-rutt frontar OpenVPN (port-delning på t.ex. 443) äger HAProxy
	// den publika porten — OpenVPN binder då loopback-TCP i stället, och
	// HAProxy relayar SNI-lös trafik dit. Kräver TCP (valideras i engine).
	if fronted, _ := cfg.OpenVPNFrontedBySNI(); fronted {
		fmt.Fprintf(&b, "port %d\n", config.OpenVPNLoopbackPort)
		fmt.Fprintf(&b, "proto tcp-server\n")
		fmt.Fprintf(&b, "local 127.0.0.1\n")
	} else {
		fmt.Fprintf(&b, "port %d\n", ovpn.ListenPort)
		fmt.Fprintf(&b, "proto %s\n", protocol)
	}
	fmt.Fprintf(&b, "dev tun\n")
	fmt.Fprintf(&b, "ca ca.crt\n")
	fmt.Fprintf(&b, "cert server.crt\n")
	fmt.Fprintf(&b, "key server.key\n")
	fmt.Fprintf(&b, "dh none\n")
	fmt.Fprintf(&b, "topology subnet\n")
	fmt.Fprintf(&b, "server %s %s\n", network, netmask)
	fmt.Fprintf(&b, "crl-verify crl.pem\n")
	fmt.Fprintf(&b, "keepalive 10 60\n")
	fmt.Fprintf(&b, "persist-key\n")
	fmt.Fprintf(&b, "persist-tun\n")
	fmt.Fprintf(&b, "cipher AES-256-GCM\n")
	fmt.Fprintf(&b, "auth SHA256\n")
	fmt.Fprintf(&b, "tls-server\n")
	fmt.Fprintf(&b, "explicit-exit-notify 1\n")
	fmt.Fprintf(&b, "verb 3\n")

	return b.String(), nil
}

// GenerateClientConfig renderar en komplett, självständig .ovpn-fil (inline
// ca/cert/key) för en given klient. clientCertPEM/clientKeyPEM kommer från
// pki.IssueCert och sparas ALDRIG på brandväggen — de returneras bara en
// gång till GUI:t (se API-endpointen generate-client, Fas 4).
func GenerateClientConfig(cfg *config.Config, clientCertPEM, clientKeyPEM string) (string, error) {
	if cfg.OpenVPN == nil {
		return "", fmt.Errorf("openvpn: ingen serverkonfiguration")
	}
	ovpn := cfg.OpenVPN

	protocol := ovpn.Protocol
	if protocol == "" {
		protocol = "udp"
	}
	// När OpenVPN frontas av en SNI-rutt ansluter klienten mot HAProxy på den
	// publika porten (ovpn.ListenPort, t.ex. 443) via TCP — HAProxy relayar
	// transparent till den loopback-bundna OpenVPN-servern.
	if fronted, _ := cfg.OpenVPNFrontedBySNI(); fronted {
		protocol = "tcp"
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "client\n")
	fmt.Fprintf(&b, "dev tun\n")
	fmt.Fprintf(&b, "proto %s\n", protocol)
	fmt.Fprintf(&b, "remote %s %d\n", ovpn.Endpoint, ovpn.ListenPort)
	fmt.Fprintf(&b, "resolv-retry infinite\n")
	fmt.Fprintf(&b, "nobind\n")
	fmt.Fprintf(&b, "persist-key\n")
	fmt.Fprintf(&b, "persist-tun\n")
	fmt.Fprintf(&b, "remote-cert-tls server\n")
	fmt.Fprintf(&b, "cipher AES-256-GCM\n")
	fmt.Fprintf(&b, "auth SHA256\n")
	fmt.Fprintf(&b, "verb 3\n")
	fmt.Fprintf(&b, "<ca>\n%s</ca>\n", strings.TrimSpace(ovpn.CACertPEM)+"\n")
	fmt.Fprintf(&b, "<cert>\n%s</cert>\n", strings.TrimSpace(clientCertPEM)+"\n")
	fmt.Fprintf(&b, "<key>\n%s</key>\n", strings.TrimSpace(clientKeyPEM)+"\n")

	return b.String(), nil
}

// ApplyConfig skriver server.conf + ca.crt/server.crt/server.key/crl.pem och
// startar/stoppar/restartar openvpn@<InstanceName>.service därefter.
func (a *Adapter) ApplyConfig(ctx context.Context, cfg *config.Config, caCertPEM, serverCertPEM, serverKeyPEM, crlPEM string, dryRun bool) error {
	unit := "openvpn@" + InstanceName + ".service"

	if cfg.OpenVPN == nil || !cfg.OpenVPN.Enabled {
		if dryRun {
			return nil
		}
		_ = exec.CommandContext(ctx, "systemctl", "stop", unit).Run()
		return nil
	}

	serverConf, err := GenerateServerConfig(cfg)
	if err != nil {
		return fmt.Errorf("misslyckades generera OpenVPN-serverkonfiguration: %w", err)
	}

	if dryRun {
		return nil
	}

	if err := os.MkdirAll(a.dir, 0700); err != nil {
		return fmt.Errorf("misslyckades skapa katalog %s: %w", a.dir, err)
	}

	files := map[string]string{
		InstanceName + ".conf": serverConf,
		"ca.crt":               caCertPEM,
		"server.crt":           serverCertPEM,
		"server.key":           serverKeyPEM,
		"crl.pem":              crlPEM,
	}
	for name, content := range files {
		mode := os.FileMode(0644)
		if strings.HasSuffix(name, ".key") {
			mode = 0600
		}
		if err := os.WriteFile(filepath.Join(a.dir, name), []byte(content), mode); err != nil {
			return fmt.Errorf("misslyckades skriva %s: %w", name, err)
		}
	}

	if out, err := exec.CommandContext(ctx, "systemctl", "restart", unit).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart %s misslyckades: %w - output: %s", unit, err, string(out))
	}

	return nil
}

// networkAndMask konverterar ett CIDR ("10.77.77.0/24") till OpenVPN:s
// `server`-direktivformat (nätadress + dotted-decimal-nätmask).
func networkAndMask(cidr string) (network, netmask string, err error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", err
	}
	_ = ip
	mask := ipNet.Mask
	if len(mask) != 4 {
		return "", "", fmt.Errorf("endast IPv4-subnät stöds")
	}
	return ipNet.IP.String(), fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3]), nil
}
