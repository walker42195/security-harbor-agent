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

// tlsCryptFileName är nyckelfilen i a.dir. Skrivs med 0600 — läcker den är
// tls-crypt-skyddet borta för alla klienter samtidigt.
const tlsCryptFileName = "tls-crypt.key"

// Kontot serverprocessen växlar ner till efter uppstart. nobody/nogroup finns
// på Debian och Ubuntu, som är de distributioner installationen stödjer.
const (
	unprivilegedUser  = "nobody"
	unprivilegedGroup = "nogroup"
)

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
func GenerateServerConfig(cfg *config.Config, tlsCryptKey string) (string, error) {
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
	fronted, _ := cfg.OpenVPNFrontedBySNI()
	if fronted {
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
	// data-ciphers ersätter det gamla `cipher`-direktivet. Med enbart
	// `cipher` FÖRHANDLAR OpenVPN 2.5+ fritt om datakanalens chiffer, och en
	// klient kan då förmå servern att falla tillbaka på ett svagare val.
	// Listan här är uttömmande: allt utanför den avvisas.
	fmt.Fprintf(&b, "data-ciphers AES-256-GCM:AES-128-GCM\n")
	fmt.Fprintf(&b, "data-ciphers-fallback AES-256-GCM\n")
	fmt.Fprintf(&b, "auth SHA256\n")
	fmt.Fprintf(&b, "tls-server\n")
	// TLS 1.0 och 1.1 är avskrivna sedan länge; utan den här raden accepterar
	// OpenVPN dem fortfarande om klienten föreslår det.
	fmt.Fprintf(&b, "tls-version-min 1.2\n")
	// Kräver att klientcertifikatet har klient-EKU. Utan detta duger VILKET
	// certifikat som helst utfärdat av CA:n — och eftersom samma CA utfärdar
	// både server- och klientcertifikat räcker det annars med en giltig
	// klientprofil för att spela server mot någon annans klient.
	fmt.Fprintf(&b, "remote-cert-tls client\n")
	if tlsCryptKey != "" {
		// Se GenerateTLSCryptKey för varför det här är den enskilt viktigaste
		// raden när servern står vänd mot internet.
		fmt.Fprintf(&b, "tls-crypt %s\n", tlsCryptFileName)
	}
	// explicit-exit-notify finns bara för UDP. Med TCP loggar OpenVPN en
	// varning vid varje start — och en konfiguration som klagar varje gång
	// lär en att sluta läsa loggen.
	if protocol == "udp" && !fronted {
		fmt.Fprintf(&b, "explicit-exit-notify 1\n")
	}
	// Släpp root efter uppstart. Serverprocessen behöver root för att skapa
	// tun-enheten och binda porten, men inget av det efteråt — och det är
	// efteråt den tar emot trafik från internet. persist-key/persist-tun ovan
	// är förutsättningen: utan dem kan processen inte läsa om nyckeln eller
	// återskapa tun-enheten vid en omförhandling när rättigheterna är borta.
	fmt.Fprintf(&b, "user %s\n", unprivilegedUser)
	fmt.Fprintf(&b, "group %s\n", unprivilegedGroup)
	// verb 3 loggar klienters IP-adresser vid varje anslutning. Det är rimligt
	// på en brandvägg man själv driver, men mer än vad som behövs för drift.
	fmt.Fprintf(&b, "verb 3\n")

	return b.String(), nil
}

// GenerateClientConfig renderar en komplett, självständig .ovpn-fil (inline
// ca/cert/key) för en given klient. clientCertPEM/clientKeyPEM kommer från
// pki.IssueCert och sparas ALDRIG på brandväggen — de returneras bara en
// gång till GUI:t (se API-endpointen generate-client, Fas 4).
func GenerateClientConfig(cfg *config.Config, clientCertPEM, clientKeyPEM, tlsCryptKey string) (string, error) {
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
	// Speglar serverns inställningar. Avviker de går anslutningen inte att
	// upprätta alls — vilket är avsikten: hellre ett tydligt fel än en tyst
	// nedgradering till något svagare.
	fmt.Fprintf(&b, "data-ciphers AES-256-GCM:AES-128-GCM\n")
	fmt.Fprintf(&b, "data-ciphers-fallback AES-256-GCM\n")
	fmt.Fprintf(&b, "auth SHA256\n")
	fmt.Fprintf(&b, "tls-version-min 1.2\n")
	// Håll inte kvar lösenfrasen till den privata nyckeln i minnet mellan
	// omförhandlingar.
	fmt.Fprintf(&b, "auth-nocache\n")
	fmt.Fprintf(&b, "verb 3\n")
	fmt.Fprintf(&b, "<ca>\n%s</ca>\n", strings.TrimSpace(ovpn.CACertPEM)+"\n")
	fmt.Fprintf(&b, "<cert>\n%s</cert>\n", strings.TrimSpace(clientCertPEM)+"\n")
	fmt.Fprintf(&b, "<key>\n%s</key>\n", strings.TrimSpace(clientKeyPEM)+"\n")
	// Utan tls-crypt-nyckeln kommer klienten inte in på en härdad server —
	// den måste följa med i profilen.
	if tlsCryptKey != "" {
		fmt.Fprintf(&b, "<tls-crypt>\n%s</tls-crypt>\n", strings.TrimSpace(tlsCryptKey)+"\n")
	}

	return b.String(), nil
}

// ApplyConfig skriver server.conf + ca.crt/server.crt/server.key/crl.pem och
// startar/stoppar/restartar openvpn@<InstanceName>.service därefter.
func (a *Adapter) ApplyConfig(ctx context.Context, cfg *config.Config, caCertPEM, serverCertPEM, serverKeyPEM, crlPEM, tlsCryptKey string, dryRun bool) error {
	unit := "openvpn@" + InstanceName + ".service"

	if cfg.OpenVPN == nil || !cfg.OpenVPN.Enabled {
		if dryRun {
			return nil
		}
		_ = exec.CommandContext(ctx, "systemctl", "stop", unit).Run()
		return nil
	}

	// Genereras även vid dry-run: ett ogiltigt subnät ska ge fel INNAN man
	// trycker Applicera, inte efteråt.
	if _, err := GenerateServerConfig(cfg, tlsCryptKey); err != nil {
		return fmt.Errorf("misslyckades generera OpenVPN-serverkonfiguration: %w", err)
	}

	if dryRun {
		return nil
	}

	// Katalogen måste vara läs- och gångbar för ANDRA än ägaren, och det
	// hänger ihop med rättighetsdroppet i serverkonfigurationen:
	// `crl-verify` läses om vid VARJE ny anslutning, alltså efter att
	// serverprocessen växlat ner till nobody. Med en katalog bara ägaren får
	// gå in i skulle varje klient nekas så fort spärrlistan skulle läsas —
	// och felet hade sett ut som ett certifikatproblem.
	//
	// Hemligheterna skyddas av filrättigheterna i stället: server.key och
	// tls-crypt.key skrivs 0600 och läses en gång vid uppstart, medan
	// OpenVPN fortfarande är root.
	if err := os.MkdirAll(a.dir, 0755); err != nil {
		return fmt.Errorf("misslyckades skapa katalog %s: %w", a.dir, err)
	}
	if err := a.ensureTraversable(); err != nil {
		return err
	}

	if err := a.writeFiles(cfg, caCertPEM, serverCertPEM, serverKeyPEM, crlPEM, tlsCryptKey); err != nil {
		return err
	}

	if out, err := exec.CommandContext(ctx, "systemctl", "restart", unit).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart %s misslyckades: %w - output: %s", unit, err, string(out))
	}

	return nil
}

// writeFiles skriver serverkonfigurationen och nyckelmaterialet till a.dir.
//
// Hemligheterna (allt som slutar på .key) skrivs 0600; resten 0644 så att den
// nedgraderade serverprocessen kan läsa om spärrlistan.
func (a *Adapter) writeFiles(cfg *config.Config, caCertPEM, serverCertPEM, serverKeyPEM, crlPEM, tlsCryptKey string) error {
	serverConf, err := GenerateServerConfig(cfg, tlsCryptKey)
	if err != nil {
		return fmt.Errorf("misslyckades generera OpenVPN-serverkonfiguration: %w", err)
	}

	files := map[string]string{
		InstanceName + ".conf": serverConf,
		"ca.crt":               caCertPEM,
		"server.crt":           serverCertPEM,
		"server.key":           serverKeyPEM,
		"crl.pem":              crlPEM,
	}
	if tlsCryptKey != "" {
		// Kontrolleras här och inte bara vid genereringen: nyckeln passerar
		// kryptering och disk på vägen hit, och OpenVPN vägrar starta på en
		// trasig nyckel med ett fel som är svårt att härleda.
		if !ValidTLSCryptKey(tlsCryptKey) {
			return fmt.Errorf("openvpn: tls-crypt-nyckeln har fel format")
		}
		files[tlsCryptFileName] = tlsCryptKey
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
	return nil
}

// ensureTraversable ser till att a.dir går att läsa för den nedgraderade
// serverprocessen.
//
// Rättar BARA en katalog som faktiskt är för snäv, och bara om vi äger den.
// Agenten kör inte som root och /etc/openvpn ägs normalt av root — ett
// villkorslöst chmod hade därför misslyckats och slagit ut hela
// OpenVPN-appliceringen på varje installation där katalogen redan är rätt
// satt. Går den inte att rätta ges ett fel som säger varför det spelar roll,
// i stället för att servern startar och sedan nekar varje klient.
func (a *Adapter) ensureTraversable() error {
	info, err := os.Stat(a.dir)
	if err != nil {
		return fmt.Errorf("misslyckades läsa katalogen %s: %w", a.dir, err)
	}
	const needed = 0o005 // r-x för "andra"
	if info.Mode().Perm()&needed == needed {
		return nil
	}
	if err := os.Chmod(a.dir, info.Mode().Perm()|needed); err != nil {
		return fmt.Errorf(
			"katalogen %s är inte läsbar för den nedgraderade OpenVPN-processen (%v) "+
				"och rättigheterna kunde inte ändras: %w — utan detta nekas varje "+
				"klient när spärrlistan ska läsas om",
			a.dir, info.Mode().Perm(), err)
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
