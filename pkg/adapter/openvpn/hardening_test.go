package openvpn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func hardenedCfg() *config.Config {
	return &config.Config{
		OpenVPN: &config.OpenVPNConfig{
			Enabled:    true,
			ListenPort: 1194,
			Protocol:   "udp",
			Address:    "10.77.77.0/24",
			Endpoint:   "vpn.example.se",
			CACertPEM:  "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
		},
	}
}

func serverConf(t *testing.T, cfg *config.Config, key string) string {
	t.Helper()
	out, err := GenerateServerConfig(cfg, key)
	if err != nil {
		t.Fatalf("GenerateServerConfig: %v", err)
	}
	return out
}

// tls-crypt är den enskilt viktigaste raden när servern står vänd mot
// internet: utan den svarar OpenVPN på vem som helst som skickar ett paket
// till porten, och varje sårbarhet före certifikatvalideringen är nåbar.
func TestServerUsesTLSCrypt(t *testing.T) {
	key, err := GenerateTLSCryptKey()
	if err != nil {
		t.Fatal(err)
	}
	conf := serverConf(t, hardenedCfg(), key)
	if !strings.Contains(conf, "tls-crypt "+tlsCryptFileName) {
		t.Errorf("saknar tls-crypt:\n%s", conf)
	}
}

// Serverprocessen behöver root för tun-enheten och porten, men inget efteråt
// — och det är efteråt den tar emot trafik från internet.
func TestServerDropsPrivileges(t *testing.T) {
	conf := serverConf(t, hardenedCfg(), "")
	for _, want := range []string{"user " + unprivilegedUser, "group " + unprivilegedGroup} {
		if !strings.Contains(conf, want) {
			t.Errorf("saknar %q:\n%s", want, conf)
		}
	}
	// Rättighetsdroppet fungerar bara med persist-key/persist-tun: utan dem
	// kan processen inte läsa om nyckeln eller återskapa tun-enheten vid en
	// omförhandling när rättigheterna är borta.
	for _, want := range []string{"persist-key", "persist-tun"} {
		if !strings.Contains(conf, want) {
			t.Errorf("rättighetsdropp utan %q är trasigt:\n%s", want, conf)
		}
	}
}

// Med enbart `cipher` förhandlar OpenVPN 2.5+ fritt om datakanalens chiffer
// och en klient kan förmå servern att falla tillbaka på ett svagare val.
func TestNoNegotiableCipherDowngrade(t *testing.T) {
	for _, conf := range []string{
		serverConf(t, hardenedCfg(), ""),
		clientConf(t, hardenedCfg(), ""),
	} {
		if !strings.Contains(conf, "data-ciphers AES-256-GCM:AES-128-GCM") {
			t.Errorf("saknar uttömmande data-ciphers:\n%s", conf)
		}
		for _, line := range strings.Split(conf, "\n") {
			if strings.TrimSpace(line) == "cipher AES-256-GCM" {
				t.Error("gamla cipher-direktivet kvar — tillåter fri förhandling")
			}
		}
	}
}

func TestTLSVersionFloor(t *testing.T) {
	for _, conf := range []string{
		serverConf(t, hardenedCfg(), ""),
		clientConf(t, hardenedCfg(), ""),
	} {
		if !strings.Contains(conf, "tls-version-min 1.2") {
			t.Errorf("accepterar TLS 1.0/1.1:\n%s", conf)
		}
	}
}

// Samma CA utfärdar både server- och klientcertifikat. Utan EKU-kontroll
// duger en giltig klientprofil för att spela server mot någon annans klient.
func TestBothSidesCheckExtendedKeyUsage(t *testing.T) {
	if !strings.Contains(serverConf(t, hardenedCfg(), ""), "remote-cert-tls client") {
		t.Error("servern kontrollerar inte klientens EKU")
	}
	if !strings.Contains(clientConf(t, hardenedCfg(), ""), "remote-cert-tls server") {
		t.Error("klienten kontrollerar inte serverns EKU")
	}
}

// explicit-exit-notify finns bara för UDP. Med TCP loggar OpenVPN en varning
// vid varje start, och en konfiguration som klagar varje gång lär en att
// sluta läsa loggen.
func TestExplicitExitNotifyOnlyForUDP(t *testing.T) {
	udp := serverConf(t, hardenedCfg(), "")
	if !strings.Contains(udp, "explicit-exit-notify") {
		t.Error("saknas för UDP")
	}

	cfg := hardenedCfg()
	cfg.OpenVPN.Protocol = "tcp"
	if strings.Contains(serverConf(t, cfg, ""), "explicit-exit-notify") {
		t.Error("sattes trots TCP")
	}
}

func clientConf(t *testing.T, cfg *config.Config, key string) string {
	t.Helper()
	out, err := GenerateClientConfig(cfg, "CERT", "KEY", key)
	if err != nil {
		t.Fatalf("GenerateClientConfig: %v", err)
	}
	return out
}

// En profil utan nyckeln kommer inte in på en härdad server — servern kastar
// paketet innan TLS ens börjar.
func TestClientProfileCarriesTLSCryptKey(t *testing.T) {
	key, err := GenerateTLSCryptKey()
	if err != nil {
		t.Fatal(err)
	}
	conf := clientConf(t, hardenedCfg(), key)
	if !strings.Contains(conf, "<tls-crypt>") || !strings.Contains(conf, "</tls-crypt>") {
		t.Fatalf("nyckeln saknas i profilen:\n%s", conf)
	}
	if !strings.Contains(conf, tlsCryptHeader) {
		t.Error("nyckelns innehåll bakades inte in, bara taggarna")
	}
}

func TestGeneratedKeyHasOpenVPNStaticKeyFormat(t *testing.T) {
	key, err := GenerateTLSCryptKey()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidTLSCryptKey(key) {
		t.Fatalf("egen nyckel underkändes av egen validering:\n%s", key)
	}
	// 2048 bitar över 16 rader — OpenVPN vägrar starta på annat.
	rows := 0
	for _, line := range strings.Split(key, "\n") {
		if len(strings.TrimSpace(line)) == 32 {
			rows++
		}
	}
	if rows != 16 {
		t.Errorf("fick %d hexrader, förväntade 16", rows)
	}
}

// Två anrop får aldrig ge samma nyckel — den skyddar alla klienter samtidigt.
func TestGeneratedKeysAreUnique(t *testing.T) {
	a, _ := GenerateTLSCryptKey()
	b, _ := GenerateTLSCryptKey()
	if a == b {
		t.Fatal("två genererade nycklar var identiska")
	}
}

// En trasig nyckel gör att OpenVPN vägrar starta, och eftersom nyckeln aldrig
// visas för någon människa vore felet därifrån svårt att koppla till orsaken.
func TestValidationRejectsBrokenKeys(t *testing.T) {
	good, _ := GenerateTLSCryptKey()
	cases := map[string]string{
		"tom":              "",
		"utan huvud":       strings.Replace(good, tlsCryptHeader, "", 1),
		"utan fot":         strings.Replace(good, tlsCryptFooter, "", 1),
		"en rad borttagen": strings.Replace(good, "\n", "", 5),
		"icke-hex":         strings.Replace(good, "a", "z", -1),
		"bara text":        "hemlig nyckel",
	}
	for name, key := range cases {
		if ValidTLSCryptKey(key) {
			t.Errorf("%s godkändes", name)
		}
	}
	if !ValidTLSCryptKey(good) {
		t.Error("en giltig nyckel underkändes")
	}
}

// Nyckeln får aldrig skrivas om den är trasig: filen läses av OpenVPN, inte
// av en människa, så felet skulle synas först som en server som inte startar.
func TestApplyRejectsBrokenKey(t *testing.T) {
	a := NewAdapter(t.TempDir())
	err := a.ApplyConfig(t.Context(), hardenedCfg(), "ca", "crt", "key", "crl", "inte en nyckel", false)
	if err == nil {
		t.Fatal("en trasig tls-crypt-nyckel accepterades")
	}
	if !strings.Contains(err.Error(), "tls-crypt") {
		t.Errorf("felmeddelandet nämner inte tls-crypt: %v", err)
	}
}

// Agenten kör INTE som root, och /etc/openvpn ägs normalt av root. Ett
// villkorslöst chmod hade därför misslyckats och slagit ut hela
// OpenVPN-appliceringen på varje installation där katalogen redan var rätt
// satt — regressionen fångades bara genom att titta på en riktig maskin.
func TestApplyLeavesAlreadyTraversableDirAlone(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o775); err != nil {
		t.Fatal(err)
	}
	a := NewAdapter(dir)
	key, _ := GenerateTLSCryptKey()
	if err := a.ApplyConfig(t.Context(), hardenedCfg(), "ca", "crt", "srvkey", "crl", key, true); err != nil {
		t.Fatalf("dry-run misslyckades: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o775 {
		t.Errorf("rättigheterna ändrades från 0775 till %v", got)
	}
}

// En för snäv katalog rättas, så att den nedgraderade processen kan läsa om
// spärrlistan vid varje ny anslutning.
func TestApplyOpensTooRestrictiveDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	a := NewAdapter(dir)
	if err := a.ensureTraversable(); err != nil {
		t.Fatalf("ensureTraversable: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o005 != 0o005 {
		t.Errorf("katalogen är fortfarande otillgänglig: %v", info.Mode().Perm())
	}
}

// Nyckelfilen får aldrig bli läsbar för den nedgraderade processen — då vore
// hela poängen med tls-crypt borta.
func TestSecretsAreOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	a := NewAdapter(dir)
	key, _ := GenerateTLSCryptKey()
	if err := a.writeFiles(hardenedCfg(), "ca", "crt", "srvkey", "crl", key); err != nil {
		t.Fatalf("writeFiles: %v", err)
	}
	for _, secret := range []string{"server.key", tlsCryptFileName} {
		info, err := os.Stat(filepath.Join(dir, secret))
		if err != nil {
			t.Fatalf("%s: %v", secret, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("%s har rättigheterna %v, förväntade 0600", secret, got)
		}
	}
}
