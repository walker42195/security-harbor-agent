package openvpn

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// tls-crypt-nyckelns format är OpenVPN:s "Static key V1": 2048 bitar råa
// slumpbytes skrivna som hexadecimal, 16 rader om 32 tecken, mellan två
// BEGIN/END-rader. Nyckeln genereras här i stället för genom att anropa
// `openvpn --genkey`: den behöver ingen annan indata än slumptal, och att
// skapa den själv slipper ett externt beroende i en kodväg som körs vid
// första uppstart.
const (
	tlsCryptKeyBytes    = 256 // 2048 bitar
	tlsCryptBytesPerRow = 16  // 32 hextecken per rad
	tlsCryptHeader      = "-----BEGIN OpenVPN Static key V1-----"
	tlsCryptFooter      = "-----END OpenVPN Static key V1-----"
)

// GenerateTLSCryptKey skapar en ny tls-crypt-nyckel.
//
// tls-crypt lägger ett symmetriskt lager runt HELA TLS-kontrollkanalen. Utan
// det svarar OpenVPN-servern på vem som helst som råkar skicka ett paket till
// porten: den syns i portskanningar, den går att fingeravtrycka, och varje
// sårbarhet som finns FÖRE certifikatvalideringen — i OpenVPN självt eller i
// OpenSSL — är nåbar för vem som helst på internet. Med tls-crypt kastas
// paket utan rätt nyckel innan något av det ens börjar tolkas.
//
// Nyckeln är delad mellan servern och alla klienter. Den ersätter alltså inte
// certifikaten: den skyddar inte klienter från varandra, den flyttar bara
// själva angreppsytan bakom en dörr som kräver en nyckel att ens knacka på.
func GenerateTLSCryptKey() (string, error) {
	raw := make([]byte, tlsCryptKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("misslyckades generera tls-crypt-nyckel: %w", err)
	}

	var b strings.Builder
	b.WriteString("#\n# 2048 bit OpenVPN static key\n#\n")
	b.WriteString(tlsCryptHeader + "\n")
	for i := 0; i < len(raw); i += tlsCryptBytesPerRow {
		fmt.Fprintf(&b, "%x\n", raw[i:i+tlsCryptBytesPerRow])
	}
	b.WriteString(tlsCryptFooter + "\n")
	return b.String(), nil
}

// ValidTLSCryptKey kontrollerar att en nyckel har rätt form.
//
// Används innan den skrivs till disk och innan den bakas in i en klientfil.
// En trasig nyckel gör att OpenVPN vägrar starta — och eftersom nyckeln
// aldrig visas för någon människa vore felmeddelandet därifrån svårt att
// koppla till orsaken.
func ValidTLSCryptKey(key string) bool {
	if !strings.Contains(key, tlsCryptHeader) || !strings.Contains(key, tlsCryptFooter) {
		return false
	}
	rows := 0
	for _, line := range strings.Split(key, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-----") {
			continue
		}
		if len(line) != tlsCryptBytesPerRow*2 {
			return false
		}
		if strings.TrimLeft(line, "0123456789abcdefABCDEF") != "" {
			return false
		}
		rows++
	}
	return rows == tlsCryptKeyBytes/tlsCryptBytesPerRow
}
