package engine

import (
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// MAC-adressen skrivs rakt in i ett `ip link set ... address`-anrop, så
// valideringen är det enda som står mellan användarens inmatning och
// kommandoraden.
func TestValidateInterfaceMAC(t *testing.T) {
	cases := []struct {
		mac string
		ok  bool
	}{
		{"", true}, // tomt = rör inte kortets MAC
		{"aa:bb:cc:dd:ee:ff", true},
		{"AA-BB-CC-DD-EE-FF", true},        // net.ParseMAC godtar bindestreck
		{"  aa:bb:cc:dd:ee:ff  ", true},    // blanksteg trimmas
		{"02:00:00:00:00:01", true},        // lokalt administrerad, unicast
		{"01:00:5e:00:00:01", false},       // multicast — ogiltig käll-MAC
		{"00:00:00:00:00:00", false},       // ingen användbar identitet
		{"aa:bb:cc:dd:ee:ff:00:11", false}, // EUI-64, går inte på ethernet
		{"inte-en-mac", false},
		{"aa:bb:cc:dd:ee", false},
		{"; reboot", false},
	}
	for _, c := range cases {
		err := validateInterfaceMAC(config.Interface{Device: "eth0", MACAddress: c.mac})
		if c.ok && err != nil {
			t.Errorf("MAC %q borde godtas, fick: %v", c.mac, err)
		}
		if !c.ok && err == nil {
			t.Errorf("MAC %q borde avvisas men godtogs", c.mac)
		}
	}
}
