package main

import "testing"

// Regression: filtret var tidigare HELT ovaliderat och gick rakt in som ett
// argv-element till en tcpdump som körs som root. tcpdump tolkar ett
// argument som börjar med "-" som en flagga (getopt tillåter sammanskriven
// form), så "-w/sökväg" gav godtycklig filskrivning som root.
func TestValidateFilterRejectsFlagInjection(t *testing.T) {
	bad := []string{
		"-w/etc/rsyslog.d/x.conf",
		"-r/etc/shadow",
		"-z/tmp/evil.sh",
		"  -w/tmp/x",
		"port 443; rm -rf /",
		"port 443 `id`",
		"port $(id)",
	}
	for _, f := range bad {
		if err := validateFilter(f); err == nil {
			t.Errorf("skulle AVVISAS: %q", f)
		}
	}

	ok := []string{
		"",
		"port 443",
		"host 10.0.0.5 and tcp",
		"tcp port 80 or udp port 53",
		"net 192.168.1.0/24",
		"not arp",
		"tcp[13] & 2 != 0",
	}
	for _, f := range ok {
		if err := validateFilter(f); err != nil {
			t.Errorf("skulle accepteras: %q -> %v", f, err)
		}
	}
}

func TestValidateArgRejectsFlagLikeInterface(t *testing.T) {
	for _, iface := range []string{"-i", "--interface", "-w/tmp/x", "ens19 extra"} {
		if err := validateArg(iface); err == nil {
			t.Errorf("skulle AVVISAS: %q", iface)
		}
	}
	for _, iface := range []string{"ens19", "ens19.1337", "br-lan", "wg0"} {
		if err := validateArg(iface); err != nil {
			t.Errorf("skulle accepteras: %q -> %v", iface, err)
		}
	}
}
