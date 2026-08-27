package traffic

import "testing"

func TestExtractSrc(t *testing.T) {
	// Verklig rad från maskinen.
	line := `SH-DENY-INPUT-DefaultDeny: IN=ens19 OUT= MAC=ff:ff:ff:ff:ff:ff:e0:63:da:8a:6f:bc:08:00 SRC=10.0.0.105 DST=255.255.255.255 LEN=225 TOS=0x00 PROTO=UDP SPT=42030 DPT=10001`
	if got := extractSrc(line); got != "10.0.0.105" {
		t.Errorf("fick %q, ville ha 10.0.0.105", got)
	}

	// IPv6 loggas också men hör inte hemma i en IPv4-baserad enhetsvy.
	v6 := `SH-DENY-INPUT-DefaultDeny: IN=ens19 SRC=fe80:0000:0000:0000:e263:daff:fe8a:6fbc DST=ff02:0000:0000:0000:0000:0000:0000:0001 PROTO=UDP`
	if got := extractSrc(v6); got != "" {
		t.Errorf("IPv6 gav %q, ville ha tom sträng", got)
	}

	// Rader utan SRC ska inte ge skräp.
	if got := extractSrc("något helt annat"); got != "" {
		t.Errorf("fick %q", got)
	}
	// SRC sist på raden, utan efterföljande blanksteg.
	if got := extractSrc("PROTO=UDP SRC=10.1.2.3"); got != "10.1.2.3" {
		t.Errorf("fick %q", got)
	}
}

func TestItoa(t *testing.T) {
	for _, c := range []struct {
		in   int
		want string
	}{{0, "0"}, {7, "7"}, {20000, "20000"}, {123456, "123456"}} {
		if got := itoa(c.in); got != c.want {
			t.Errorf("itoa(%d) = %q, ville ha %q", c.in, got, c.want)
		}
	}
}
