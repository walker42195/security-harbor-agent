package api

import "testing"

// Värdet kommer från en HTTP-parameter och hamnar i ett kommandoargument
// till journalctl. Bara "<tal><m|h|d>" får släppas igenom.
func TestFirewallLogWindowRejectsInjection(t *testing.T) {
	for _, bad := range []string{
		"15m; rm -rf /", "--output=cat", "-1h", "2026-08-26", "yesterday",
		"15 m", "15M", "15s", "", "99999m", "m", "15mm", "$(id)",
	} {
		if firewallLogWindowRe.MatchString(bad) {
			t.Errorf("%q borde avvisas", bad)
		}
	}
}

func TestFirewallLogWindowAcceptsRealValues(t *testing.T) {
	for _, ok := range []string{"1m", "15m", "60m", "1h", "6h", "24h", "1d", "7d", "30d"} {
		if !firewallLogWindowRe.MatchString(ok) {
			t.Errorf("%q borde godtas", ok)
		}
	}
}
