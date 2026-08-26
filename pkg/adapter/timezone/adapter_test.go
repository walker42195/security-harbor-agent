package timezone

import "testing"

func TestSafeNameAcceptsRealZones(t *testing.T) {
	for _, zone := range []string{
		"UTC", "Europe/Stockholm", "America/Argentina/Buenos_Aires",
		"Etc/GMT+3", "America/Port-au-Prince",
	} {
		if !safeName.MatchString(zone) {
			t.Errorf("%q borde godtas", zone)
		}
	}
}

// Värdet kommer från GUI:t och hamnar i ett kommandoargument — allt som inte
// ser ut som ett IANA-namn ska avvisas innan det kommer dit.
func TestSafeNameRejectsInjection(t *testing.T) {
	for _, bad := range []string{
		"Europe/Stockholm; rm -rf /",
		"../../etc/passwd",
		"Europe/Stockholm\nUTC",
		"$(whoami)",
		"a/b/c/d",
		"",
	} {
		if safeName.MatchString(bad) {
			t.Errorf("%q borde avvisas", bad)
		}
	}
}
