// Package haproxy konfigurerar HAProxy i mode tcp för namnbaserad routning
// via SNI (Server Name Indication) — passthrough, INGEN TLS-terminering.
// HAProxy läser bara värdnamnet ur TLS ClientHello (req.ssl_sni) och relayar
// den krypterade strömmen vidare till rätt intern server, så certifikaten
// stannar på servrarna och änd-till-änd-krypteringen bevaras.
//
// Agenten äger /etc/haproxy/haproxy.cfg och start/stopp av tjänsten (samma
// minimala-touch-mönster som pkg/adapter/suricata mot Suricata). Varje aktiv
// SNIRoute blir en egen frontend; nftables-adaptern öppnar motsvarande
// INPUT-port (HAProxy lyssnar på brandväggen själv — inte DNAT).
package haproxy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

type Adapter struct {
	cfgPath string
}

const (
	defaultCfgPath = "/etc/haproxy/haproxy.cfg"
	unit           = "haproxy.service"
)

func NewAdapter(cfgPath string) *Adapter {
	if cfgPath == "" {
		cfgPath = defaultCfgPath
	}
	return &Adapter{cfgPath: cfgPath}
}

// hasActiveRoutes returnerar true om det finns minst en aktiv SNI-rutt med
// något mål att generera en frontend för.
func hasActiveRoutes(cfg *config.Config) bool {
	for _, r := range cfg.SNIRoutes {
		if r.Enabled && (len(r.Backends) > 0 || r.DefaultBackend != nil) {
			return true
		}
	}
	return false
}

// sanitizeName gör ett route-ID säkert som HAProxy proxy-namn (tillåtna
// tecken: bokstäver, siffror, '-', '_', '.', ':').
func sanitizeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "route"
	}
	return b.String()
}

// splitHostnames delar upp en backends hostnamn i exakta namn och wildcard-
// suffix. "*.exempel.se" blir suffixet ".exempel.se" (matchas med HAProxys
// `-m end`), medan "app.exempel.se" är ett exakt namn (`-i`).
func splitHostnames(hostnames []string) (exact, suffixes []string) {
	for _, h := range hostnames {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if strings.HasPrefix(h, "*.") {
			suffixes = append(suffixes, strings.ToLower(h[1:])) // "*.x.se" -> ".x.se"
		} else {
			exact = append(exact, strings.ToLower(h))
		}
	}
	return exact, suffixes
}

// backendServerLine returnerar HAProxy server-raden för ett mål (intern
// server eller lokal OpenVPN på loopback).
func backendServerLine(b config.SNIBackend) string {
	if b.LocalService == config.LocalServiceOpenVPN {
		return fmt.Sprintf("    server ovpn 127.0.0.1:%d", config.OpenVPNLoopbackPort)
	}
	return fmt.Sprintf("    server s0 %s:%d", b.TargetIP, b.TargetPort)
}

// GenerateConfig bygger hela haproxy.cfg-texten ur configen. Ren funktion
// (inga sidoeffekter) så den är enkel att enhetstesta.
func GenerateConfig(cfg *config.Config) (string, error) {
	var b strings.Builder

	b.WriteString("# Genererad av Security Harbor Agent — ändra inte för hand.\n")
	b.WriteString("global\n")
	b.WriteString("    daemon\n")
	b.WriteString("    maxconn 4096\n")
	b.WriteString("    user haproxy\n")
	b.WriteString("    group haproxy\n\n")
	b.WriteString("defaults\n")
	b.WriteString("    mode tcp\n")
	b.WriteString("    timeout connect 5s\n")
	b.WriteString("    timeout client 1h\n")
	b.WriteString("    timeout server 1h\n")
	b.WriteString("    timeout tunnel 24h\n")

	for _, r := range cfg.SNIRoutes {
		if !r.Enabled {
			continue
		}
		if len(r.Backends) == 0 && r.DefaultBackend == nil {
			continue
		}
		id := sanitizeName(r.ID)
		bind := fmt.Sprintf(":%d", r.ListenPort)
		if strings.TrimSpace(r.ExternalIP) != "" {
			bind = fmt.Sprintf("%s:%d", strings.TrimSpace(r.ExternalIP), r.ListenPort)
		}

		name := r.Name
		if name == "" {
			name = r.ID
		}
		b.WriteString(fmt.Sprintf("\n# --- SNI-rutt: %s ---\n", name))
		b.WriteString(fmt.Sprintf("frontend fe_%s\n", id))
		b.WriteString(fmt.Sprintf("    bind %s\n", bind))
		b.WriteString("    tcp-request inspect-delay 5s\n")
		b.WriteString("    tcp-request content accept if { req.ssl_hello_type 1 }\n")

		// ACL:er + use_backend per backend (i slice-ordning = matchningsordning).
		for i, be := range r.Backends {
			exact, suffixes := splitHostnames(be.Hostnames)
			if len(exact) == 0 && len(suffixes) == 0 {
				continue // inget att matcha på — hoppa (valideringen fångar detta)
			}
			var aclNames []string
			if len(exact) > 0 {
				aclName := fmt.Sprintf("sni_%s_%d_exact", id, i)
				b.WriteString(fmt.Sprintf("    acl %s req.ssl_sni -i %s\n", aclName, strings.Join(exact, " ")))
				aclNames = append(aclNames, aclName)
			}
			if len(suffixes) > 0 {
				aclName := fmt.Sprintf("sni_%s_%d_wild", id, i)
				b.WriteString(fmt.Sprintf("    acl %s req.ssl_sni -m end -i %s\n", aclName, strings.Join(suffixes, " ")))
				aclNames = append(aclNames, aclName)
			}
			b.WriteString(fmt.Sprintf("    use_backend be_%s_%d if %s\n", id, i, strings.Join(aclNames, " || ")))
		}

		if r.DefaultBackend != nil {
			b.WriteString(fmt.Sprintf("    default_backend be_%s_default\n", id))
		}

		// Backend-sektioner.
		for i, be := range r.Backends {
			exact, suffixes := splitHostnames(be.Hostnames)
			if len(exact) == 0 && len(suffixes) == 0 {
				continue
			}
			b.WriteString(fmt.Sprintf("\nbackend be_%s_%d\n", id, i))
			b.WriteString(backendServerLine(be) + "\n")
		}
		if r.DefaultBackend != nil {
			b.WriteString(fmt.Sprintf("\nbackend be_%s_default\n", id))
			b.WriteString(backendServerLine(*r.DefaultBackend) + "\n")
		}
	}

	return b.String(), nil
}

// ApplyConfig skriver haproxy.cfg och startar om tjänsten, eller stoppar den
// om inga aktiva rutter finns. Följer suricata-adapterns mönster: kontrollera
// skrivbarhet FÖRST (så rättighetsfel upptäcks innan nftables redan ändrats),
// validera med `haproxy -c` innan skarp skrivning.
func (a *Adapter) ApplyConfig(ctx context.Context, cfg *config.Config, dryRun bool) error {
	if !hasActiveRoutes(cfg) {
		if dryRun {
			return nil
		}
		_ = exec.CommandContext(ctx, "systemctl", "stop", unit).Run()
		return nil
	}

	if err := a.checkWritable(); err != nil {
		return err
	}

	text, err := GenerateConfig(cfg)
	if err != nil {
		return err
	}

	// Validera med `haproxy -c` mot en temporärfil (haproxy läser en fil,
	// inte stdin, till skillnad från `nft -f -`).
	if err := validateConfig(ctx, text); err != nil {
		return err
	}
	if dryRun {
		return nil
	}

	if err := os.WriteFile(a.cfgPath, []byte(text), 0644); err != nil {
		return fmt.Errorf("misslyckades skriva %s: %w", a.cfgPath, err)
	}
	if out, err := exec.CommandContext(ctx, "systemctl", "restart", unit).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart %s misslyckades: %w - output: %s", unit, err, string(out))
	}
	return nil
}

// validateConfig kör `haproxy -c -f <tmp>` på den genererade texten och
// returnerar ett begripligt fel om HAProxy underkänner den.
func validateConfig(ctx context.Context, text string) error {
	tmp, err := os.CreateTemp("", "sh-haproxy-*.cfg")
	if err != nil {
		return fmt.Errorf("kunde inte skapa temporär haproxy-fil: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(text); err != nil {
		tmp.Close()
		return fmt.Errorf("kunde inte skriva temporär haproxy-fil: %w", err)
	}
	tmp.Close()

	out, err := exec.CommandContext(ctx, "haproxy", "-c", "-f", tmp.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("HAProxy-konfigurationen underkändes (haproxy -c): %w - %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// checkWritable verifierar att haproxy.cfg finns och är skrivbar för agentens
// användare, med ett åtgärdsinriktat felmeddelande (samma resonemang som
// suricata-adapterns checkWritable).
func (a *Adapter) checkWritable() error {
	f, err := os.OpenFile(a.cfgPath, os.O_WRONLY, 0)
	if err == nil {
		return f.Close()
	}
	if os.IsNotExist(err) {
		return fmt.Errorf("SNI-routning kan inte aktiveras: %s saknas — är paketet haproxy installerat? (apt install haproxy)", a.cfgPath)
	}
	if os.IsPermission(err) {
		return fmt.Errorf("SNI-routning kan inte aktiveras: agenten saknar skrivrätt på %s. Kör på brandväggen: sudo chgrp security-harbor %s && sudo chmod g+w %s", a.cfgPath, a.cfgPath, a.cfgPath)
	}
	return fmt.Errorf("SNI-routning kan inte aktiveras: %s går inte att öppna för skrivning: %w", a.cfgPath, err)
}
