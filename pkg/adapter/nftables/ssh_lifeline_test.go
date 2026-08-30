package nftables

import (
	"strings"
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func lifelineRule(t *testing.T, cfg *config.Config) *Rule {
	t.Helper()
	for _, r := range renderRules(t, cfg) {
		if r.Comment == sshLifelineComment {
			rule := r
			return &rule
		}
	}
	return nil
}

// Livlinan ska finnas ÄVEN när policylistan är helt tom — det är hela
// poängen: den överlever att SSH-policyn raderas, stängs av eller pekar på
// ett kort som inte finns.
func TestSSHLifelineExistsWithoutAnyPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.Config
	}{
		{"gateway utan policyer", &config.Config{
			Interfaces: []config.Interface{
				{Device: "ens18", Zone: "WAN", Enabled: true},
				{Device: "ens19", Zone: "LAN", Enabled: true},
			},
		}},
		{"host-läge utan policyer", &config.Config{
			Settings:   config.Settings{Mode: config.ModeHost},
			Interfaces: []config.Interface{{Device: "ens18", Zone: "HOST", Enabled: true}},
		}},
		{"config med kort som inte finns", &config.Config{
			Settings:   config.Settings{Mode: config.ModeHost},
			Interfaces: []config.Interface{{Device: "eth0", Zone: "HOST", Enabled: true}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := lifelineRule(t, tc.cfg)
			if r == nil {
				t.Fatal("livlineregeln saknas i regelsetet")
			}
			if r.Chain != "input" {
				t.Errorf("livlinan hamnade i kedjan %q, ska vara input", r.Chain)
			}
			expr := exprJSON(t, *r)
			if !strings.Contains(expr, "\"dport\"") || !strings.Contains(expr, "22") {
				t.Errorf("livlinan öppnar inte port 22: %s", expr)
			}
			if !strings.Contains(expr, "accept") {
				t.Errorf("livlinan accepterar inte: %s", expr)
			}
		})
	}
}

// I gateway-läge får livlinan ALDRIG gälla WAN-kortet — då hade den
// exponerat SSH mot internet, vilket vore ett långt värre problem än det
// den löser.
func TestSSHLifelineNeverAppliesToWAN(t *testing.T) {
	cfg := &config.Config{
		Interfaces: []config.Interface{
			{Device: "ens18", Zone: "WAN", Enabled: true},
			{Device: "ens19", Zone: "LAN", Enabled: true},
		},
	}
	r := lifelineRule(t, cfg)
	if r == nil {
		t.Fatal("livlineregeln saknas")
	}
	expr := exprJSON(t, *r)
	if !strings.Contains(expr, "\"!=\"") {
		t.Fatalf("livlinan saknar iifname != WAN-villkor: %s", expr)
	}
	if !strings.Contains(expr, "ens18") {
		t.Fatalf("livlinan undantar inte WAN-kortet ens18: %s", expr)
	}
}

// Livlinan måste ligga före HARD WAN DROP och före alla policy-genererade
// regler — en Deny-policy som hamnade före den hade gjort den verkningslös.
func TestSSHLifelineComesBeforePolicies(t *testing.T) {
	cfg := &config.Config{
		Interfaces: []config.Interface{
			{Device: "ens18", Zone: "WAN", Enabled: true},
			{Device: "ens19", Zone: "LAN", Enabled: true},
		},
		Policies: []config.Policy{{
			ID: "deny-all", Name: "Neka allt", Enabled: true, Local: true,
			Action: config.ActionDrop, SourceZone: "LAN", Service: "ANY",
		}},
	}
	lifelineIdx, denyIdx := -1, -1
	for i, r := range renderRules(t, cfg) {
		if r.Chain != "input" {
			continue
		}
		if r.Comment == sshLifelineComment {
			lifelineIdx = i
		}
		if strings.Contains(r.Comment, "Neka allt") && denyIdx == -1 {
			denyIdx = i
		}
	}
	if lifelineIdx == -1 {
		t.Fatal("livlineregeln saknas")
	}
	if denyIdx != -1 && lifelineIdx > denyIdx {
		t.Fatalf("livlinan (index %d) ligger EFTER Deny-policyn (index %d) och är därmed verkningslös",
			lifelineIdx, denyIdx)
	}
}
