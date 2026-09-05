package store

import (
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func TestEnsureDefaultVPNAutoBlock(t *testing.T) {
	cfg := &config.Config{Version: 1}
	if !ensureDefaultVPNAutoBlock(cfg) {
		t.Fatal("förväntade changed=true på en config utan VPN-auto-block")
	}
	var obj *config.Object
	for i := range cfg.Objects {
		if cfg.Objects[i].ID == vpnAutoBlockObjectID {
			obj = &cfg.Objects[i]
		}
	}
	if obj == nil {
		t.Fatal("objektet obj-vpn-autoblock skapades inte")
	}
	var pol *config.Policy
	for i := range cfg.Policies {
		if cfg.Policies[i].ID == vpnAutoBlockPolicyID {
			pol = &cfg.Policies[i]
		}
	}
	if pol == nil || !pol.Enabled {
		t.Fatalf("deny-policyn ska finnas och vara PÅSLAGEN: %+v", pol)
	}
	if pol.SourceObj != vpnAutoBlockObjectID {
		t.Errorf("policyn ska peka på objektet, fick %q", pol.SourceObj)
	}
	// Idempotent
	if ensureDefaultVPNAutoBlock(cfg) {
		t.Error("andra körningen ska inte ändra något")
	}
}
