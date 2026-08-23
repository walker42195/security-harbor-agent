package engine

import (
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func TestValidateUniqueNamesDetectsDuplicateObjects(t *testing.T) {
	cfg := &config.Config{
		Objects: []config.Object{
			{ID: "a", Name: "IPS - Auto block"},
			{ID: "b", Name: "ips - auto block"}, // dubblett (skiftlägesokänsligt + trim)
		},
	}
	wantErr(t, validateUniqueNames(cfg), "två objekt har samma namn")
}

func TestValidateUniqueNamesDetectsDuplicateZones(t *testing.T) {
	cfg := &config.Config{
		Zones: []config.Zone{
			{Name: "LAN"},
			{Name: " LAN "},
		},
	}
	wantErr(t, validateUniqueNames(cfg), "två zoner har samma namn")
}

func TestValidateUniqueNamesAllowsObjectAndZoneSharingName(t *testing.T) {
	cfg := &config.Config{
		Objects: []config.Object{{ID: "a", Name: "Kontor"}},
		Zones:   []config.Zone{{Name: "Kontor"}},
	}
	if err := validateUniqueNames(cfg); err != nil {
		t.Fatalf("objekt och zon får dela namn, men fick fel: %v", err)
	}
}

func TestValidateUniqueNamesIgnoresEmptyNames(t *testing.T) {
	cfg := &config.Config{
		Objects: []config.Object{{ID: "a", Name: ""}, {ID: "b", Name: ""}},
	}
	if err := validateUniqueNames(cfg); err != nil {
		t.Fatalf("tomma namn ska inte räknas som dubbletter, fick: %v", err)
	}
}
