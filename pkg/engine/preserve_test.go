package engine

import (
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// En klient som PUT:ar ett objekt med tomma status-fält ska INTE kunna
// radera de agent-ägda LastUpdated/LastError/EntryCount — de återställs
// från serverns kända config. RefreshHours (klient-ägd) ska däremot behållas
// som klienten skickade.
func TestPreserveObjectSourceStatus(t *testing.T) {
	prev := &config.Config{Objects: []config.Object{
		{ID: "o1", Source: &config.ObjectSource{Kind: "spamhaus_drop", RefreshHours: 24, LastUpdated: "2026-08-20T10:00:00Z", EntryCount: 1699}},
	}}
	incoming := &config.Config{Objects: []config.Object{
		{ID: "o1", Source: &config.ObjectSource{Kind: "spamhaus_drop", RefreshHours: 12, LastUpdated: "", EntryCount: 0}},
	}}

	preserveObjectSourceStatus(incoming, prev)

	s := incoming.Objects[0].Source
	if s.LastUpdated != "2026-08-20T10:00:00Z" {
		t.Errorf("LastUpdated skulle bevarats från servern, fick %q", s.LastUpdated)
	}
	if s.EntryCount != 1699 {
		t.Errorf("EntryCount skulle bevarats, fick %d", s.EntryCount)
	}
	if s.RefreshHours != 12 {
		t.Errorf("RefreshHours är klient-ägd och skulle vara 12, fick %d", s.RefreshHours)
	}
}
