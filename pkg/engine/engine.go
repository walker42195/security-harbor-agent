package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/nftables"
	"github.com/walker42195/security-harbor-agent/pkg/config"
	"github.com/walker42195/security-harbor-agent/pkg/store"
)

type State string

const (
	StateIdle       State = "idle"
	StateUnconfirmed State = "unconfirmed"
)

type Engine struct {
	mu           sync.Mutex
	store        *store.Store
	nftAdapter   *nftables.Adapter
	state        State
	confirmTimer *time.Timer
	unconfirmedCfg *config.Config
}

func NewEngine(st *store.Store, adapter *nftables.Adapter) *Engine {
	return &Engine{
		store:      st,
		nftAdapter: adapter,
		state:      StateIdle,
	}
}

// ValidateCandidate validerar en candidate-konfiguration utan att ändra systemet.
func (e *Engine) ValidateCandidate(ctx context.Context, cfg *config.Config) error {
	// 1. Kör nftables dry-run validering
	_, err := e.nftAdapter.ApplyConfig(ctx, cfg, true)
	if err != nil {
		return fmt.Errorf("nftables validering misslyckades: %w", err)
	}

	// 2. Validera IP-överlapp och logiska fel
	if len(cfg.Interfaces) == 0 {
		return fmt.Errorf("konfigurationen måste ha minst ett gränssnitt")
	}

	return nil
}

// ApplyCandidate applicerar candidate-konfigurationen och startar 30-sekunders rollback-timern.
func (e *Engine) ApplyCandidate(ctx context.Context, user string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	candidate := e.store.GetCandidateConfig()

	// Validera först
	if err := e.ValidateCandidate(ctx, candidate); err != nil {
		return fmt.Errorf("kan inte applicera ogiltig konfiguration: %w", err)
	}

	// Applicera skarpt på Linux-kärnan via nftables adapter
	_, err := e.nftAdapter.ApplyConfig(ctx, candidate, false)
	if err != nil {
		return fmt.Errorf("misslyckades applicera konfiguration på nftables: %w", err)
	}

	e.state = StateUnconfirmed
	e.unconfirmedCfg = candidate

	// Om det redan finns en timer igång, stoppa den
	if e.confirmTimer != nil {
		e.confirmTimer.Stop()
	}

	timeout := time.Duration(candidate.Settings.RollbackTimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Starta automatisk rollback timer ifall confirmation uteblir
	e.confirmTimer = time.AfterFunc(timeout, func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.state == StateUnconfirmed {
			fmt.Printf("[SAFE APPLY] ingen confirm mottagen inom %v -> utlöser AUTOMATISK ROLLBACK!\n", timeout)
			e.rollbackLocked(context.Background(), "SYSTEM_ROLLBACK_TIMEOUT")
		}
	})

	_ = e.store.LogAudit(user, "APPLY_CANDIDATE", fmt.Sprintf("Applicerade revision %d, väntar på bekräftelse (timeout %v)", candidate.Revision, timeout))
	return nil
}

// ConfirmConfig bekräftar den nya konfigurationen (avbryter rollback-timern och gör commit).
func (e *Engine) ConfirmConfig(ctx context.Context, user string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.state != StateUnconfirmed {
		return fmt.Errorf("ingen ubekräftad konfiguration att bekräfta")
	}

	if e.confirmTimer != nil {
		e.confirmTimer.Stop()
		e.confirmTimer = nil
	}

	if err := e.store.CommitCandidate(); err != nil {
		return fmt.Errorf("misslyckades göra commit av konfiguration: %w", err)
	}

	e.state = StateIdle
	e.unconfirmedCfg = nil

	_ = e.store.LogAudit(user, "CONFIRM_CONFIG", "Konfiguration bekräftad och committad till running.json")
	return nil
}

// RollbackConfig återställer konfigurationen manuellt eller vid fel.
func (e *Engine) RollbackConfig(ctx context.Context, user string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.rollbackLocked(ctx, user)
}

func (e *Engine) rollbackLocked(ctx context.Context, user string) error {
	if e.confirmTimer != nil {
		e.confirmTimer.Stop()
		e.confirmTimer = nil
	}

	running := e.store.GetRunningConfig()
	_, err := e.nftAdapter.ApplyConfig(ctx, running, false)
	if err != nil {
		fmt.Printf("[SAFE APPLY] fel vid återställning till running config: %v\n", err)
	}

	e.state = StateIdle
	_ = e.store.SetCandidateConfig(running)
	e.unconfirmedCfg = nil

	_ = e.store.LogAudit(user, "ROLLBACK_CONFIG", "Konfiguration återställd till senast kända säkra running config")
	return nil
}

func (e *Engine) GetState() State {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state
}
