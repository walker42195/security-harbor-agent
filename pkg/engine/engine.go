package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/dhcp"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/nftables"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/openvpn"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/wireguard"
	"github.com/walker42195/security-harbor-agent/pkg/config"
	"github.com/walker42195/security-harbor-agent/pkg/pki"
	"github.com/walker42195/security-harbor-agent/pkg/store"
)

type State string

const (
	StateIdle        State = "idle"
	StateUnconfirmed State = "unconfirmed"
)

type Engine struct {
	mu             sync.Mutex
	store          *store.Store
	nftAdapter     *nftables.Adapter
	dhcpAdapter    *dhcp.Adapter
	wgAdapter      *wireguard.Adapter
	ovpnAdapter    *openvpn.Adapter
	state          State
	confirmTimer   *time.Timer
	unconfirmedCfg *config.Config
}

func NewEngine(st *store.Store, nftAdapter *nftables.Adapter, dhcpAdapter *dhcp.Adapter, wgAdapter *wireguard.Adapter, ovpnAdapter *openvpn.Adapter) *Engine {
	return &Engine{
		store:       st,
		nftAdapter:  nftAdapter,
		dhcpAdapter: dhcpAdapter,
		wgAdapter:   wgAdapter,
		ovpnAdapter: ovpnAdapter,
		state:       StateIdle,
	}
}

// applyBackends applicerar samtliga systembackends (nftables, Kea DHCP,
// WireGuard) för en given konfiguration. Delas mellan ApplyCandidate och
// rollback så att en rollback verkligen återställer DHCP/VPN, inte bara
// brandväggsreglerna.
func (e *Engine) applyBackends(ctx context.Context, cfg *config.Config, dryRun bool) error {
	if _, err := e.nftAdapter.ApplyConfig(ctx, cfg, dryRun); err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	if err := e.dhcpAdapter.ApplyConfig(ctx, cfg, dryRun); err != nil {
		return fmt.Errorf("dhcp: %w", err)
	}
	if cfg.WireGuard != nil && cfg.WireGuard.Enabled {
		privKey, _, err := e.store.EnsureWireGuardServerKeys()
		if err != nil {
			return fmt.Errorf("wireguard: kunde inte hämta serverns nyckelpar: %w", err)
		}
		if err := e.wgAdapter.ApplyConfig(ctx, cfg, privKey, dryRun); err != nil {
			return fmt.Errorf("wireguard: %w", err)
		}
	} else if err := e.wgAdapter.ApplyConfig(ctx, cfg, "", dryRun); err != nil {
		return fmt.Errorf("wireguard: %w", err)
	}

	if cfg.OpenVPN != nil && cfg.OpenVPN.Enabled {
		ca, err := e.store.EnsureOpenVPNCA()
		if err != nil {
			return fmt.Errorf("openvpn: kunde inte hämta CA: %w", err)
		}
		serverCert, err := e.store.EnsureOpenVPNServerCert()
		if err != nil {
			return fmt.Errorf("openvpn: kunde inte hämta servercertifikat: %w", err)
		}

		var revoked []string
		for _, c := range cfg.OpenVPN.Clients {
			if c.Revoked && c.CertSerial != "" {
				revoked = append(revoked, c.CertSerial)
			}
		}
		crl, err := pki.GenerateCRL(ca.CertPEM, ca.KeyPEM, revoked)
		if err != nil {
			return fmt.Errorf("openvpn: kunde inte generera CRL: %w", err)
		}

		if err := e.ovpnAdapter.ApplyConfig(ctx, cfg, ca.CertPEM, serverCert.CertPEM, serverCert.KeyPEM, crl, dryRun); err != nil {
			return fmt.Errorf("openvpn: %w", err)
		}
	} else if err := e.ovpnAdapter.ApplyConfig(ctx, cfg, "", "", "", "", dryRun); err != nil {
		return fmt.Errorf("openvpn: %w", err)
	}

	return nil
}

// ApplyRunningConfigAtBoot laddar den senast committade konfigurationen i
// samtliga backends vid agentstart (kallas från main.go innan API-servern
// startar). Går inte via Safe Apply/rollback-timern — det är bara att
// återskapa det tillstånd som redan var bekräftat innan omstarten.
func (e *Engine) ApplyRunningConfigAtBoot(ctx context.Context) error {
	return e.applyBackends(ctx, e.store.GetRunningConfig(), false)
}

func (e *Engine) GetRunningConfig() *config.Config {
	return e.store.GetRunningConfig()
}

func (e *Engine) GetCandidateConfig() *config.Config {
	return e.store.GetCandidateConfig()
}

func (e *Engine) UpdateCandidate(cfg *config.Config) error {
	return e.store.SetCandidateConfig(cfg)
}

// ValidateCandidate validerar en candidate-konfiguration utan att ändra systemet.
func (e *Engine) ValidateCandidate(ctx context.Context, cfg *config.Config) error {
	// 1. Kör dry-run validering av samtliga backends
	if err := e.applyBackends(ctx, cfg, true); err != nil {
		return fmt.Errorf("validering misslyckades: %w", err)
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

	// Applicera skarpt mot Linux-kärnan (nftables, Kea DHCP, WireGuard)
	if err := e.applyBackends(ctx, candidate, false); err != nil {
		return fmt.Errorf("misslyckades applicera konfiguration: %w", err)
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
		return fmt.Errorf("ingen obekräftad konfiguration att bekräfta")
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
	if err := e.applyBackends(ctx, running, false); err != nil {
		fmt.Printf("[SAFE APPLY] fel vid återställning till running config: %v\n", err)
	}

	e.state = StateIdle
	_ = e.store.SetCandidateConfig(running)
	e.unconfirmedCfg = nil

	_ = e.store.LogAudit(user, "ROLLBACK_CONFIG", "Konfiguration återställd till senast kända säkra running config")
	return nil
}

// GetWireGuardServerPublicKey returnerar (och vid behov genererar) brandväggens
// egna WireGuard-publika nyckel. Den privata nyckeln lämnar aldrig denna funktion.
func (e *Engine) GetWireGuardServerPublicKey() (string, error) {
	_, pub, err := e.store.EnsureWireGuardServerKeys()
	return pub, err
}

// GetOpenVPNCACertPEM returnerar (och vid behov genererar) brandväggens
// OpenVPN-CA-certifikat i publik PEM-form. CA-nyckeln lämnar aldrig denna
// funktion.
func (e *Engine) GetOpenVPNCACertPEM() (string, error) {
	ca, err := e.store.EnsureOpenVPNCA()
	if err != nil {
		return "", err
	}
	return ca.CertPEM, nil
}

// IssueOpenVPNClient signerar ett nytt klientcertifikat med brandväggens CA.
// Klientens privata nyckel returneras EN gång och sparas aldrig av agenten —
// anroparen (API-lagret) ansvarar för att bara spara certPEM/serial i
// candidate-konfigurationen.
func (e *Engine) IssueOpenVPNClient(commonName string) (clientCertPEM, clientKeyPEM, serial string, err error) {
	ca, err := e.store.EnsureOpenVPNCA()
	if err != nil {
		return "", "", "", fmt.Errorf("openvpn: kunde inte hämta CA: %w", err)
	}
	kp, err := pki.IssueCert(ca.CertPEM, ca.KeyPEM, commonName, false)
	if err != nil {
		return "", "", "", err
	}
	return kp.CertPEM, kp.KeyPEM, kp.Serial, nil
}

func (e *Engine) GetState() State {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state
}
