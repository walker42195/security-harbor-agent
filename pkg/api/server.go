package api

import (
	"bufio"
	"context"
	"encoding/json"

	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/network"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/openvpn"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/wireguard"
	"github.com/walker42195/security-harbor-agent/pkg/config"
	"github.com/walker42195/security-harbor-agent/pkg/engine"
)

type Server struct {
	bindAddr string
	engine   *engine.Engine
	auth     *AuthManager
	srv      *http.Server
	netAdapt *network.Adapter
}

func NewServer(bindAddr string, eng *engine.Engine, auth *AuthManager) *Server {
	return &Server{
		bindAddr: bindAddr,
		engine:   eng,
		auth:     auth,
		netAdapt: network.NewAdapter(),
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Öppna endpoints
	mux.HandleFunc("/api/v1/auth/login", s.handleLogin)

	// Skyddade endpoints
	mux.HandleFunc("/api/v1/system", s.authMiddleware(s.handleSystemStatus))
	mux.HandleFunc("/api/v1/interfaces/discover", s.authMiddleware(s.handleDiscoverInterfaces))
	mux.HandleFunc("/api/v1/diagnostics/conntrack", s.authMiddleware(s.handleConntrack))
	mux.HandleFunc("/api/v1/diagnostics/firewall-log", s.authMiddleware(s.handleFirewallLog))
	mux.HandleFunc("/api/v1/diagnostics/ping", s.authMiddleware(s.handlePing))
	mux.HandleFunc("/api/v1/diagnostics/traceroute", s.authMiddleware(s.handleTraceroute))
	mux.HandleFunc("/api/v1/diagnostics/bandwidth", s.authMiddleware(s.handleBandwidthStats))
	mux.HandleFunc("/api/v1/vpn/wireguard/server-info", s.authMiddleware(s.handleWireGuardServerInfo))
	mux.HandleFunc("/api/v1/vpn/wireguard/generate-peer-keys", s.authMiddleware(s.handleWireGuardGeneratePeerKeys))
	mux.HandleFunc("/api/v1/vpn/openvpn/ca-info", s.authMiddleware(s.handleOpenVPNCAInfo))
	mux.HandleFunc("/api/v1/vpn/openvpn/generate-client", s.authMiddleware(s.handleOpenVPNGenerateClient))

	mux.HandleFunc("/api/v1/config/running", s.authMiddleware(s.handleGetRunningConfig))
	mux.HandleFunc("/api/v1/config/candidate", s.authMiddleware(s.handleCandidateConfig))
	mux.HandleFunc("/api/v1/config/apply", s.authMiddleware(s.handleApplyConfig))
	mux.HandleFunc("/api/v1/config/confirm", s.authMiddleware(s.handleConfirmConfig))
	mux.HandleFunc("/api/v1/config/rollback", s.authMiddleware(s.handleRollbackConfig))

	handler := s.wanBlockMiddleware(mux)

	s.srv = &http.Server{
		Addr:         s.bindAddr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	return s.srv.ListenAndServe()
}

func (s *Server) Stop(ctx context.Context) error {
	if s.srv != nil {
		return s.srv.Shutdown(ctx)
	}
	return nil
}

func (s *Server) wanBlockMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := strings.Split(r.RemoteAddr, ":")[0]
		if strings.HasPrefix(clientIP, "10.13.13.") {
			http.Error(w, "Forbidden: Management API disabled on WAN interface", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if _, err := s.auth.ValidateToken(token); err != nil {
			http.Error(w, "Unauthorized or expired token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	if s.auth.IsLockedOut(clientIP) {
		http.Error(w, "IP spärrad p.g.a. för många misslyckade försök", http.StatusTooManyRequests)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if creds.Username == "admin" && creds.Password == "SecurityHarbor2026!" {
		token, err := s.auth.CreateSession(creds.Username, 24*time.Hour)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": token, "user": creds.Username})
		return
	}

	s.auth.RecordFailedAttempt(clientIP)
	http.Error(w, "Felaktigt användarnamn eller lösenord", http.StatusUnauthorized)
}

func (s *Server) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	st := string(s.engine.GetState())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"hostname": "security-harbor", "state": st, "version": "0.2.0-fas2"})
}

func (s *Server) handleDiscoverInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := s.netAdapt.DiscoverInterfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ifaces)
}

func (s *Server) handleConntrack(w http.ResponseWriter, r *http.Request) {
	entries := parseConntrack()
	arp := parseARPTable()
	for i := range entries {
		if mac, ok := arp[entries[i].SrcIP]; ok {
			entries[i].SrcMAC = mac
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}

func (s *Server) handleFirewallLog(w http.ResponseWriter, r *http.Request) {
	entries := parseFirewallLog()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Host == "" {
		http.Error(w, "Host saknas", http.StatusBadRequest)
		return
	}
	out, _ := exec.Command("ping", "-c", "4", "-W", "2", req.Host).CombinedOutput()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"output": string(out)})
}

func (s *Server) handleTraceroute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Host == "" {
		http.Error(w, "Host saknas", http.StatusBadRequest)
		return
	}
	out, _ := exec.Command("traceroute", "-n", "-w", "1", "-m", "15", req.Host).CombinedOutput()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"output": string(out)})
}

// handleWireGuardServerInfo returnerar brandväggens publika WireGuard-nyckel
// (aldrig den privata) samt lyssningsport/endpoint från körande config, så
// att GUI:t kan bygga färdiga klientkonfigurationer/QR-koder.
func (s *Server) handleWireGuardServerInfo(w http.ResponseWriter, r *http.Request) {
	pubKey, err := s.engine.GetWireGuardServerPublicKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	listenPort := 0
	endpoint := ""
	if cfg := s.engine.GetRunningConfig(); cfg != nil && cfg.WireGuard != nil {
		listenPort = cfg.WireGuard.ListenPort
		endpoint = cfg.WireGuard.Endpoint
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"public_key":  pubKey,
		"listen_port": listenPort,
		"endpoint":    endpoint,
	})
}

// handleWireGuardGeneratePeerKeys genererar ett engångsnyckelpar åt en ny
// VPN-klient. Den privata nyckeln returneras EN gång till den inloggade
// admin-klienten och sparas aldrig på brandväggen — bara den publika nyckeln
// hör hemma i den sparade Policy/Peer-konfigurationen.
func (s *Server) handleWireGuardGeneratePeerKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	priv, pub, err := wireguard.GenerateKeypair()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"private_key": priv, "public_key": pub})
}

// handleOpenVPNCAInfo returnerar brandväggens publika OpenVPN-CA-certifikat
// (aldrig CA-nyckeln), så att GUI:t kan visa/verifiera det utan att behöva
// generera en klient först.
func (s *Server) handleOpenVPNCAInfo(w http.ResponseWriter, r *http.Request) {
	caCertPEM, err := s.engine.GetOpenVPNCACertPEM()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"ca_cert_pem": caCertPEM})
}

// handleOpenVPNGenerateClient signerar ett nytt klientcertifikat med
// brandväggens CA och returnerar en färdig, självständig .ovpn-fil. Klientens
// privata nyckel returneras EN gång till den inloggade admin-klienten och
// sparas aldrig på brandväggen — GUI:t ansvarar för att spara cert_pem/serial
// (inte private_key) i candidate-konfigurationens OpenVPN.Clients-lista.
func (s *Server) handleOpenVPNGenerateClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "Namn saknas", http.StatusBadRequest)
		return
	}

	certPEM, keyPEM, serial, err := s.engine.IssueOpenVPNClient(req.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cfg := s.engine.GetCandidateConfig()
	if cfg == nil {
		cfg = s.engine.GetRunningConfig()
	}
	if cfg == nil || cfg.OpenVPN == nil {
		http.Error(w, "OpenVPN är inte konfigurerat", http.StatusBadRequest)
		return
	}
	caCertPEM, err := s.engine.GetOpenVPNCACertPEM()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfgCopy := *cfg
	ovpnCopy := *cfg.OpenVPN
	ovpnCopy.CACertPEM = caCertPEM
	cfgCopy.OpenVPN = &ovpnCopy

	ovpnFile, err := openvpn.GenerateClientConfig(&cfgCopy, certPEM, keyPEM)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"cert_pem":    certPEM,
		"serial":      serial,
		"ovpn_config": ovpnFile,
	})
}

func (s *Server) handleGetRunningConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.engine.GetRunningConfig()
	if cfg != nil {
		cfgCopy := *cfg
		s.netAdapt.PopulateDynamicIPs(&cfgCopy)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&cfgCopy)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cfg)
}

func (s *Server) handleCandidateConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.engine.GetCandidateConfig()
		if cfg != nil {
			cfgCopy := *cfg
			s.netAdapt.PopulateDynamicIPs(&cfgCopy)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(&cfgCopy)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	case http.MethodPost, http.MethodPut:
		var newCfg config.Config
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		if err := s.engine.UpdateCandidate(&newCfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "revision": newCfg.Revision})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleApplyConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.engine.ApplyCandidate(r.Context(), "admin"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) handleConfirmConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.engine.ConfirmConfig(r.Context(), "admin"); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) handleRollbackConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.engine.RollbackConfig(r.Context(), "admin"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// parseConntrack läser aktiva anslutningar via `conntrack -L`. Moderna
// kernlar (upptäckt 2026-08-17 mot 10.0.0.163) exponerar inte längre
// /proc/net/nf_conntrack eller /proc/net/ip_conntrack som procfs-filer —
// conntrack-tabellen nås numera bara via netlink, vilket `conntrack`-
// verktyget (paketet heter bara "conntrack", inte "conntrack-tools") pratar.
// Kräver CAP_NET_ADMIN, som agentens systemd-enhet redan ger den (samma
// mönster som nft/wg/ip).
func parseConntrack() []config.ConntrackEntry {
	out, err := exec.Command("conntrack", "-L").CombinedOutput()
	if err != nil && len(out) == 0 {
		return []config.ConntrackEntry{}
	}

	var entries []config.ConntrackEntry
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "conntrack v") {
			continue // sammanfattningsrad, t.ex. "conntrack v1.4.9 (...): N flow entries have been shown."
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		proto := fields[0]
		entry := config.ConntrackEntry{Protocol: proto}

		for _, f := range fields {
			if strings.HasPrefix(f, "src=") && entry.SrcIP == "" {
				entry.SrcIP = strings.TrimPrefix(f, "src=")
			} else if strings.HasPrefix(f, "dst=") && entry.DstIP == "" {
				entry.DstIP = strings.TrimPrefix(f, "dst=")
			} else if strings.HasPrefix(f, "sport=") && entry.SrcPort == 0 {
				p, _ := strconv.Atoi(strings.TrimPrefix(f, "sport="))
				entry.SrcPort = p
			} else if strings.HasPrefix(f, "dport=") && entry.DstPort == 0 {
				p, _ := strconv.Atoi(strings.TrimPrefix(f, "dport="))
				entry.DstPort = p
			} else if f == "ESTABLISHED" || f == "TIME_WAIT" || f == "SYN_SENT" || f == "CLOSE" {
				entry.State = f
			}
		}

		if entry.SrcIP != "" {
			entries = append(entries, entry)
		}
	}

	return entries
}

// parseARPTable läser /proc/net/arp och returnerar en karta IP -> MAC-adress
// för enheter på de lokala (LAN/VLAN) näten. Används för att berika
// conntrack-listan med MAC-adresser, som inte finns i /proc/net/nf_conntrack.
func parseARPTable() map[string]string {
	result := make(map[string]string)
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return result
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	first := true
	for scanner.Scan() {
		if first {
			first = false // hoppa över kolumnrubriker
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		ip := fields[0]
		mac := fields[3]
		if mac != "" && mac != "00:00:00:00:00:00" {
			result[ip] = mac
		}
	}
	return result
}

// firewallLogLineRe matchar kernelns netfilter-loggformat, t.ex.:
// "...kernel: SH-DENY-INPUT: IN=ens18 OUT= MAC=... SRC=1.2.3.4 DST=10.0.0.163 ... PROTO=TCP SPT=51820 DPT=8443 ..."
var firewallLogFieldRe = regexp.MustCompile(`(\w+)=([^\s]*)`)

// parseFirewallLog läser de senaste blockerade paketen ur journalens
// kärnlogg (nftables "log"-uttryck, se SH-DENY-*-prefixen i
// pkg/adapter/nftables/adapter.go) och returnerar dem strukturerat.
func parseFirewallLog() []config.FirewallLogEntry {
	out, err := exec.Command("journalctl", "-k", "-n", "500", "--no-pager", "-o", "short-iso", "-g", "SH-DENY-").CombinedOutput()
	if err != nil && len(out) == 0 {
		return []config.FirewallLogEntry{}
	}

	var entries []config.FirewallLogEntry
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		var chain string
		switch {
		case strings.Contains(line, "SH-DENY-INPUT:"):
			chain = "INPUT"
		case strings.Contains(line, "SH-DENY-FWD:"):
			chain = "FWD"
		default:
			continue
		}

		entry := config.FirewallLogEntry{Chain: chain}
		// Tidsstämpeln är de första tre fälten i "short-iso"-format (t.ex. "2026-08-17T10:15:00+0200 host kernel:").
		tsFields := strings.Fields(line)
		if len(tsFields) > 0 {
			entry.Timestamp = tsFields[0]
		}

		for _, m := range firewallLogFieldRe.FindAllStringSubmatch(line, -1) {
			key, val := m[1], m[2]
			switch key {
			case "IN":
				entry.InIface = val
			case "OUT":
				entry.OutIface = val
			case "MAC":
				// nftables loggar käll- och destinations-MAC hopslaget; de sex
				// första oktetten hör till destinationen och nästa sex till
				// källan för mottagen trafik. Vi tar de sista sex byten som en
				// rimlig approximation av avsändarens MAC.
				parts := strings.Split(val, ":")
				if len(parts) >= 12 {
					entry.SrcMAC = strings.Join(parts[6:12], ":")
				}
			case "SRC":
				entry.SrcIP = val
			case "DST":
				entry.DstIP = val
			case "PROTO":
				entry.Protocol = val
			case "SPT":
				p, _ := strconv.Atoi(val)
				entry.SrcPort = p
			case "DPT":
				p, _ := strconv.Atoi(val)
				entry.DstPort = p
			}
		}

		if entry.SrcIP != "" {
			entries = append(entries, entry)
		}
	}
	return entries
}

type NetDevStat struct {
	Device  string `json:"device"`
	RxBytes int64  `json:"rx_bytes"`
	TxBytes int64  `json:"tx_bytes"`
}

func (s *Server) handleBandwidthStats(w http.ResponseWriter, r *http.Request) {
	stats := parseProcNetDev()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

func parseProcNetDev() []NetDevStat {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return []NetDevStat{}
	}
	defer file.Close()

	var stats []NetDevStat
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		devName := strings.TrimSpace(parts[0])
		if devName == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) >= 9 {
			rx, _ := strconv.ParseInt(fields[0], 10, 64)
			tx, _ := strconv.ParseInt(fields[8], 10, 64)
			stats = append(stats, NetDevStat{
				Device:  devName,
				RxBytes: rx,
				TxBytes: tx,
			})
		}
	}
	return stats
}
