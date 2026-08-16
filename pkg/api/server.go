package api

import (
	"bufio"
	"context"
	"encoding/json"

	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/network"
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
	mux.HandleFunc("/api/v1/diagnostics/ping", s.authMiddleware(s.handlePing))
	mux.HandleFunc("/api/v1/diagnostics/traceroute", s.authMiddleware(s.handleTraceroute))

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

func (s *Server) handleGetRunningConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.engine.GetRunningConfig()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cfg)
}

func (s *Server) handleCandidateConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.engine.GetCandidateConfig()
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

func parseConntrack() []config.ConntrackEntry {
	file, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		file, err = os.Open("/proc/net/ip_conntrack")
		if err != nil {
			return []config.ConntrackEntry{}
		}
	}
	defer file.Close()

	var entries []config.ConntrackEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
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
