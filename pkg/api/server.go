package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/config"
	"github.com/walker42195/security-harbor-agent/pkg/engine"
	"github.com/walker42195/security-harbor-agent/pkg/store"
)

type Server struct {
	store    *store.Store
	engine   *engine.Engine
	auth     *AuthManager
	srv      *http.Server
	bindAddr string
}

func NewServer(bindAddr string, st *store.Store, eng *engine.Engine) *Server {
	s := &Server{
		store:    st,
		engine:   eng,
		auth:     NewAuthManager(),
		bindAddr: bindAddr,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("GET /api/v1/system", s.authMiddleware(s.handleSystem))
	mux.HandleFunc("GET /api/v1/config/running", s.authMiddleware(s.handleGetRunning))
	mux.HandleFunc("GET /api/v1/config/candidate", s.authMiddleware(s.handleGetCandidate))
	mux.HandleFunc("POST /api/v1/config/candidate", s.authMiddleware(s.handleSetCandidate))
	mux.HandleFunc("POST /api/v1/config/apply", s.authMiddleware(s.handleApply))
	mux.HandleFunc("POST /api/v1/config/confirm", s.authMiddleware(s.handleConfirm))
	mux.HandleFunc("POST /api/v1/config/rollback", s.authMiddleware(s.handleRollback))

	s.srv = &http.Server{
		Addr:         bindAddr,
		Handler:      s.wanBlockMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return s
}

func (s *Server) Start() error {
	fmt.Printf("[API SERVER] Startar Management API på %s\n", s.bindAddr)
	return s.srv.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// wanBlockMiddleware verifierar att anslutningen inte kommer från WAN-gränssnittet (Hård WAN-spärr).
func (s *Server) wanBlockMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}

		ip := net.ParseIP(host)
		if ip != nil {
			// Kontrollera om anslutnings-IP ligger på WAN-subnätet
			running := s.store.GetRunningConfig()
			for _, iface := range running.Interfaces {
				if iface.Zone == "WAN" && iface.IPv4 != "" {
					_, wanSubnet, err := net.ParseCIDR(iface.IPv4)
					if err == nil && wanSubnet.Contains(ip) && !ip.IsLoopback() {
						http.Error(w, "Access Denied: WAN Management Access Forbidden", http.StatusForbidden)
						return
					}
				}
			}
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
		user, err := s.auth.ValidateToken(token)
		if err != nil {
			http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if s.auth.IsLockedOut(host) {
		http.Error(w, "Too many failed attempts, IP locked out", http.StatusTooManyRequests)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Standard admin konto i dev/test
	if req.Username == "admin" && req.Password == "SecurityHarbor2026!" {
		token, err := s.auth.CreateSession("admin", 2*time.Hour)
		if err != nil {
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"token": token,
			"user":  "admin",
		})
		return
	}

	s.auth.RecordFailedAttempt(host)
	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	running := s.store.GetRunningConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"hostname": running.Settings.HostName,
		"version":  "0.1.0-fas0",
		"state":    s.engine.GetState(),
		"revision": running.Revision,
	})
}

func (s *Server) handleGetRunning(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.store.GetRunningConfig())
}

func (s *Server) handleGetCandidate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.store.GetCandidateConfig())
}

func (s *Server) handleSetCandidate(w http.ResponseWriter, r *http.Request) {
	var cfg config.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.engine.ValidateCandidate(r.Context(), &cfg); err != nil {
		http.Error(w, "Validation Error: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.store.SetCandidateConfig(&cfg); err != nil {
		http.Error(w, "Store Error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "candidate_updated"})
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(string)
	if err := s.engine.ApplyCandidate(r.Context(), user); err != nil {
		http.Error(w, "Apply Error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "applied_unconfirmed",
		"message": "Konfiguration applicerad. Vänligen bekräfta (confirm) inom 30 sekunder annars sker automatiskt rollback.",
	})
}

func (s *Server) handleConfirm(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(string)
	if err := s.engine.ConfirmConfig(r.Context(), user); err != nil {
		http.Error(w, "Confirm Error: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "confirmed_and_committed"})
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(string)
	if err := s.engine.RollbackConfig(r.Context(), user); err != nil {
		http.Error(w, "Rollback Error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "rolled_back"})
}
