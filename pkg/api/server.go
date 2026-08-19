package api

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/network"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/openvpn"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/wireguard"
	"github.com/walker42195/security-harbor-agent/pkg/config"
	"github.com/walker42195/security-harbor-agent/pkg/engine"
	"github.com/walker42195/security-harbor-agent/pkg/pki"
	"github.com/walker42195/security-harbor-agent/pkg/store"
)

type Server struct {
	bindAddr string
	engine   *engine.Engine
	auth     *AuthManager
	srv      *http.Server
	netAdapt *network.Adapter
	tlsCert  *pki.KeyPair
	webUIDir string
}

func NewServer(bindAddr string, eng *engine.Engine, auth *AuthManager, tlsCert *pki.KeyPair, webUIDir string) *Server {
	return &Server{
		bindAddr: bindAddr,
		engine:   eng,
		auth:     auth,
		netAdapt: network.NewAdapter(),
		tlsCert:  tlsCert,
		webUIDir: webUIDir,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Öppna endpoints
	mux.HandleFunc("/api/v1/auth/login", s.handleLogin)

	// Skyddade endpoints — läsande, tillgängliga för både admin och viewer
	// (Fas 8). En "viewer" ska vara strikt skrivskyddad.
	mux.HandleFunc("/api/v1/system", s.authMiddleware(s.handleSystemStatus))
	mux.HandleFunc("/api/v1/interfaces/discover", s.authMiddleware(s.handleDiscoverInterfaces))
	mux.HandleFunc("/api/v1/diagnostics/conntrack", s.authMiddleware(s.handleConntrack))
	mux.HandleFunc("/api/v1/diagnostics/firewall-log", s.authMiddleware(s.handleFirewallLog))
	mux.HandleFunc("/api/v1/diagnostics/bandwidth", s.authMiddleware(s.handleBandwidthStats))
	mux.HandleFunc("/api/v1/diagnostics/security-events", s.authMiddleware(s.handleSecurityEvents))
	mux.HandleFunc("/api/v1/vpn/wireguard/server-info", s.authMiddleware(s.handleWireGuardServerInfo))
	mux.HandleFunc("/api/v1/vpn/openvpn/ca-info", s.authMiddleware(s.handleOpenVPNCAInfo))
	mux.HandleFunc("/api/v1/policies/hit-counts", s.authMiddleware(s.handleHitCounts))
	mux.HandleFunc("/api/v1/dns/blocklist-domains", s.authMiddleware(s.handleGetDNSBlocklistDomains))
	mux.HandleFunc("/api/v1/config/running", s.authMiddleware(s.handleGetRunningConfig))
	mux.HandleFunc("/api/v1/auth/change-password", s.authMiddleware(s.handleChangePassword))

	// Skyddade endpoints — kräver admin-roll: allt som ändrar konfig,
	// exekverar kommandon (ping/traceroute kan användas för intern
	// nätverksrekognosering från brandväggen) eller genererar/roterar
	// hemligheter.
	mux.HandleFunc("/api/v1/diagnostics/ping", s.authMiddlewareAdmin(s.handlePing))
	mux.HandleFunc("/api/v1/diagnostics/traceroute", s.authMiddlewareAdmin(s.handleTraceroute))
	mux.HandleFunc("/api/v1/diagnostics/nmap", s.authMiddlewareAdmin(s.handleNmap))
	mux.HandleFunc("/api/v1/diagnostics/tcpdump", s.authMiddlewareAdmin(s.handleTcpdumpCapture))
	mux.HandleFunc("/api/v1/vpn/wireguard/generate-peer-keys", s.authMiddlewareAdmin(s.handleWireGuardGeneratePeerKeys))
	mux.HandleFunc("/api/v1/vpn/openvpn/generate-client", s.authMiddlewareAdmin(s.handleOpenVPNGenerateClient))
	mux.HandleFunc("/api/v1/objects/refresh-source", s.authMiddlewareAdmin(s.handleRefreshObjectSource))
	mux.HandleFunc("/api/v1/dns/refresh-blocklist", s.authMiddlewareAdmin(s.handleRefreshDNSBlocklist))
	mux.HandleFunc("/api/v1/config/candidate", s.authMiddleware(s.handleCandidateConfig)) // GET=alla, POST/PUT kräver admin internt (se handlern)
	mux.HandleFunc("/api/v1/config/apply", s.authMiddlewareAdmin(s.handleApplyConfig))
	mux.HandleFunc("/api/v1/config/confirm", s.authMiddlewareAdmin(s.handleConfirmConfig))
	mux.HandleFunc("/api/v1/config/rollback", s.authMiddlewareAdmin(s.handleRollbackConfig))

	// Användarhantering (Fas 8) — enbart admin.
	mux.HandleFunc("/api/v1/auth/users", s.authMiddlewareAdmin(s.handleListUsers))
	mux.HandleFunc("/api/v1/auth/users/create", s.authMiddlewareAdmin(s.handleCreateUser))
	mux.HandleFunc("/api/v1/auth/users/delete", s.authMiddlewareAdmin(s.handleDeleteUser))
	mux.HandleFunc("/api/v1/auth/users/reset-password", s.authMiddlewareAdmin(s.handleResetUserPassword))
	mux.HandleFunc("/api/v1/system/backup", s.authMiddlewareAdmin(s.handleBackup))
	mux.HandleFunc("/api/v1/system/restore", s.authMiddlewareAdmin(s.handleRestore))
	mux.HandleFunc("/api/v1/system/factory-reset", s.authMiddlewareAdmin(s.handleFactoryReset))

	// Web-UI (Fas 8+) — statiska filer (flutter build web), t.ex. driftsatta
	// via rsync till --webui-dir. Registreras SIST men ServeMux matchar
	// alltid det mest specifika mönstret oavsett ordning, så /api/v1/*
	// påverkas inte. Om katalogen saknas/är tom svarar "/" bara 404 — bryter
	// inget om web-UI:t inte är driftsatt.
	mux.Handle("/", http.FileServer(http.Dir(s.webUIDir)))

	// wanBlockMiddleware och securityHeadersMiddleware omsluter HELA
	// mux:en, så web-UI:t skyddas/får samma huvuden som Management-API:t.
	handler := s.wanBlockMiddleware(securityHeadersMiddleware(mux))

	s.srv = &http.Server{
		Addr:         s.bindAddr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		// IdleTimeout skyddar mot slow-loris-liknande resursutmattning via
		// keep-alive-anslutningar som annars inte fångas av Read/WriteTimeout
		// (de gäller bara EN aktiv request, inte tomgångstid mellan dem).
		IdleTimeout: 60 * time.Second,
		// MaxHeaderBytes: uttryckligt satt betydligt snävare än Go:s
		// 1 MB-default — det här är ett internt JSON-API, inga rimliga
		// headers närmar sig ens en bråkdel av 64 KB.
		MaxHeaderBytes: 1 << 16,
	}

	if s.tlsCert != nil {
		cert, err := tls.X509KeyPair([]byte(s.tlsCert.CertPEM), []byte(s.tlsCert.KeyPEM))
		if err != nil {
			return fmt.Errorf("misslyckades tolka TLS-certifikat: %w", err)
		}
		s.srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		// Tomma sökvägar = använd TLSConfig.Certificates istället för att
		// läsa cert/nyckel från disk igen (de finns redan bara i minnet,
		// dekrypterade av Store).
		return s.srv.ListenAndServeTLS("", "")
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

// securityHeadersMiddleware sätter grundläggande säkerhetshuvuden på VARJE
// svar (Fas 12) — även på den statiska web-UI-filservern, inte bara
// /api/v1/*. HSTS är rimligt eftersom TLS redan är obligatoriskt för hela
// Management-API:t (se tlsCert-hanteringen i Start()). CSP hålls medvetet
// enkel (default-src 'self') eftersom Flutter Web-bygget är helt
// self-contained utan externa resurser (typsnitt/skript/bilder bakas in i
// bygget, se artifact-liknande CSP-resonemang i webUI-driftsättningen).
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'self'")
		next.ServeHTTP(w, r)
	})
}

type ctxKey string

const (
	ctxKeyUsername ctxKey = "sh_username"
	ctxKeyRole     ctxKey = "sh_role"
)

// authMiddleware kräver en giltig session, oavsett roll (admin ELLER
// viewer). Lägger in användarnamn/roll i request-context så handlers kan
// läsa vem som anropar (se ctxKeyUsername/ctxKeyRole).
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		username, role, err := s.auth.ValidateToken(token)
		if err != nil {
			http.Error(w, "Unauthorized or expired token", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyUsername, username)
		ctx = context.WithValue(ctx, ctxKeyRole, role)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// authMiddlewareAdmin kräver en giltig session MED admin-roll (Fas 8 —
// flera användare/roller). En "viewer" får 403 Forbidden. Används för
// alla endpoints som ändrar något (config apply/confirm/rollback,
// nyckelgenerering, uppdatera hot-listor/blocklistor, användarhantering
// m.m.) — en viewer ska vara strikt läsande.
func (s *Server) authMiddlewareAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if role, _ := r.Context().Value(ctxKeyRole).(string); role != string(store.RoleAdmin) {
			http.Error(w, "Forbidden: kräver admin-roll", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	clientIP := strings.Split(r.RemoteAddr, ":")[0]

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Spärren kollas för BÅDE käll-IP och användarnamn (Fas 12) — annars
	// kan en angripare kringgå en ren IP-spärr genom att rotera käll-IP
	// mot samma användarnamn.
	if s.auth.IsLockedOut(clientIP, creds.Username) {
		http.Error(w, "Spärrad p.g.a. för många misslyckade försök", http.StatusTooManyRequests)
		return
	}

	user, err := s.engine.VerifyUserCredentials(creds.Username, creds.Password)
	if err == nil {
		token, tokenErr := s.auth.CreateSession(user.Username, string(user.Role), 24*time.Hour)
		if tokenErr != nil {
			http.Error(w, tokenErr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": token, "user": user.Username, "role": string(user.Role)})
		return
	}

	s.auth.RecordFailedAttempt(clientIP, creds.Username)
	http.Error(w, "Felaktigt användarnamn eller lösenord", http.StatusUnauthorized)
}

// handleChangePassword byter LOSENORDET FÖR DEN INLOGGADE ANVÄNDAREN
// SJÄLV — kräver att nuvarande lösenord anges (se Engine.ChangeOwnPassword).
// Tillgänglig för alla roller (både admin och viewer får byta sitt eget
// lösenord).
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	username, _ := r.Context().Value(ctxKeyUsername).(string)
	user, err := s.engine.FindUserByUsername(username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.engine.ChangeOwnPassword(user.ID, req.CurrentPassword, req.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// handleListUsers/handleCreateUser/handleDeleteUser: admin-only
// användarhantering (Fas 8).
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.engine.ListUsers())
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	user, err := s.engine.CreateUser(req.Username, req.Password, store.Role(req.Role))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(user)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "id saknas", http.StatusBadRequest)
		return
	}
	if err := s.engine.DeleteUser(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// handleResetUserPassword: admin sätter ett nytt lösenord för en ANNAN
// användare, utan att behöva känna till dennes nuvarande lösenord.
func (s *Server) handleResetUserPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID          string `json:"id"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "id saknas", http.StatusBadRequest)
		return
	}
	if err := s.engine.AdminResetPassword(req.ID, req.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// handleBackup skapar en lösenfras-krypterad backup av persistenslagret
// (Fas 10, se Engine.Backup/pkg/store/backup.go) och returnerar den som
// base64 i JSON — konsekvent med resten av API:t, ingen ny content-type.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Passphrase == "" {
		http.Error(w, "Lösenfras saknas", http.StatusBadRequest)
		return
	}
	data, err := s.engine.Backup(req.Passphrase)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"backup_b64": base64.StdEncoding.EncodeToString(data)})
}

// handleRestore skriver tillbaka en backup och startar om agenten rent
// (systemd Restart=always tar hand om omstarten, se
// systemd/security-harbor-agent.service) istället för att försöka
// hot-swappa engine-tillståndet i en levande process.
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Passphrase string `json:"passphrase"`
		BackupB64  string `json:"backup_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Passphrase == "" || req.BackupB64 == "" {
		http.Error(w, "Lösenfras eller backup-data saknas", http.StatusBadRequest)
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.BackupB64)
	if err != nil {
		http.Error(w, "Ogiltig base64-data", http.StatusBadRequest)
		return
	}
	if err := s.engine.Restore(data, req.Passphrase); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	restartSelfAfterResponse(w)
}

// handleFactoryReset kräver att den INLOGGADE admin-användarens nuvarande
// lösenord skickas med som extra bekräftelse-spärr (samma
// VerifyUserCredentials-väg som login) innan ALL config/nyckeldata
// (utom audit.log) tas bort — se Engine.FactoryReset.
func (s *Server) handleFactoryReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		http.Error(w, "Lösenord saknas", http.StatusBadRequest)
		return
	}
	username, _ := r.Context().Value(ctxKeyUsername).(string)
	if _, err := s.engine.VerifyUserCredentials(username, req.Password); err != nil {
		http.Error(w, "Fel lösenord", http.StatusUnauthorized)
		return
	}
	if err := s.engine.FactoryReset(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	restartSelfAfterResponse(w)
}

// restartSelfAfterResponse avslutar processen strax efter att svaret
// hunnit skickas — systemd (Restart=always, se
// systemd/security-harbor-agent.service) startar om agenten rent med de
// (åter-/fabriks-)återställda filerna. Flusar svaret om writern stödjer
// det, väntar sedan en kort stund innan os.Exit så TCP-anslutningen hinner
// stängas ordentligt hos klienten.
func restartSelfAfterResponse(w http.ResponseWriter) {
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go func() {
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()
}

func (s *Server) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	st := string(s.engine.GetState())
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "security-harbor"
	}
	w.Header().Set("Content-Type", "application/json")
	memTotalGB, memFreePercent := readMemoryTotals()
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"hostname":        hostname,
		"state":           st,
		"version":         "0.12.0-fas12",
		"uptime":          readUptime(),
		"cpu":             readCPUPercent(),
		"cpu_cores":       runtime.NumCPU(),
		"memory":          readMemoryPercent(),
		"memory_total_gb": memTotalGB,
		"memory_free_pct": memFreePercent,
	})
}

// readUptime läser systemets faktiska drifttid ur /proc/uptime (sekunder
// sedan start) och formaterar den som "XhYm" — ersätter den tidigare
// hårdkodade platshållaren "1h 42m" som visades i GUI:t oavsett verklig
// drifttid.
func readUptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return ""
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return ""
	}
	d := time.Duration(seconds) * time.Second
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh %dm", hours, minutes)
}

// readCPUPercent tar ett kort (100ms) sample av /proc/stat före/efter för
// att räkna ut aktuell total CPU-belastning i procent — ersätter den
// tidigare hårdkodade platshållaren "14.5" som visades oavsett verklig
// belastning.
func readCPUPercent() float64 {
	sample := func() (idle, total uint64, ok bool) {
		data, err := os.ReadFile("/proc/stat")
		if err != nil {
			return 0, 0, false
		}
		line := strings.SplitN(string(data), "\n", 2)[0]
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "cpu" {
			return 0, 0, false
		}
		for i := 1; i < len(fields); i++ {
			v, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				continue
			}
			total += v
			if i == 4 { // "idle"-fältet
				idle = v
			}
		}
		return idle, total, true
	}

	idle1, total1, ok := sample()
	if !ok {
		return 0
	}
	time.Sleep(100 * time.Millisecond)
	idle2, total2, ok := sample()
	if !ok || total2 <= total1 {
		return 0
	}

	idleDelta := float64(idle2 - idle1)
	totalDelta := float64(total2 - total1)
	usage := (1.0 - idleDelta/totalDelta) * 100
	return math.Round(usage*10) / 10
}

// readMemInfoKB läser MemTotal/MemAvailable ur /proc/meminfo (i kB).
func readMemInfoKB() (total, available uint64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			available = v
		}
	}
	return total, available
}

// readMemoryPercent räknar ut använt minne i procent (MemTotal -
// MemAvailable) — ersätter den tidigare hårdkodade platshållaren "38.2"
// som visades oavsett verklig minnesanvändning.
func readMemoryPercent() float64 {
	total, available := readMemInfoKB()
	if total == 0 {
		return 0
	}
	usage := (1.0 - float64(available)/float64(total)) * 100
	return math.Round(usage*10) / 10
}

// readMemoryTotals returnerar totalt RAM i GB samt ledigt minne i procent
// — ersätter det tidigare hårdkodade "RAM: 8 GB (LEDIGT 62%)" som visades
// oavsett verklig maskinvara.
func readMemoryTotals() (totalGB float64, freePercent float64) {
	total, available := readMemInfoKB()
	if total == 0 {
		return 0, 0
	}
	totalGB = math.Round(float64(total)/1024/1024*10) / 10
	freePercent = math.Round(float64(available)/float64(total)*1000) / 10
	return totalGB, freePercent
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
		if mac, ok := arp[entries[i].DstIP]; ok {
			entries[i].DstMAC = mac
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

// handleSecurityEvents returnerar de senaste Suricata-larmen (Fas 9).
// Läsrättighet räcker (admin+viewer) — precis som conntrack/firewall-log,
// det är bara diagnostik, ingen handling utförs.
func (s *Server) handleSecurityEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.engine.GetSecurityEvents(1000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
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

// handleNmap kör nmap mot ett angivet mål med valfri kombination av
// skanningstyper (kryssrutor i GUI:t). Endast admin, eftersom en portscan
// kan generera avsevärd trafik och bör vara en medveten handling — se
// авsnitt 5.2 i genomförandeplanen där samma nmap-kommandon redan körs
// manuellt från master-harbor-desktop.
func (s *Server) handleNmap(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host     string `json:"host"`
		SYNScan  bool   `json:"syn_scan"`  // -sS
		FullTCP  bool   `json:"full_tcp"`  // -p- -sV
		UDPScan  bool   `json:"udp_scan"`  // -sU
		OSDetect bool   `json:"os_detect"` // -O
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Host == "" {
		http.Error(w, "Host saknas", http.StatusBadRequest)
		return
	}
	// nmap-argument skickas ALDRIG via ett skal (exec.Command anropar
	// execve direkt) så klassisk shell-injektion är inte möjlig — men ett
	// host-värde som börjar med "-" skulle annars tolkas som en egen
	// nmap-flagga. Avvisa det explicit.
	if strings.HasPrefix(req.Host, "-") {
		http.Error(w, "Ogiltigt värde för host", http.StatusBadRequest)
		return
	}
	if !req.SYNScan && !req.FullTCP && !req.UDPScan && !req.OSDetect {
		http.Error(w, "Minst en skanningstyp måste väljas", http.StatusBadRequest)
		return
	}

	args := []string{"-n"}
	if req.SYNScan {
		args = append(args, "-sS")
	}
	if req.FullTCP {
		args = append(args, "-p-", "-sV")
	}
	if req.UDPScan {
		args = append(args, "-sU")
	}
	if req.OSDetect {
		args = append(args, "-O")
	}
	args = append(args, req.Host)

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	// SYN/UDP/OS-detektion kräver riktig root (Ubuntu-paketets nmap är
	// byggt utan libcap-ng, så filkapabiliteter räcker inte — verifierat på
	// 10.0.0.163 2026-08-18). Agentens EGEN process kör med
	// NoNewPrivileges=true (systemd/security-harbor-agent.service), vilket
	// kategoriskt blockerar sudo oavsett sudoers-regler. Istället triggas
	// en helt separat, ohärdad engångstjänst (security-harbor-nmap.service,
	// cmd/security-harbor-nmap-runner) via `systemctl start --wait` — det
	// isolerar privilegiehöjningen till en minimal komponent istället för
	// att försvaga hela agentens sandbox.
	result, err := runNmapViaHelperService(ctx, args)
	if err != nil {
		result = fmt.Sprintf("nmap misslyckades: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"output": result})
}

const (
	nmapRequestPath = "/run/security-harbor/nmap-request.json"
	nmapResultPath  = "/run/security-harbor/nmap-result.json"
)

func runNmapViaHelperService(ctx context.Context, args []string) (string, error) {
	// Rensa ett ev. gammalt resultat FÖRST, så ett tyst misslyckande i
	// hjälptjänsten inte råkar returnera en tidigare skannings utdata.
	_ = os.Remove(nmapResultPath)

	reqData, err := json.Marshal(map[string][]string{"args": args})
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(nmapRequestPath, reqData, 0600); err != nil {
		return "", fmt.Errorf("kunde inte skriva request-fil: %w", err)
	}

	if out, err := exec.CommandContext(ctx, "systemctl", "start", "--wait", "security-harbor-nmap.service").CombinedOutput(); err != nil {
		return "", fmt.Errorf("kunde inte starta security-harbor-nmap.service: %w — %s", err, strings.TrimSpace(string(out)))
	}

	resultData, err := os.ReadFile(nmapResultPath)
	if err != nil {
		return "", fmt.Errorf("hjälptjänsten skrev inget resultat: %w", err)
	}
	var result struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal(resultData, &result); err != nil {
		return "", fmt.Errorf("ogiltigt resultat från hjälptjänsten: %w", err)
	}
	return result.Output, nil
}

// handleTcpdumpCapture kör en avgränsad (tids- och paketantalsbegränsad)
// paketfångst mot ett konfigurerat gränssnitt. Ingen verklig "live"-ström —
// hela fångsten körs klart och returneras som textutdata i ett svar, precis
// som nmap redan hanterar flera minuter långa skanningar. Taket på 12
// sekunder håller sig inom serverns globala WriteTimeout (se Start()).
func (s *Server) handleTcpdumpCapture(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Interface   string `json:"interface"`
		Filter      string `json:"filter"`
		PacketCount int    `json:"packet_count"`
		DurationSec int    `json:"duration_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Interface == "" {
		http.Error(w, "Gränssnitt saknas", http.StatusBadRequest)
		return
	}

	// Gränssnittet måste vara ett av de som faktiskt är konfigurerade på
	// brandväggen — förhindrar både flagg-injektion via -i och att fångst
	// körs mot ett godtyckligt, oavsiktligt device.
	cfg := s.engine.GetRunningConfig()
	valid := false
	if cfg != nil {
		for _, iface := range cfg.Interfaces {
			if iface.Device == req.Interface {
				valid = true
				break
			}
		}
	}
	if !valid {
		http.Error(w, "Okänt eller ej konfigurerat gränssnitt", http.StatusBadRequest)
		return
	}

	if req.PacketCount <= 0 || req.PacketCount > 2000 {
		req.PacketCount = 200
	}
	if req.DurationSec <= 0 || req.DurationSec > 12 {
		req.DurationSec = 10
	}

	ctx, cancel := context.WithTimeout(r.Context(), 13*time.Second)
	defer cancel()

	result, err := runTcpdumpViaHelperService(ctx, req.Interface, req.Filter, req.PacketCount, req.DurationSec)
	if err != nil {
		result = fmt.Sprintf("tcpdump misslyckades: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"output": result})
}

const (
	tcpdumpRequestPath = "/run/security-harbor/tcpdump-request.json"
	tcpdumpResultPath  = "/run/security-harbor/tcpdump-result.json"
)

// runTcpdumpViaHelperService triggar security-harbor-tcpdump.service, exakt
// samma privilegie-separeringsmönster som runNmapViaHelperService (se
// cmd/security-harbor-tcpdump-runner) — tcpdump kräver CAP_NET_RAW/root för
// en raw socket, vilket den härdade huvuddaemonen (NoNewPrivileges=true)
// inte kan bevilja sig själv.
func runTcpdumpViaHelperService(ctx context.Context, iface, filter string, packetCount, durationSec int) (string, error) {
	_ = os.Remove(tcpdumpResultPath)

	reqData, err := json.Marshal(map[string]interface{}{
		"interface":    iface,
		"filter":       filter,
		"packet_count": packetCount,
		"duration_sec": durationSec,
	})
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(tcpdumpRequestPath, reqData, 0600); err != nil {
		return "", fmt.Errorf("kunde inte skriva request-fil: %w", err)
	}

	if out, err := exec.CommandContext(ctx, "systemctl", "start", "--wait", "security-harbor-tcpdump.service").CombinedOutput(); err != nil {
		return "", fmt.Errorf("kunde inte starta security-harbor-tcpdump.service: %w — %s", err, strings.TrimSpace(string(out)))
	}

	resultData, err := os.ReadFile(tcpdumpResultPath)
	if err != nil {
		return "", fmt.Errorf("hjälptjänsten skrev inget resultat: %w", err)
	}
	var result struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal(resultData, &result); err != nil {
		return "", fmt.Errorf("ogiltigt resultat från hjälptjänsten: %w", err)
	}
	return result.Output, nil
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

// handleRefreshObjectSource triggar en omedelbar hämtning av ett Object med
// automatisk källa (Fas 5 — hot-lista/GeoIP), t.ex. via "Uppdatera nu" i
// GUI:t, istället för att vänta på nästa periodiska tillfälle.
func (s *Server) handleRefreshObjectSource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ObjectID string `json:"object_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ObjectID == "" {
		http.Error(w, "object_id saknas", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	if err := s.engine.RefreshObjectSource(ctx, req.ObjectID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
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
		// Denna route registreras med authMiddleware (alla roller) eftersom
		// GET-fallet ovan ska vara läsbart för viewer — POST/PUT (en
		// konfigurationsändring) kräver admin, kontrollerat här internt.
		if role, _ := r.Context().Value(ctxKeyRole).(string); role != string(store.RoleAdmin) {
			http.Error(w, "Forbidden: kräver admin-roll", http.StatusForbidden)
			return
		}
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
	if err := s.engine.ApplyCandidate(r.Context(), "master"); err != nil {
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
	if err := s.engine.ConfirmConfig(r.Context(), "master"); err != nil {
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
	if err := s.engine.RollbackConfig(r.Context(), "master"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// handleHitCounts läser de faktiska paket-/bytesräknarna för brandväggens
// regler (Fas 7 — Hit counters) direkt ur den skarpa nftables-ruleseten
// (`nft -j list table inet security_harbor`), och slår ihop dem per
// Policy-namn (en Policy kan generera flera regler, t.ex. en Service
// Group eller flera WAN-interface — se resolveServiceMatchExprSets i
// nftables-adaptern). Detta är alltså LIVE-data ur kärnan, inte något
// agenten själv räknar eller lagrar.
func (s *Server) handleHitCounts(w http.ResponseWriter, r *http.Request) {
	counts, err := readNftHitCounts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(counts)
}

func readNftHitCounts() (map[string]map[string]int64, error) {
	out, err := exec.Command("nft", "-j", "list", "table", "inet", "security_harbor").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nft list table misslyckades: %w - %s", err, string(out))
	}

	var raw struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("ogiltig JSON från nft: %w", err)
	}

	counts := make(map[string]map[string]int64)
	for _, el := range raw.Nftables {
		ruleRaw, ok := el["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Comment string            `json:"comment"`
			Expr    []json.RawMessage `json:"expr"`
		}
		if err := json.Unmarshal(ruleRaw, &rule); err != nil || rule.Comment == "" {
			continue
		}
		for _, exprEl := range rule.Expr {
			var counter struct {
				Counter *struct {
					Packets int64 `json:"packets"`
					Bytes   int64 `json:"bytes"`
				} `json:"counter"`
			}
			if err := json.Unmarshal(exprEl, &counter); err != nil || counter.Counter == nil {
				continue
			}
			if counts[rule.Comment] == nil {
				counts[rule.Comment] = map[string]int64{"packets": 0, "bytes": 0}
			}
			counts[rule.Comment]["packets"] += counter.Counter.Packets
			counts[rule.Comment]["bytes"] += counter.Counter.Bytes
		}
	}
	return counts, nil
}

// handleRefreshDNSBlocklist triggar en omedelbar hämtning av EN DNS-
// domänblocklista (Fas 6, matchad på DNSBlocklistSource.ID — flera källor
// kan vara aktiva samtidigt), t.ex. via "Uppdatera nu" i GUI:t.
func (s *Server) handleRefreshDNSBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		BlocklistID string `json:"blocklist_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BlocklistID == "" {
		http.Error(w, "blocklist_id saknas", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	if err := s.engine.RefreshDNSBlocklist(ctx, req.BlocklistID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// handleGetDNSBlocklistDomains returnerar den cachade domänlistan för EN
// blocklist-källa (Fas 6) — så att GUI:t faktiskt kan visa vad som är
// blockerat, inte bara antalet poster.
func (s *Server) handleGetDNSBlocklistDomains(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id saknas", http.StatusBadRequest)
		return
	}
	domains, err := s.engine.GetDNSBlocklistDomains(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(domains)
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

// firewallLogFieldRe matchar kernelns netfilter-loggformat, t.ex.:
// "...kernel: SH-ACCEPT-FWD-Kontor mot Internet: IN=ens18 OUT=ens19 MAC=... SRC=... DST=... ... PROTO=TCP SPT=51820 DPT=8443 ..."
var firewallLogFieldRe = regexp.MustCompile(`(\w+)=([^\s]*)`)

// firewallLogHeaderRe plockar ut åtgärd/kedja/policynamn ur log-prefixet
// (satt av pkg/adapter/nftables — SH-ACCEPT-*/SH-DENY-*-prefixen, se
// logSlug där). Policynamnet får innehålla mellanslag, men inte ":"
// (redan sanerat bort vid generering), så matchningen kan gå fram till
// första ":" efter prefixet.
var firewallLogHeaderRe = regexp.MustCompile(`SH-(ACCEPT|DENY)-(INPUT|FWD)-(.+?):`)

// parseFirewallLog läser de senaste loggade paket-händelserna (BÅDE
// tillåtna och nekade) ur journalens kärnlogg (nftables "log"-uttryck, se
// SH-ACCEPT-*/SH-DENY-*-prefixen i pkg/adapter/nftables/adapter.go) och
// returnerar dem strukturerat, inklusive vilken policy som fattade
// beslutet (PolicyName).
func parseFirewallLog() []config.FirewallLogEntry {
	out, err := exec.Command("journalctl", "-k", "-n", "500", "--no-pager", "-o", "short-iso", "-g", "SH-(ACCEPT|DENY)-").CombinedOutput()
	if err != nil && len(out) == 0 {
		return []config.FirewallLogEntry{}
	}

	var entries []config.FirewallLogEntry
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		header := firewallLogHeaderRe.FindStringSubmatch(line)
		if header == nil {
			continue
		}

		entry := config.FirewallLogEntry{
			Action:     strings.ToLower(header[1]),
			Chain:      header[2],
			PolicyName: header[3],
		}
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
				// första oktetterna hör till destinationen och nästa sex till
				// källan för mottagen trafik.
				parts := strings.Split(val, ":")
				if len(parts) >= 12 {
					entry.DstMAC = strings.Join(parts[0:6], ":")
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
