package api

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/network"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/nftables"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/openvpn"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/timezone"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/wireguard"
	"github.com/walker42195/security-harbor-agent/pkg/config"
	"github.com/walker42195/security-harbor-agent/pkg/engine"
	"github.com/walker42195/security-harbor-agent/pkg/pki"
	"github.com/walker42195/security-harbor-agent/pkg/store"
	"github.com/walker42195/security-harbor-agent/pkg/traffic"
	"github.com/walker42195/security-harbor-agent/pkg/updater"
)

type Server struct {
	bindAddr string
	engine   *engine.Engine
	auth     *AuthManager
	srv      *http.Server
	netAdapt *network.Adapter
	tlsCert  *pki.KeyPair
	webUIDir string
	version  string
}

func NewServer(bindAddr string, eng *engine.Engine, auth *AuthManager, tlsCert *pki.KeyPair, webUIDir, version string) *Server {
	return &Server{
		bindAddr: bindAddr,
		engine:   eng,
		auth:     auth,
		netAdapt: network.NewAdapter(),
		tlsCert:  tlsCert,
		webUIDir: webUIDir,
		version:  version,
	}
}

func (s *Server) Start() error {
	// Starta bakgrunds-CPU-samplaren (se startCPUSampler) så att
	// /api/v1/system kan läsa ett cachat, stabilt belastningsvärde.
	startCPUSampler()

	mux := http.NewServeMux()

	// Öppna endpoints
	mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	// Öppen (oautentiserad) versions-endpoint — bara versionssträngen. Låter
	// GUI:t upptäcka att agenten kommit tillbaka på den nya versionen efter en
	// uppgradering ÄVEN om sessionen just då inte gäller (t.ex. en äldre agent
	// som inte persisterade sin token över omstarten). Ingen känslig info;
	// management-API:t är dessutom LAN-only via nftables.
	mux.HandleFunc("/api/v1/version", s.handleVersion)

	// Skyddade endpoints — läsande, tillgängliga för både admin och viewer
	// (Fas 8). En "viewer" ska vara strikt skrivskyddad.
	mux.HandleFunc("/api/v1/system", s.authMiddleware(s.handleSystemStatus))
	mux.HandleFunc("/api/v1/interfaces/discover", s.authMiddleware(s.handleDiscoverInterfaces))
	mux.HandleFunc("/api/v1/system/timezones", s.authMiddleware(s.handleTimezones))
	mux.HandleFunc("/api/v1/policies/implicit", s.authMiddleware(s.handleImplicitPolicies))
	mux.HandleFunc("/api/v1/diagnostics/conntrack", s.authMiddleware(s.handleConntrack))
	mux.HandleFunc("/api/v1/diagnostics/firewall-log", s.authMiddleware(s.handleFirewallLog))
	mux.HandleFunc("/api/v1/diagnostics/bandwidth", s.authMiddleware(s.handleBandwidthStats))
	mux.HandleFunc("/api/v1/diagnostics/security-events", s.authMiddleware(s.handleSecurityEvents))
	// IDS-regelurval (kategorier + tystade signaturer).
	// Dashboard: trafik per enhet.
	mux.HandleFunc("/api/v1/dashboard/devices", s.authMiddleware(s.handleDashboardDevices))
	mux.HandleFunc("/api/v1/dashboard/device-history", s.authMiddleware(s.handleDeviceHistory))
	mux.HandleFunc("/api/v1/dashboard/traffic-types", s.authMiddleware(s.handleTrafficTypes))
	mux.HandleFunc("/api/v1/ids/rules", s.authMiddleware(s.handleIDSRules))
	mux.HandleFunc("/api/v1/ids/rules/status", s.authMiddleware(s.handleIDSRuleStatus))
	mux.HandleFunc("/api/v1/vpn/wireguard/server-info", s.authMiddleware(s.handleWireGuardServerInfo))
	mux.HandleFunc("/api/v1/vpn/openvpn/ca-info", s.authMiddleware(s.handleOpenVPNCAInfo))
	mux.HandleFunc("/api/v1/policies/hit-counts", s.authMiddleware(s.handleHitCounts))
	mux.HandleFunc("/api/v1/dns/blocklist-domains", s.authMiddleware(s.handleGetDNSBlocklistDomains))
	mux.HandleFunc("/api/v1/dhcp/leases", s.authMiddleware(s.handleDHCPLeases))
	mux.HandleFunc("/api/v1/config/running", s.authMiddleware(s.handleGetRunningConfig))
	mux.HandleFunc("/api/v1/auth/change-password", s.authMiddleware(s.handleChangePassword))
	mux.HandleFunc("/api/v1/auth/logout", s.authMiddleware(s.handleLogout))

	// Skyddade endpoints — kräver admin-roll: allt som ändrar konfig,
	// exekverar kommandon (ping/traceroute kan användas för intern
	// nätverksrekognosering från brandväggen) eller genererar/roterar
	// hemligheter.
	mux.HandleFunc("/api/v1/diagnostics/ping", s.authMiddlewareAdmin(s.handlePing))
	mux.HandleFunc("/api/v1/diagnostics/traceroute", s.authMiddlewareAdmin(s.handleTraceroute))
	mux.HandleFunc("/api/v1/diagnostics/nmap", s.authMiddlewareAdmin(s.handleNmap))
	mux.HandleFunc("/api/v1/diagnostics/dig", s.authMiddlewareAdmin(s.handleDig))
	mux.HandleFunc("/api/v1/diagnostics/arp", s.authMiddlewareAdmin(s.handleArp))
	mux.HandleFunc("/api/v1/diagnostics/tcpdump", s.authMiddlewareAdmin(s.handleTcpdumpCapture))
	mux.HandleFunc("/api/v1/vpn/wireguard/generate-peer-keys", s.authMiddlewareAdmin(s.handleWireGuardGeneratePeerKeys))
	mux.HandleFunc("/api/v1/vpn/openvpn/generate-client", s.authMiddlewareAdmin(s.handleOpenVPNGenerateClient))
	mux.HandleFunc("/api/v1/objects/refresh-source", s.authMiddlewareAdmin(s.handleRefreshObjectSource))
	mux.HandleFunc("/api/v1/dns/refresh-blocklist", s.authMiddlewareAdmin(s.handleRefreshDNSBlocklist))
	mux.HandleFunc("/api/v1/interfaces/renew-dhcp", s.authMiddlewareAdmin(s.handleRenewDHCP))
	mux.HandleFunc("/api/v1/dhcp/leases/delete", s.authMiddlewareAdmin(s.handleDeleteDHCPLease))
	mux.HandleFunc("/api/v1/notifications", s.authMiddleware(s.handleNotifications))
	mux.HandleFunc("/api/v1/notifications/test", s.authMiddlewareAdmin(s.handleNotificationsTest))
	mux.HandleFunc("/api/v1/services/status", s.authMiddleware(s.handleServicesStatus))
	mux.HandleFunc("/api/v1/services/restart", s.authMiddlewareAdmin(s.handleServiceRestart))
	mux.HandleFunc("/api/v1/config/candidate", s.authMiddleware(s.handleCandidateConfig)) // GET=alla, POST/PUT kräver admin internt (se handlern)
	mux.HandleFunc("/api/v1/config/apply", s.authMiddlewareAdmin(s.handleApplyConfig))
	mux.HandleFunc("/api/v1/config/confirm", s.authMiddlewareAdmin(s.handleConfirmConfig))
	mux.HandleFunc("/api/v1/config/rollback", s.authMiddlewareAdmin(s.handleRollbackConfig))
	mux.HandleFunc("/api/v1/config/history", s.authMiddleware(s.handleConfigHistory))
	mux.HandleFunc("/api/v1/config/history/restore", s.authMiddlewareAdmin(s.handleRestoreConfigHistory))

	// Användarhantering (Fas 8) — enbart admin.
	mux.HandleFunc("/api/v1/auth/users", s.authMiddlewareAdmin(s.handleListUsers))
	mux.HandleFunc("/api/v1/auth/users/create", s.authMiddlewareAdmin(s.handleCreateUser))
	mux.HandleFunc("/api/v1/auth/users/delete", s.authMiddlewareAdmin(s.handleDeleteUser))
	mux.HandleFunc("/api/v1/auth/users/reset-password", s.authMiddlewareAdmin(s.handleResetUserPassword))
	mux.HandleFunc("/api/v1/system/backup", s.authMiddlewareAdmin(s.handleBackup))
	mux.HandleFunc("/api/v1/system/restore", s.authMiddlewareAdmin(s.handleRestore))
	mux.HandleFunc("/api/v1/system/factory-reset", s.authMiddlewareAdmin(s.handleFactoryReset))
	mux.HandleFunc("/api/v1/system/update/check", s.authMiddlewareAdmin(s.handleUpdateCheck))
	mux.HandleFunc("/api/v1/system/update/download", s.authMiddlewareAdmin(s.handleUpdateDownload))
	mux.HandleFunc("/api/v1/system/update/apply", s.authMiddlewareAdmin(s.handleUpdateApply))
	mux.HandleFunc("/api/v1/system/versions", s.authMiddlewareAdmin(s.handleListVersions))
	mux.HandleFunc("/api/v1/system/versions/rollback", s.authMiddlewareAdmin(s.handleRollbackVersion))

	// Web-UI (Fas 8+) — statiska filer (flutter build web), t.ex. driftsatta
	// via rsync till --webui-dir. Registreras SIST men ServeMux matchar
	// alltid det mest specifika mönstret oavsett ordning, så /api/v1/*
	// påverkas inte. Om katalogen saknas/är tom svarar "/" bara 404 — bryter
	// inget om web-UI:t inte är driftsatt.
	mux.Handle("/", http.FileServer(http.Dir(s.webUIDir)))

	// managementACLMiddleware och securityHeadersMiddleware omsluter HELA
	// mux:en, så web-UI:t skyddas/får samma huvuden som Management-API:t.
	handler := s.managementACLMiddleware(securityHeadersMiddleware(bodyLimitMiddleware(mux)))

	s.srv = &http.Server{
		Addr:    s.bindAddr,
		Handler: handler,
		// ReadHeaderTimeout är den egentliga slow-loris-spärren: den kapar
		// en anslutning som droppar headers byte-för-byte, oberoende av hur
		// länge själva handlern sedan får köra.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// WriteTimeout måste rymma de MEDVETET långkörande diagnostik-
		// endpointsen. Upptäckt vid kodgranskning 2026-08-20: den var satt
		// till 15 s, medan handleNmap ger sig själv 5 minuter och en
		// Suricata-omstart (Fas 9) ensam tar ~15 s på referensmaskinen —
		// deadlinen sätts på anslutningen INNAN handlern körs, så en lång
		// nmap-skanning eller ett IDS-apply hann aldrig få tillbaka sitt
		// svar till GUI:t. 6 minuter ger 5-minutersskanningen marginal.
		WriteTimeout: 6 * time.Minute,
		// IdleTimeout skyddar mot resursutmattning via keep-alive-
		// anslutningar som annars inte fångas av Read/WriteTimeout (de
		// gäller bara EN aktiv request, inte tomgångstid mellan dem).
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

// clientIP plockar ut käll-IP:n ur r.RemoteAddr på ett sätt som fungerar
// för BÅDE IPv4 och IPv6.
//
// Upptäckt vid kodgranskning 2026-08-20: koden gjorde tidigare
// strings.Split(r.RemoteAddr, ":")[0], vilket för en IPv6-klient
// ("[::1]:54321") ger "[" — alltså samma nyckel för ALLA IPv6-klienter.
// Eftersom den strängen används som nyckel i inloggningsspärren (se
// AuthManager) delade varje IPv6-klient på en och samma försöksräknare:
// fem misslyckade försök från vilken IPv6-adress som helst låste ute alla
// andra IPv6-klienter, och en angripare kunde inte särskiljas från dem.
func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// managementACLMiddleware begränsar Management-API:t till de nät
// administratören listat i Settings.AllowedManagementLAN (CIDR eller bar
// IP). Tom lista = ingen extra begränsning; nftables-reglerna (HARD WAN
// DROP + "Allow Management API on LAN") är fortfarande den primära
// spärren, det här är ett andra lager för den som vill snäva in ännu mer.
//
// Ersätter en tidigare "wanBlockMiddleware" som blockerade allt från det
// HÅRDKODADE nätet 10.13.13.0/24 under rubriken "Management API disabled
// on WAN interface". Det hade ingenting med brandväggens faktiska
// WAN-gränssnitt att göra (10.13.13.x är ett internt nät i ett HELT annat
// projekt) — den gav alltså noll skydd på en riktig installation samtidigt
// som den låtsades göra det, och kunde dessutom av misstag stänga ute en
// administratör som råkade ha just det nätet på insidan.
// Settings.AllowedManagementLAN fanns redan i datamodellen men lästes
// aldrig av någon kod; nu gör den faktiskt vad namnet säger.
func (s *Server) managementACLMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.engine.GetRunningConfig()
		if cfg == nil || len(cfg.Settings.AllowedManagementLAN) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		ip := net.ParseIP(clientIP(r.RemoteAddr))
		if ip != nil && ip.IsLoopback() {
			next.ServeHTTP(w, r)
			return
		}
		for _, entry := range cfg.Settings.AllowedManagementLAN {
			entry = strings.TrimSpace(entry)
			if entry == "" || ip == nil {
				continue
			}
			if strings.Contains(entry, "/") {
				if _, netw, err := net.ParseCIDR(entry); err == nil && netw.Contains(ip) {
					next.ServeHTTP(w, r)
					return
				}
				continue
			}
			if allowed := net.ParseIP(entry); allowed != nil && allowed.Equal(ip) {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "Forbidden: käll-IP ligger utanför tillåtna management-nät", http.StatusForbidden)
	})
}

// securityHeadersMiddleware sätter grundläggande säkerhetshuvuden på VARJE
// svar (Fas 12) — även på den statiska web-UI-filservern, inte bara
// /api/v1/*. HSTS är rimligt eftersom TLS redan är obligatoriskt för hela
// Management-API:t (se tlsCert-hanteringen i Start()). CSP hålls medvetet
// enkel (default-src 'self') eftersom Flutter Web-bygget är helt
// self-contained utan externa resurser (typsnitt/skript/bilder bakas in i
// bygget, se artifact-liknande CSP-resonemang i webUI-driftsättningen).
//
// script-src lägger till 'wasm-unsafe-eval' (INTE det bredare
// 'unsafe-eval') — hittat och åtgärdat 2026-08-19: en ren default-src
// 'self' gjorde webb-GUI:t till en helt vit sida, eftersom Flutter Webs
// CanvasKit-renderare (WebAssembly.compileStreaming) kräver den
// specifika, avgränsade CSP3-nyckeln för att kompilera WASM alls —
// 'wasm-unsafe-eval' tillåter BARA WebAssembly-kompilering, inte
// godtycklig eval()/Function() av vanlig JS som 'unsafe-eval' hade gjort.
// maxRequestBodyBytes är taket för en request-body. Konfigurationen
// (candidate.json med hot-listor upplösta) och en inklistrad backup är de
// största legitima bodies, därav en generös men ändå ändlig gräns.
const maxRequestBodyBytes = 32 << 20 // 32 MiB

// bodyLimitMiddleware sätter ett tak på hur mycket en klient kan skicka.
//
// Kodgranskning 2026-08-25: ingen handler använde http.MaxBytesReader, så
// varje json.Decode läste obegränsat. Mest relevant för /api/v1/auth/login,
// som är OAUTENTISERAD — 30 sekunders ReadTimeout räcker för att skicka
// mycket data på ett LAN och tvinga fram allokeringar.
func bodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'")

		// Web-UI:ts statiska filer (allt utanför /api/) serveras med
		// no-cache, så webbläsaren ALLTID omvaliderar mot servern (Go:s
		// FileServer svarar 304 när filen är oförändrad, hela filen bara när
		// den ändrats). Utan detta kunde webbläsaren fortsätta köra en gammal
		// cachad main.dart.js efter en driftsättning — upptäckt 2026-08-20
		// när en GUI-fix inte syntes hos klienten trots att den var deployad.
		// (Flutter-bygget görs numera med --pwa-strategy=none, så ingen
		// service worker cachar appen bakom ryggen på detta heller.)
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-cache")
		}
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

const (
	// defaultSessionTTL är ett arbetspass. Utan "Kom ihåg inloggning" ska en
	// glömd session inte överleva särskilt länge på en delad dator.
	defaultSessionTTL = 24 * time.Hour
	// rememberedSessionTTL används när klienten kryssat i "Kom ihåg
	// inloggning". Det är fortfarande en session med utgång och den går att
	// återkalla serversidan — till skillnad från att spara lösenordet på
	// klienten, som varken går att återkalla eller ta tillbaka.
	rememberedSessionTTL = 30 * 24 * time.Hour
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r.RemoteAddr)

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
		// Remember = klientens "Kom ihåg inloggning". Ger en LÅNG session i
		// stället för dygnssessionen. Lösenordet lagras aldrig någonstans —
		// det enda som sparas hos klienten är den serversignerade token, och
		// den kan återkallas här (sessionerna är spårade per användare).
		Remember bool `json:"remember"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Spärren kollas för BÅDE käll-IP och användarnamn (Fas 12) — annars
	// kan en angripare kringgå en ren IP-spärr genom att rotera käll-IP
	// mot samma användarnamn.
	if s.auth.IsLockedOut(ip, creds.Username) {
		log.Printf("[LOGIN] SPÄRRAD: käll-IP=%s användarnamn=%q", ip, creds.Username)
		http.Error(w, "Spärrad p.g.a. för många misslyckade försök", http.StatusTooManyRequests)
		return
	}

	user, err := s.engine.VerifyUserCredentials(creds.Username, creds.Password)
	if err == nil {
		sessionTTL := defaultSessionTTL
		if creds.Remember {
			sessionTTL = rememberedSessionTTL
		}
		token, tokenErr := s.auth.CreateSession(user.Username, string(user.Role), sessionTTL)
		if tokenErr != nil {
			log.Printf("[LOGIN] MISSLYCKADES (kunde inte skapa session): käll-IP=%s användarnamn=%q fel=%v", ip, creds.Username, tokenErr)
			http.Error(w, tokenErr.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("[LOGIN] LYCKADES: käll-IP=%s användarnamn=%q roll=%s", ip, user.Username, user.Role)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": token, "user": user.Username, "role": string(user.Role)})
		return
	}

	log.Printf("[LOGIN] FEL LÖSENORD/ANVÄNDARNAMN: käll-IP=%s användarnamn=%q fel=%v", ip, creds.Username, err)
	s.auth.RecordFailedAttempt(ip, creds.Username)
	http.Error(w, "Felaktigt användarnamn eller lösenord", http.StatusUnauthorized)
}

// handleLogout ogiltigförklarar den token anropet gjordes med, på SERVERN.
//
// Kodgranskning 2026-08-25: tidigare fanns ingen sådan endpoint alls —
// "Logga ut" i GUI:t rensade bara klientens minne, medan sessionen levde
// vidare i upp till 24 timmar. En token som läckt (delad dator, kopierad
// localStorage) gick alltså inte att återkalla.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.auth.DeleteSession(token)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
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
	// Ett lösenordsbyte ska ogiltigförklara ALLA andra sessioner för kontot —
	// annars gör "byt lösenord efter intrång" ingen nytta mot någon som redan
	// har en giltig token. Den token anropet gjordes med behålls, så
	// administratören inte loggas ut av sitt eget byte.
	currentToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.auth.DeleteSessionsForUserExcept(user.Username, currentToken)
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
	// Slå upp namnet FÖRE raderingen — efteråt går kontot inte att hitta.
	username := s.engine.UsernameByID(req.ID)
	if err := s.engine.DeleteUser(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Ett raderat konto måste förlora sina aktiva sessioner direkt. Utan
	// detta fortsatte en raderad användares token att fungera i upp till 24
	// timmar (kodgranskning 2026-08-25).
	if username != "" {
		if n := s.auth.DeleteSessionsForUser(username); n > 0 {
			log.Printf("[AUTH] raderade %d aktiv(a) session(er) för borttagen användare %q", n, username)
		}
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
	// En admin som återställer någons lösenord gör det typiskt EFTER en
	// misstänkt kapning — då måste kontots befintliga sessioner dö, annars
	// sitter angriparen kvar med sin token (kodgranskning 2026-08-25).
	if username := s.engine.UsernameByID(req.ID); username != "" {
		if n := s.auth.DeleteSessionsForUser(username); n > 0 {
			log.Printf("[AUTH] raderade %d aktiv(a) session(er) efter lösenordsåterställning för %q", n, username)
		}
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

// handleUpdateCheck hämtar releasens manifest och jämför mot den körande
// agent- och webb-GUI-versionen. Returnerar vad som finns att uppgradera till.
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	m, err := updater.FetchManifest(ctx)
	if err != nil {
		http.Error(w, "kunde inte hämta uppdateringsinfo: "+err.Error(), http.StatusBadGateway)
		return
	}
	webNow := updater.ReadWebUIVersion(s.webUIDir)
	resp := map[string]interface{}{
		"agent":  map[string]string{"current": s.version},
		"webui":  map[string]string{"current": webNow},
		"staged": readStagedVersion(),
	}
	updateAvailable := false
	if m.Firewall != nil {
		resp["agent"].(map[string]string)["available"] = m.Firewall.Version
		resp["webui"].(map[string]string)["available"] = m.Firewall.WebUIVersion
		if updater.IsNewer(m.Firewall.Version, s.version) || updater.IsNewer(m.Firewall.WebUIVersion, webNow) {
			updateAvailable = true
		}
	}
	resp["update_available"] = updateAvailable
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleUpdateDownload laddar ner och verifierar (SHA256 + Ed25519) firewall-
// bunten och stagear den. Uppgradera-knappen i GUI:t låses upp först när detta
// svarar verified:true.
func (s *Server) handleUpdateDownload(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	m, err := updater.FetchManifest(ctx)
	if err != nil {
		http.Error(w, "kunde inte hämta manifest: "+err.Error(), http.StatusBadGateway)
		return
	}
	if m.Firewall == nil {
		http.Error(w, "manifestet saknar en firewall-bunt", http.StatusBadGateway)
		return
	}
	// Nedgraderingsskydd: tarbollen är signerad, men MANIFESTET är det inte.
	// Den som kontrollerar manifest-URL:en (t.ex. ett kapat GitHub-konto)
	// kan därför inte förfalska en bunt — men väl peka ut en ÄLDRE, korrekt
	// signerad version med kända sårbarheter. Vägra staga något som inte är
	// nyare än det som redan kör (kodgranskning 2026-08-25). Rollback till
	// en tidigare version görs medvetet via /system/versions/rollback, som
	// bara använder lokalt arkiverade versioner.
	if m.Firewall.Version != s.version && !updater.IsNewer(m.Firewall.Version, s.version) {
		http.Error(w, fmt.Sprintf(
			"vägrar ladda ner version %s — den är inte nyare än den installerade (%s). Använd Tidigare versioner för att gå tillbaka.",
			m.Firewall.Version, s.version), http.StatusBadRequest)
		return
	}
	if err := updater.DownloadAndStage(ctx, m.Firewall); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"verified": true,
		"version":  m.Firewall.Version,
	})
}

// handleUpdateApply triggar den privilegierade root-installern (systemd
// oneshot). Kräver att en verifierad bunt redan stagats. Startas med
// --no-block så att API-svaret hinner skickas innan agenten startas om.
func (s *Server) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	tarball := filepath.Join(updater.StagingDir, updater.StagedTarball)
	sig := filepath.Join(updater.StagingDir, updater.StagedSig)
	if _, err := os.Stat(tarball); err != nil {
		http.Error(w, "ingen nedladdad uppdatering att installera — ladda ner först", http.StatusBadRequest)
		return
	}
	if _, err := os.Stat(sig); err != nil {
		http.Error(w, "signaturfil saknas för den stagade bunten", http.StatusBadRequest)
		return
	}
	// Extra spärr: verifiera signaturen igen här innan vi ens triggar
	// installern (root-runnern verifierar dessutom en tredje gång som root).
	if err := updater.VerifyFile(tarball, sig); err != nil {
		http.Error(w, "den stagade bunten kan inte verifieras: "+err.Error(), http.StatusBadRequest)
		return
	}
	out, err := exec.Command("systemctl", "start", "--no-block", "security-harbor-update.service").CombinedOutput()
	if err != nil {
		http.Error(w, "kunde inte starta installern: "+string(out), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"message": "Installationen startad. Agenten startar om på den nya versionen om en liten stund.",
	})
}

// handleConfigHistory listar de senast bekräftade konfigurationerna som
// finns sparade på brandväggen. Läsbar för alla roller (som övriga
// statusvyer); att faktiskt återställa kräver admin.
func (s *Server) handleConfigHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"current_revision": currentRevision(s.engine.GetRunningConfig()),
		"history":          s.engine.ListConfigHistory(),
	})
}

func currentRevision(cfg *config.Config) int64 {
	if cfg == nil {
		return 0
	}
	return cfg.Revision
}

// handleRestoreConfigHistory laddar en sparad konfiguration som KANDIDAT.
// Den appliceras INTE här — administratören trycker Applicera som vanligt
// och får hela Safe Apply-kedjan. Se Engine.RestoreConfigFromHistory.
func (s *Server) handleRestoreConfigHistory(w http.ResponseWriter, r *http.Request) {
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
	cfg, err := s.engine.RestoreConfigFromHistory(req.ID, auditUser(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":       true,
		"revision": cfg.Revision,
		"message":  "Den sparade konfigurationen är inläst som kandidat. Tryck Applicera för att aktivera den — Safe Apply gäller som vanligt.",
	})
}

// readStagedVersion returnerar den verifierade, nedladdade version som väntar
// på installation (tom sträng om ingen).
func readStagedVersion() string {
	data, err := os.ReadFile(filepath.Join(updater.StagingDir, "staged-version.txt"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// rollbackVersionPattern styr vilka versionssträngar som accepteras av
// handleRollbackVersion INNAN de någonsin används för att bygga ett
// systemd-enhetsnamn (security-harbor-rollback@<version>.service) eller
// skickas vidare till exec.Command — stänger kommandoinjektions-ytan helt,
// oavsett vad som råkar stå i versions/index.json.
var rollbackVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// handleListVersions returnerar de senast installerade versionerna som
// fortfarande finns sparade på disk (se systemd/lib-archive-version.sh) och
// går att rulla tillbaka till, samt vilken som är den nu körande.
func (s *Server) handleListVersions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"current":  s.version,
		"versions": updater.ListRetainedVersions(),
	})
}

// handleRollbackVersion triggar den privilegierade root-rollback-installern
// (systemd mall-enhet) för en tidigare sparad version. Till skillnad från
// handleUpdateApply görs ingen ny signaturverifiering — den arkiverade
// binären har redan körts betrott på den här maskinen tidigare.
func (s *Server) handleRollbackVersion(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "ogiltig begäran", http.StatusBadRequest)
		return
	}
	version := strings.TrimSpace(body.Version)
	if !rollbackVersionPattern.MatchString(version) {
		http.Error(w, "ogiltig versionssträng", http.StatusBadRequest)
		return
	}
	if version == s.version {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":      true,
			"message": "redan på version " + version,
		})
		return
	}
	found := false
	for _, v := range updater.ListRetainedVersions() {
		if v.Version == version {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "versionen finns inte bland sparade versioner", http.StatusBadRequest)
		return
	}
	unit := "security-harbor-rollback@" + version + ".service"
	out, err := exec.Command("systemctl", "start", "--no-block", unit).CombinedOutput()
	if err != nil {
		http.Error(w, "kunde inte starta rollback-installern: "+string(out), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"message": "Återställningen startad. Agenten startar om på version " + version + " om en liten stund.",
	})
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

// handleVersion returnerar bara agentens version, utan autentisering (se
// route-registreringen). Används av GUI:ts uppgraderings-återkoppling.
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"version": s.version})
}

func (s *Server) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	st := string(s.engine.GetState())
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "security-harbor"
	}
	w.Header().Set("Content-Type", "application/json")
	memTotalGB, memFreePercent := readMemoryTotals()
	diskPct, diskTotalGB, diskFreeGB := readDiskUsage()
	rebootRequired, rebootPkgs := readRebootRequired()
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"hostname":        hostname,
		"state":           st,
		"version":         s.version,
		"webui_version":   updater.ReadWebUIVersion(s.webUIDir),
		"uptime":          readUptime(),
		"cpu":             readCPUPercent(),
		"cpu_cores":       runtime.NumCPU(),
		"memory":          readMemoryPercent(),
		"memory_total_gb": memTotalGB,
		"memory_free_pct": memFreePercent,
		"disk":            diskPct,
		"disk_total_gb":   diskTotalGB,
		"disk_free_gb":    diskFreeGB,
		// OS-omstart krävs efter paketuppdateringar (kärna/libc m.m.).
		// apt/unattended-upgrades skapar /run/reboot-required; samma signal
		// som visas i CLI:ns MOTD vid inloggning ska synas i GUI:t.
		"reboot_required":      rebootRequired,
		"reboot_required_pkgs": rebootPkgs,
		// Backends som inte kunde appliceras men som inte är trafikstyrande
		// (i praktiken IDS) — appliceringen gick igenom, men funktionen är
		// inte igång och det ska synas i GUI:t i stället för att tyst
		// försvinna i agentloggen.
		"degraded_backends": s.engine.DegradedBackends(),
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

// readRebootRequired speglar samma signal som CLI:ns inloggnings-MOTD:
// apt/unattended-upgrades skapar /run/reboot-required när en installerad
// uppdatering (kärna, libc, m.m.) inte träder i kraft förrän maskinen
// startats om, och listar de utlösande paketen i .pkgs-filen. Returnerar
// om omstart behövs samt en (avdubblerad) lista över paketen — så GUI:t kan
// visa en banner i stället för att administratören bara ser det i CLI:n.
func readRebootRequired() (required bool, pkgs []string) {
	// /var/run är en symlänk till /run på moderna system; prova båda så att
	// funktionen är robust oavsett distro-layout.
	found := false
	for _, p := range []string{"/run/reboot-required", "/var/run/reboot-required"} {
		if _, err := os.Stat(p); err == nil {
			found = true
			break
		}
	}
	if !found {
		return false, nil
	}
	seen := map[string]bool{}
	for _, p := range []string{"/run/reboot-required.pkgs", "/var/run/reboot-required.pkgs"} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			name := strings.TrimSpace(line)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			pkgs = append(pkgs, name)
		}
		break
	}
	sort.Strings(pkgs)
	return true, pkgs
}

// cpuSample är den senast uträknade CPU-belastningen, uppdaterad av
// startCPUSampler i bakgrunden. readCPUPercent (som anropas synkront i
// varje /api/v1/system-anrop) läser bara det cachade värdet.
var cpuSample struct {
	mu     sync.RWMutex
	value  float64
	primed bool
}

// sampleCPUStat läser den aggregerade "cpu"-raden ur /proc/stat och
// returnerar idle-jiffies (inkl. iowait, som också är overksam tid) och
// totala jiffies. Skillnaden mellan två avlästa sample ger belastningen.
func sampleCPUStat() (idle, total uint64, ok bool) {
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
		// Fält 4 = idle, fält 5 = iowait (om det finns). Båda räknas
		// som overksam tid, annars överskattas belastningen på en
		// I/O-väntande värd.
		if i == 4 || i == 5 {
			idle += v
		}
	}
	return idle, total, true
}

// startCPUSampler kör en bakgrundsloop som var 2:a sekund räknar ut
// CPU-belastningen över HELA intervallet och cachar den.
//
// Ersätter det tidigare 100ms-samplet som togs synkront i varje
// /api/v1/system-anrop: ett så kort fönster fångar bara ett fåtal jiffies
// (kärnans jiffy-upplösning är ~10ms) på en nästan-idle brandvägg, så
// idle-andelen dominerade och resultatet kvantiserades nästan alltid till
// 0,0 % — därav "Dashboard visar nästan alltid 0 %". Ett 2s-fönster ger
// ett stabilt, verkligt värde och lägger dessutom ingen fördröjning på
// dashboard-anropet (som förut blockerade 100ms per hämtning).
func startCPUSampler() {
	go func() {
		idlePrev, totalPrev, okPrev := sampleCPUStat()
		for range time.Tick(2 * time.Second) {
			idle, total, ok := sampleCPUStat()
			if okPrev && ok && total > totalPrev {
				idleDelta := float64(idle - idlePrev)
				totalDelta := float64(total - totalPrev)
				usage := (1.0 - idleDelta/totalDelta) * 100
				if usage < 0 {
					usage = 0
				} else if usage > 100 {
					usage = 100
				}
				cpuSample.mu.Lock()
				cpuSample.value = math.Round(usage*10) / 10
				cpuSample.primed = true
				cpuSample.mu.Unlock()
			}
			idlePrev, totalPrev, okPrev = idle, total, ok
		}
	}()
}

// readCPUPercent returnerar det senast cachade CPU-belastningsvärdet.
// Innan den första 2s-cykeln hunnit klart (precis efter boot) returneras
// 0 — det stämmer i praktiken ändå, eftersom värden inte hunnit mätas.
func readCPUPercent() float64 {
	cpuSample.mu.RLock()
	defer cpuSample.mu.RUnlock()
	return cpuSample.value
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

// readDiskUsage returnerar rotfilsystemets användning i procent samt total-
// och ledigt utrymme i GB. En full disk gör brandväggen oanvändbar (Kea/
// Unbound/agent kan inte skriva) — därför ska det synas i GUI:t. Använder
// statfs på "/"; utrymme reserverat för root räknas som använt (Bavail =
// det som faktiskt går att använda).
func readDiskUsage() (usedPercent float64, totalGB float64, freeGB float64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return 0, 0, 0
	}
	bs := float64(st.Bsize)
	total := bs * float64(st.Blocks)
	free := bs * float64(st.Bavail)
	if total <= 0 {
		return 0, 0, 0
	}
	used := total - free
	usedPercent = math.Round(used/total*1000) / 10
	totalGB = math.Round(total/1e9*10) / 10
	freeGB = math.Round(free/1e9*10) / 10
	return usedPercent, totalGB, freeGB
}

// handleRenewDHCP kör om DHCP-förhandlingen för ETT gränssnitt i
// DHCP-läge (t.ex. WAN) på begäran — en "förnya IP"-knapp i GUI:t,
// 2026-08-24. Slår upp gränssnittet i RUNNING-configen (den faktiskt
// applicerade, inte kandidaten) eftersom det är det som faktiskt finns på
// systemet just nu.
func (s *Server) handleRenewDHCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	cfg := s.engine.GetRunningConfig()
	if cfg == nil {
		http.Error(w, "Ingen körande konfiguration", http.StatusInternalServerError)
		return
	}
	var target *config.Interface
	for i := range cfg.Interfaces {
		if cfg.Interfaces[i].ID == req.ID {
			target = &cfg.Interfaces[i]
			break
		}
	}
	if target == nil {
		http.Error(w, "Gränssnittet hittades inte", http.StatusBadRequest)
		return
	}
	if !target.Enabled || target.AddressType != "dhcp" {
		http.Error(w, "Gränssnittet är inte aktiverat i DHCP-läge", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()
	if err := s.netAdapt.RenewDHCP(ctx, target.Device, strings.EqualFold(target.Zone, "WAN")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
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
	entries, truncated := parseFirewallLogWindow(r.URL.Query().Get("window"))
	w.Header().Set("Content-Type", "application/json")
	// Svaret är ett OBJEKT, inte en bar lista, så klienten kan få veta att
	// fönstret klipptes. Äldre GUI:n som förväntar sig en lista hanteras av
	// att de skickar utan window-parameter och då får samma 500 rader som
	// förut — men de måste ändå uppdateras för att kunna tolka svaret.
	_ = json.NewEncoder(w).Encode(map[string]any{
		"entries":   entries,
		"truncated": truncated,
		"max":       firewallLogMaxEntries,
	})
}

// handleSecurityEvents returnerar de senaste Suricata-larmen (Fas 9).
// Läsrättighet räcker (admin+viewer) — precis som conntrack/firewall-log,
// det är bara diagnostik, ingen handling utförs.
//
// Frågeparametrar:
//
//	source: "live" (default, ur eve.json) | "history" / "fast" (ur fast.log)
//	limit:  antal rader att läsa (default 1000, max 5000)
func (s *Server) handleSecurityEvents(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source")
	if source == "" {
		source = "live"
	}
	limit := 1000
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 5000 {
			limit = l
		}
	}
	maxSeverity := 0
	if sev := r.URL.Query().Get("severity"); sev != "" {
		if sev == "blocking" {
			maxSeverity = 2
		} else if l, err := strconv.Atoi(sev); err == nil && l > 0 {
			maxSeverity = l
		}
	}
	events, err := s.engine.GetSecurityEvents(source, limit, maxSeverity)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}

// handleDashboardDevices returnerar trafik per enhet för dashboarden.
//
// Frågeparametrar:
//
//	res    "1m" | "5m" | "1h" | "1d"  (fönster/upplösning, default "5m")
//	spark  antal minutpunkter för minigrafen i varje rad (0 = ingen)
//	live   "1" = klienten visar en realtidsvy och vill att agenten läser av
//	       trafikräknarna i snabb takt en kort stund framåt (se
//	       Engine.RequestLiveTraffic). Utan den kan bps-siffrorna aldrig
//	       ändras oftare än var 10:e sekund, hur ofta klienten än pollar.
func (s *Server) handleDashboardDevices(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("live") == "1" {
		s.engine.RequestLiveTraffic()
	}
	res := r.URL.Query().Get("res")
	switch res {
	case "", "1m", "5m", "1h", "1d":
	default:
		http.Error(w, "ogiltig upplösning", http.StatusBadRequest)
		return
	}

	spark := 0
	if v := r.URL.Query().Get("spark"); v != "" {
		n, err := strconv.Atoi(v)
		// Taket finns för att en klient inte ska kunna be om godtyckligt
		// mycket data per rad — 60 punkter är en timme i minutupplösning.
		if err != nil || n < 0 || n > 60 {
			http.Error(w, "spark måste vara 0-60", http.StatusBadRequest)
			return
		}
		spark = n
	}

	data := s.engine.GetDashboard(r.Context(), res, spark)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}

// handleDeviceHistory returnerar tidsserien för EN enhet.
func (s *Server) handleDeviceHistory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ip := q.Get("ip")
	if net.ParseIP(ip) == nil {
		http.Error(w, "ogiltig ip", http.StatusBadRequest)
		return
	}
	res := q.Get("res")
	switch res {
	case "", "1m", "5m", "1h", "1d":
	default:
		http.Error(w, "ogiltig upplösning", http.StatusBadRequest)
		return
	}
	if res == "" {
		res = "1m"
	}
	points := 120
	if v := q.Get("points"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 2160 {
			http.Error(w, "points måste vara 1-2160", http.StatusBadRequest)
			return
		}
		points = n
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.engine.DeviceHistory(res, ip, points))
}

// trafficTypesResponse är svaret från GET /api/v1/dashboard/traffic-types.
type trafficTypesResponse struct {
	Categories []traffic.CategoryTotal            `json:"categories"`
	PerDevice  map[string][]traffic.CategoryTotal `json:"per_device"`
	TopDomains []traffic.DomainTotal              `json:"top_domains"`
	// DeviceNames är IP -> visningsnamn. Statistiken är nycklad på IP, men en
	// adress säger sällan någon någonting.
	DeviceNames map[string]string `json:"device_names"`
	Resolution  string            `json:"resolution"`
	// IDSOnInside är falskt när Suricata lyssnar på WAN-kortet. Då finns
	// ingen klassificerbar trafik alls, eftersom allt syns efter NAT med
	// brandväggens egen adress som källa — GUI:t visar en förklaring i
	// stället för en tom vy.
	IDSOnInside bool `json:"ids_on_inside"`
}

func (s *Server) handleTrafficTypes(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	res := q.Get("res")
	switch res {
	case "", "1h", "1d":
	default:
		http.Error(w, "ogiltig upplösning (1h eller 1d)", http.StatusBadRequest)
		return
	}
	ip := q.Get("ip")
	if ip != "" && net.ParseIP(ip) == nil {
		http.Error(w, "ogiltig ip", http.StatusBadRequest)
		return
	}
	limit := 20
	if v := q.Get("domains"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 100 {
			http.Error(w, "domains måste vara 0-100", http.StatusBadRequest)
			return
		}
		limit = n
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(trafficTypesResponse{
		Categories:  s.engine.TrafficCategories(res, ip),
		PerDevice:   s.engine.TrafficCategoriesPerDevice(res),
		TopDomains:  s.engine.TopDomains(ip, limit),
		DeviceNames: s.engine.DeviceNames(r.Context()),
		Resolution:  res,
		IDSOnInside: s.engine.IDSOnInside(),
	})
}

// idsRulesResponse är svaret från GET /api/v1/ids/rules: alla kategorier med
// antal regler och nuvarande status, plus listan över enskilt tystade
// signaturer.
type idsRulesResponse struct {
	Categories         []suricataCategoryView     `json:"categories"`
	DisabledSignatures []config.DisabledSignature `json:"disabled_signatures"`
	UpdateStatus       string                     `json:"update_status"`
}

type suricataCategoryView struct {
	Name    string `json:"name"`
	Total   int    `json:"total"`
	Enabled int    `json:"enabled"`
	// Disabled speglar konfigurationen, INTE regelfilen: efter att en
	// kategori stängts av tar det ~40-60 s innan suricata-update skrivit om
	// filen, och GUI:t ska visa användarens val direkt.
	Disabled bool `json:"disabled"`
}

// idsRulesRequest är kroppen till POST /api/v1/ids/rules.
//
// Kategori- och signaturändringar skickas som deltan snarare än hela listor,
// så att två samtidiga admins inte råkar radera varandras val genom att skicka
// en lista som var färsk när deras vy laddades.
type idsRulesRequest struct {
	DisableCategory string `json:"disable_category,omitempty"`
	EnableCategory  string `json:"enable_category,omitempty"`
	SilenceSID      int    `json:"silence_sid,omitempty"`
	UnsilenceSID    int    `json:"unsilence_sid,omitempty"`
}

func (s *Server) handleIDSRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getIDSRules(w, r)
	case http.MethodPost:
		s.postIDSRules(w, r)
	default:
		http.Error(w, "metod stöds inte", http.StatusMethodNotAllowed)
	}
}

func (s *Server) getIDSRules(w http.ResponseWriter, r *http.Request) {
	cats, err := s.engine.IDSCategories()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cfg := s.engine.GetRunningConfig()
	disabled := map[string]bool{}
	var sigs []config.DisabledSignature
	if cfg != nil && cfg.IDS != nil {
		for _, c := range cfg.IDS.DisabledCategories {
			disabled[c] = true
		}
		sigs = cfg.IDS.DisabledSignatures
	}
	if sigs == nil {
		sigs = []config.DisabledSignature{}
	}

	views := make([]suricataCategoryView, 0, len(cats))
	for _, c := range cats {
		views = append(views, suricataCategoryView{
			Name: c.Name, Total: c.Total, Enabled: c.Enabled, Disabled: disabled[c.Name],
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(idsRulesResponse{
		Categories:         views,
		DisabledSignatures: sigs,
		UpdateStatus:       s.engine.IDSRuleUpdateStatus(r.Context()),
	})
}

func (s *Server) postIDSRules(w http.ResponseWriter, r *http.Request) {
	var req idsRulesRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		http.Error(w, "ogiltig JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	cfg := s.engine.GetRunningConfig()
	if cfg == nil || cfg.IDS == nil {
		http.Error(w, "IDS är inte konfigurerat", http.StatusConflict)
		return
	}

	cats := append([]string(nil), cfg.IDS.DisabledCategories...)
	sigs := append([]config.DisabledSignature(nil), cfg.IDS.DisabledSignatures...)

	switch {
	case req.DisableCategory != "":
		if !containsString(cats, req.DisableCategory) {
			cats = append(cats, req.DisableCategory)
		}
	case req.EnableCategory != "":
		cats = removeString(cats, req.EnableCategory)
	case req.SilenceSID > 0:
		already := false
		for _, sg := range sigs {
			if sg.SID == req.SilenceSID {
				already = true
			}
		}
		if !already {
			// Slå upp signaturtexten så att GUI:t kan visa VAD som tystades
			// utan att läsa om regelfilen. Misslyckas uppslaget är det inte
			// ett fel — SID:t stängs av ändå.
			name, _ := s.engine.IDSLookupSignature(req.SilenceSID)
			sigs = append(sigs, config.DisabledSignature{
				SID:        req.SilenceSID,
				Signature:  name,
				DisabledAt: time.Now().UTC().Format(time.RFC3339),
			})
		}
	case req.UnsilenceSID > 0:
		out := sigs[:0]
		for _, sg := range sigs {
			if sg.SID != req.UnsilenceSID {
				out = append(out, sg)
			}
		}
		sigs = out
	default:
		http.Error(w, "ingen åtgärd angiven", http.StatusBadRequest)
		return
	}

	// Sparar urvalet OCH startar regeluppdateringen. Den kör i bakgrunden
	// (~40-60 s) — GUI:t följer den via /api/v1/ids/rules/status.
	if err := s.engine.UpdateIDSRuleSelection(r.Context(), sigs, cats); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":              "applying",
		"disabled_categories": cats,
		"disabled_signatures": sigs,
	})
}

func (s *Server) handleIDSRuleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": s.engine.IDSRuleUpdateStatus(r.Context()),
	})
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func removeString(list []string, v string) []string {
	out := list[:0]
	for _, s := range list {
		if s != v {
			out = append(out, s)
		}
	}
	return out
}

// diagnosticHostPattern är en ALLOWLIST för mål till ping/traceroute/nmap:
// IP-adresser (v4/v6), CIDR och värdnamn. Argumenten skickas aldrig via ett
// skal (exec.Command anropar execve direkt) så klassisk shell-injektion är
// inte möjlig — men ETT VÄRDE SOM BÖRJAR MED "-" tolkas av verktyget som en
// egen flagga. handleNmap avvisade redan det; ping och traceroute gjorde det
// INTE (upptäckt vid kodgranskning 2026-08-20), så en admin kunde t.ex.
// skicka "-f" och få ping att köra flood-ping istället för fyra paket.
// Alla tre går nu genom samma kontroll, och "--" avslutar dessutom
// flagg-tolkningen hos verktyget som ett andra lager.
var diagnosticHostPattern = regexp.MustCompile(`^[A-Za-z0-9._:\[\]/-]+$`)

func validateDiagnosticHost(host string) error {
	if host == "" || len(host) > 255 {
		return fmt.Errorf("ogiltigt värde för host")
	}
	if strings.HasPrefix(host, "-") || !diagnosticHostPattern.MatchString(host) {
		return fmt.Errorf("ogiltigt värde för host")
	}
	return nil
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Host == "" {
		http.Error(w, "Host saknas", http.StatusBadRequest)
		return
	}
	if err := validateDiagnosticHost(req.Host); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out, _ := exec.Command("ping", "-c", "4", "-W", "2", "--", req.Host).CombinedOutput()
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
	if err := validateDiagnosticHost(req.Host); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out, _ := exec.Command("traceroute", "-n", "-w", "1", "-m", "15", "--", req.Host).CombinedOutput()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"output": string(out)})
}

// handleDig slår upp ett DNS-namn med `dig`. Valfri record-typ (A/AAAA/MX/...)
// och valfri server att fråga (@server). Kräver inte root; körs direkt som
// tjänstekontot. Validering återanvänder validateDiagnosticHost så inga flaggor
// kan smugglas in via host/server-fälten, och type begränsas till en vitlista.
var digTypePattern = regexp.MustCompile(`^[A-Za-z]{1,10}$`)

func (s *Server) handleDig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host   string `json:"host"`
		Type   string `json:"type"`
		Server string `json:"server"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Host == "" {
		http.Error(w, "Host saknas", http.StatusBadRequest)
		return
	}
	if err := validateDiagnosticHost(req.Host); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	args := []string{"+noall", "+answer", "+comments", "+stats"}
	if req.Type != "" {
		if !digTypePattern.MatchString(req.Type) {
			http.Error(w, "ogiltig record-typ", http.StatusBadRequest)
			return
		}
		args = append(args, "-t", strings.ToUpper(req.Type))
	}
	if req.Server != "" {
		if err := validateDiagnosticHost(req.Server); err != nil {
			http.Error(w, "ogiltig server", http.StatusBadRequest)
			return
		}
		args = append(args, "@"+req.Server)
	}
	args = append(args, "--", req.Host)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "dig", args...).CombinedOutput()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"output": string(out)})
}

// handleArp visar grannbords-/ARP-tabellen (IPv4 + IPv6) med `ip neigh`. Enbart
// läsning, ingen root krävs. Ger IP↔MAC-mappningar för enheter brandväggen
// nyligen pratat med — praktiskt för att hitta MAC att reservera i DHCP.
func (s *Server) handleArp(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "ip", "neigh", "show").CombinedOutput()
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
		Host       string `json:"host"`
		SYNScan    bool   `json:"syn_scan"`    // -sS
		FullTCP    bool   `json:"full_tcp"`    // -p- -sV
		UDPScan    bool   `json:"udp_scan"`    // -sU
		OSDetect   bool   `json:"os_detect"`   // -O
		FastTiming bool   `json:"fast_timing"` // -T4 - kombinerbar med valfri scanningstyp ovan
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Host == "" {
		http.Error(w, "Host saknas", http.StatusBadRequest)
		return
	}
	// nmap-argument skickas ALDRIG via ett skal (exec.Command anropar
	// execve direkt) så klassisk shell-injektion är inte möjlig — men ett
	// host-värde som börjar med "-" skulle annars tolkas som en egen
	// nmap-flagga. Avvisa det explicit.
	if err := validateDiagnosticHost(req.Host); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
	// -T4 ("aggressive") - snabbare parallellisering/timeouts än nmaps
	// default -T3. Kombinerbar med vilken scanningstyp som helst ovan,
	// styr bara HUR snabbt nmap kör, inte VAD den skannar. -T5 ("insane")
	// undviks medvetet - den offrar tillförlitlighet (missade portar) på
	// ett sätt -T4 inte gör, olämpligt som standardval för ett
	// administrationsverktyg.
	if req.FastTiming {
		args = append(args, "-T4")
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

// nmapHelperMu serialiserar anrop till den delade request-/resultatfilen
// (samma icke-templatade unit för alla anrop). Utan detta lås kan två
// samtidiga admin-sessioner kapplöpa om filerna — säkerhetsgranskning
// 2026-08-19 bekräftade skarpt att session B:s förfrågan om att skanna
// 10.0.0.163 fick TILLBAKA session A:s resultat för 127.0.0.1 (fel mål,
// tyst felaktig utdata till fel session). Låset gör att anrop köas
// istället för att kapplöpa — samma mönster används för tcpdump nedan.
var nmapHelperMu sync.Mutex

func runNmapViaHelperService(ctx context.Context, args []string) (string, error) {
	nmapHelperMu.Lock()
	defer nmapHelperMu.Unlock()

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
// bpfFilterPattern är en ALLOWLIST för tcpdump-filteruttryck: de tecken en
// riktig BPF-primitiv behöver (bokstäver, siffror, blanksteg, punkt, kolon,
// snedstreck för CIDR, parenteser, jämförelseoperatorer och hakparenteser
// för byte-offsets). Notera att "-" INTE ingår — ett filter kan aldrig
// börja likna en tcpdump-flagga.
var bpfFilterPattern = regexp.MustCompile(`^[A-Za-z0-9 ._:/()\[\]<>=!&|+*]*$`)

// validateBPFFilter avvisar allt som inte är ett rimligt BPF-uttryck. Delas
// medvetet inte med diagnosticHostPattern: den tillåter inledande tecken som
// vore olämpliga här, och ett BPF-filter behöver blanksteg och parenteser
// som ett värdnamn inte får ha.
func validateBPFFilter(filter string) error {
	if filter == "" {
		return nil
	}
	if len(filter) > 512 {
		return fmt.Errorf("filtret är för långt (max 512 tecken)")
	}
	if strings.HasPrefix(strings.TrimSpace(filter), "-") {
		return fmt.Errorf("ogiltigt filter: får inte börja med \"-\"")
	}
	if !bpfFilterPattern.MatchString(filter) {
		return fmt.Errorf("ogiltigt filter: endast BPF-uttryck tillåts (t.ex. \"port 443\", \"host 10.0.0.5 and tcp\")")
	}
	return nil
}

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

	// BPF-filtret skickas vidare till en tcpdump som körs som ROOT i
	// hjälptjänsten. Det går aldrig via ett skal, men tcpdump tolkar ett
	// argument som börjar med "-" som en FLAGGA — och getopt tillåter
	// sammanskriven form, så ett enda argument som "-w/etc/rsyslog.d/x.conf"
	// räcker för att skriva en godtycklig fil som root och därmed kringgå
	// hela privilegieseparationen (upptäckt vid kodgranskning 2026-08-25).
	// Validera därför strikt här, och en gång till i runnern.
	if err := validateBPFFilter(req.Filter); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
// tcpdumpHelperMu: samma serialisering och samma anledning som
// nmapHelperMu ovan.
var tcpdumpHelperMu sync.Mutex

func runTcpdumpViaHelperService(ctx context.Context, iface, filter string, packetCount, durationSec int) (string, error) {
	tcpdumpHelperMu.Lock()
	defer tcpdumpHelperMu.Unlock()

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

	// Utan tls-crypt-nyckeln kommer profilen inte in på en härdad server:
	// servern kastar paket som saknar den innan TLS ens börjar. Ett fel här
	// måste därför stoppa utfärdandet, inte ge en profil som tyst inte
	// fungerar.
	tlsCryptKey, err := s.engine.GetOpenVPNTLSCryptKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ovpnFile, err := openvpn.GenerateClientConfig(&cfgCopy, certPEM, keyPEM, tlsCryptKey)
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

// auditUser plockar ut den FAKTISKT inloggade användaren ur request-
// contexten för revisionsloggen. Tidigare skickades strängen "master"
// hårdkodat från apply/confirm/rollback — med flera administratörskonton
// (Fas 8) blev revisionshistoriken därmed obrukbar, eftersom varje
// ändring tillskrevs "master" oavsett vem som faktiskt gjorde den.
func auditUser(r *http.Request) string {
	if u, _ := r.Context().Value(ctxKeyUsername).(string); u != "" {
		return u
	}
	return "okänd"
}

// detachedApplyContext ger en konfigurationsapplicering en EGEN livstid,
// frikopplad från HTTP-requestens context.
//
// Upptäckt vid kodgranskning 2026-08-20: apply/rollback ärvde r.Context(),
// som avbryts så fort klienten kopplar ner eller serverns WriteTimeout
// löper ut. Mitt i ett apply innebär det att exec.CommandContext dödar
// nft/systemctl HALVVÄGS — brandväggen kan då bli stående i ett delvis
// applicerat tillstånd (t.ex. nya nftables-regler men gammal DHCP/IDS)
// bara för att en webbläsarflik stängdes. En applicering måste få köra
// klart och sedan antingen bekräftas eller rullas tillbaka av Safe
// Apply-timern; den får aldrig avbrytas mitt i av klientsidan.
func detachedApplyContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

func (s *Server) handleApplyConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := detachedApplyContext()
	defer cancel()
	if err := s.engine.ApplyCandidate(ctx, auditUser(r)); err != nil {
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
	ctx, cancel := detachedApplyContext()
	defer cancel()
	if err := s.engine.ConfirmConfig(ctx, auditUser(r)); err != nil {
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
	ctx, cancel := detachedApplyContext()
	defer cancel()
	if err := s.engine.RollbackConfig(ctx, auditUser(r)); err != nil {
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
// handleDHCPLeases returnerar aktuella DHCP-klienter (Kea-utlåningar)
// berikade med gränssnitt/zon (se Engine.GetDHCPLeases). Läsrättighet
// räcker (admin+viewer) — det är ren diagnostik.
func (s *Server) handleDHCPLeases(w http.ResponseWriter, r *http.Request) {
	leases, err := s.engine.GetDHCPLeases()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(leases)
}

// handleDeleteDHCPLease frigör en aktiv DHCP-lease (admin-only) via Kea:s
// lease4-del. Body: {"ip":"10.5.5.123"}.
func (s *Server) handleDeleteDHCPLease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		http.Error(w, "IP saknas", http.StatusBadRequest)
		return
	}
	if err := s.engine.DeleteDHCPLease(r.Context(), req.IP); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "ip": req.IP})
}

// handleNotifications GET returnerar notifieringskonfigurationen (SMTP-lösen
// maskerat); POST/PUT sparar den (admin-only). Tomt lösenord vid spara behåller
// det redan sparade.
func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := s.engine.GetNotificationConfig()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		hasPass := cfg.SMTPPass != ""
		cfg.SMTPPass = "" // maskera — skickas aldrig ut
		w.Header().Set("Content-Type", "application/json")
		out, _ := json.Marshal(cfg)
		var m map[string]interface{}
		_ = json.Unmarshal(out, &m)
		m["has_password"] = hasPass
		_ = json.NewEncoder(w).Encode(m)
	case http.MethodPost, http.MethodPut:
		if role, _ := r.Context().Value(ctxKeyRole).(string); role != string(store.RoleAdmin) {
			http.Error(w, "Forbidden: kräver admin-roll", http.StatusForbidden)
			return
		}
		var cfg config.NotificationConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		if cfg.SMTPPass == "" { // behåll befintligt lösen om GUI:t inte skickade nytt
			if saved, err := s.engine.GetNotificationConfig(); err == nil {
				cfg.SMTPPass = saved.SMTPPass
			}
		}
		if err := s.engine.SaveNotificationConfig(&cfg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleNotificationsTest skickar ett testmejl med den medskickade
// konfigurationen (admin-only).
func (s *Server) handleNotificationsTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var cfg config.NotificationConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}
	if err := s.engine.SendTestNotification(&cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

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
// firewallLogWindowRe begränsar vad som får skickas till journalctl --since.
//
// Värdet kommer från en HTTP-parameter och hamnar i ett kommandoargument.
// Bara "<tal><enhet>" godtas, med enheten m/h/d — inget annat, och aldrig
// journalctls fria datumsyntax.
var firewallLogWindowRe = regexp.MustCompile(`^[0-9]{1,4}[mhd]$`)

// firewallLogMaxEntries är taket på hur många poster ETT svar innehåller.
//
// Behövs eftersom tidsfönstret kan spänna över dygn: brandväggen loggar i
// storleksordningen hundratusen rader per dygn, och att skicka dem till
// GUI:t skulle låsa både agenten och klienten. Nås taket returneras de
// NYASTE posterna, och svaret säger att det klipptes.
const firewallLogMaxEntries = 3000

// firewallLogScanLimit är hur många journalrader vi ber journald om. Taket
// ovan gäller POSTER vi behåller; marginalen däremellan finns för att kunna
// avgöra om det fanns mer att visa (truncated) och för rader som inte blir
// någon post (t.ex. saknad SRC=).
const firewallLogScanLimit = firewallLogMaxEntries + 500

// ParseFirewallLogWindow läser brandväggsloggen för ett tidsfönster.
//
// window är t.ex. "15m", "6h", "2d". Tomt värde ger de senaste 500 raderna,
// vilket var beteendet innan tidsfiltret fanns.
//
// Fram till 2026-08-26 hämtades ALLTID exakt de 500 senaste raderna. Med den
// loggvolym brandväggen numera producerar (~680 rader/minut) motsvarade det
// bara omkring 45 sekunder — man kunde inte titta på något som hänt för fem
// minuter sedan.
func parseFirewallLogWindow(window string) (entries []config.FirewallLogEntry, truncated bool) {
	args := []string{"-k", "--no-pager", "-o", "short-iso", "-g", "SH-(ACCEPT|DENY)-"}
	if window != "" && firewallLogWindowRe.MatchString(window) {
		// -n TILLSAMMANS med --since är det som gör långa fönster billiga:
		// journald söker bakifrån och slutar när den har så många träffar,
		// i stället för att vi läser hela perioden och kastar nästan allt.
		// Utan den här raden skannade ett 7-dagarsfönster hela journalen vid
		// VARJE poll från loggvyn — uppmätt 2026-08-29: fem samtidiga
		// journalctl-processer som aldrig blev klara, agenten på 134 % CPU och
		// en loggvy som bara visade tomt eftersom inget svar hann fram.
		//
		// Marginalen mot taket finns för att kunna sätta `truncated`: får vi
		// fler poster än taket vet vi att det fanns mer att visa.
		args = append(args, "--since", "-"+window, "-n", strconv.Itoa(firewallLogScanLimit))
	} else {
		args = append(args, "-n", "500")
	}

	// Journalen läses STRÖMMANDE, inte via CombinedOutput. Ett långt fönster
	// (--since -2d) på en brandvägg som loggar varje ACCEPT/DENY kan ge
	// gigabyte, och CombinedOutput höll hela utdatan i minnet — varpå
	// string(out) tog en ANDRA full kopia. Toppminnet blev 2x journalutdatan
	// i en process som dessutom är undantagen OOM-killaren
	// (OOMScoreAdjust=-500), så kärnan sköt ner Suricata i stället och den
	// hamnade i omstartsloop. Uppmätt 2026-08-29: 3,5 GB anon-rss / 8,7 GB
	// virtuellt på en enda loggsökning.
	//
	// Taket nedan (firewallLogMaxEntries) fanns redan, men applicerades
	// FÖRST EFTER att allt låg i RAM — det begränsade svaret, inte
	// inläsningen. Nu hålls bara de senaste posterna kvar medan vi läser.
	cmd := exec.Command("journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return []config.FirewallLogEntry{}, false
	}
	if err := cmd.Start(); err != nil {
		return []config.FirewallLogEntry{}, false
	}
	// Processen måste alltid skördas, och stdout dräneras, annars blir
	// journalctl kvar som zombie om vi lämnar loopen tidigt.
	defer func() {
		_, _ = io.Copy(io.Discard, stdout)
		_ = cmd.Wait()
	}()

	scanner := bufio.NewScanner(stdout)
	// nftables-loggrader är långa (MAC-fältet ensamt är 14 oktetter), men
	// aldrig i närheten av 1 MB. Default-bufferten på 64 kB räcker; taket
	// finns bara så att en oväntat lång rad avbryter läsningen i stället för
	// att växa fritt.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	ring := make([]config.FirewallLogEntry, 0, firewallLogMaxEntries)
	head := 0
	full := false

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
			// Äkta cirkulär buffert: skrivpositionen flyttas, inte innehållet.
			// Första försöket sköt i stället hela bufferten ett steg med
			// copy(entries, entries[1:]) för varje post efter de första 3000 —
			// en memmove på 2 999 structar PER RAD. På ett kort fönster märks
			// det inte (färre poster än taket), men på ett långt blev det
			// O(n*tak) och pinnade en kärna i minuter.
			if !full {
				ring = append(ring, entry)
				if len(ring) == firewallLogMaxEntries {
					full = true
					head = 0
				}
			} else {
				ring[head] = entry
				head = (head + 1) % firewallLogMaxEntries
				truncated = true
			}
		}
	}

	// Packa upp ringen i kronologisk ordning: äldsta posten ligger på head.
	if !full {
		return ring, truncated
	}
	entries = make([]config.FirewallLogEntry, 0, firewallLogMaxEntries)
	entries = append(entries, ring[head:]...)
	entries = append(entries, ring[:head]...)
	return entries, truncated
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

// handleTimezones listar de tidszoner servern känner till, plus vilken som är
// aktiv just nu. GUI:t behöver båda: listan för väljaren, och den aktiva för
// att kunna visa vad som FAKTISKT gäller på servern — som kan skilja sig från
// konfigurationens värde om appliceringen misslyckats (då finns även en
// varning under Tjänster).
func (s *Server) handleTimezones(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"current":   timezone.Current(),
		"available": timezone.Available(),
	})
}

// handleImplicitPolicies beskriver de regler adaptern genererar själv
// (loopback, etablerade anslutningar, VPN-portar, WAN-drop, DNS, NTP).
//
// De finns inte som Policy-objekt och gick därför inte att se någonstans i
// GUI:t — man kunde inte svara på "vad är öppet mot brandväggen själv?" utan
// SSH. Beskrivningarna räknas fram ur RUNNING-configen, alltså det som
// faktiskt gäller, inte ur kandidaten.
func (s *Server) handleImplicitPolicies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(nftables.DescribeImplicitRules(s.engine.GetRunningConfig()))
}
