package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type TokenSession struct {
	Token     string
	User      string
	Role      string // "admin" eller "viewer" (Fas 8 — flera användare/roller)
	ExpiresAt time.Time
}

// AuthManager håller BÅDE per-IP OCH per-användarnamn misslyckade
// inloggningsförsök/lockouts, som två oberoende, parallella spärrar (Fas
// 12 — den ursprungliga per-IP-spärren ensam går att kringgå genom att
// rotera källa-IP mot ETT specifikt användarnamn; per-användarnamn-spärren
// täcker det fallet oavsett hur många IP:n angriparen använder). Ett
// inloggningsförsök blockeras om ANTINGEN käll-IP:t ELLER användarnamnet
// för tillfället är låst.
type AuthManager struct {
	mu       sync.RWMutex
	sessions map[string]TokenSession

	ipAttempts   map[string]int
	ipLockouts   map[string]time.Time
	userAttempts map[string]int
	userLockouts map[string]time.Time
}

func NewAuthManager() *AuthManager {
	return &AuthManager{
		sessions:     make(map[string]TokenSession),
		ipAttempts:   make(map[string]int),
		ipLockouts:   make(map[string]time.Time),
		userAttempts: make(map[string]int),
		userLockouts: make(map[string]time.Time),
	}
}

func isLockedOutLocked(lockouts map[string]time.Time, key string) bool {
	until, ok := lockouts[key]
	if !ok {
		return false
	}
	return !time.Now().After(until)
}

// IsLockedOut returnerar true om KÄLL-IP:T ELLER ANVÄNDARNAMNET (eller
// båda) för tillfället är låst.
func (a *AuthManager) IsLockedOut(ip, username string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return isLockedOutLocked(a.ipLockouts, ip) || isLockedOutLocked(a.userLockouts, username)
}

func recordFailedAttemptLocked(attempts map[string]int, lockouts map[string]time.Time, key string) {
	attempts[key]++
	if attempts[key] >= 5 {
		lockouts[key] = time.Now().Add(15 * time.Minute)
		attempts[key] = 0
	}
}

// pruneLocked rensar utgångna sessioner och utgångna lockout-poster.
//
// Upptäckt vid kodgranskning 2026-08-20: inget av de fyra map:arna
// städades någonsin. sessions växte med en post per inloggning och
// behöll dem för evigt (utgångna tokens avvisades korrekt, men posten låg
// kvar). Allvarligare var userAttempts/userLockouts: nyckeln är det
// ANVÄNDARNAMN klienten skickar in, så en angripare kunde skicka
// misslyckade inloggningar med ett nytt påhittat användarnamn varje gång
// och få agenten att allokera obegränsat med minne — en enkel
// minnesutmattnings-DoS mot en brandvägg som ska vara det som står emot
// sådant. Städningen körs vid inloggning/tokenvalidering, alltså utan en
// egen bakgrundsgoroutine att hålla reda på.
func (a *AuthManager) pruneLocked() {
	now := time.Now()
	for token, sess := range a.sessions {
		if now.After(sess.ExpiresAt) {
			delete(a.sessions, token)
		}
	}
	for _, m := range []map[string]time.Time{a.ipLockouts, a.userLockouts} {
		for key, until := range m {
			if now.After(until) {
				delete(m, key)
			}
		}
	}
	// Försöksräknare utan en aktiv lockout är bara meningsfulla i
	// anslutning till pågående försök — släpp dem när spärren gått ut.
	for key := range a.ipAttempts {
		if _, locked := a.ipLockouts[key]; !locked && a.ipAttempts[key] == 0 {
			delete(a.ipAttempts, key)
		}
	}
	for key := range a.userAttempts {
		if _, locked := a.userLockouts[key]; !locked && a.userAttempts[key] == 0 {
			delete(a.userAttempts, key)
		}
	}
}

// RecordFailedAttempt räknar upp BÅDA räknarna (käll-IP och användarnamn)
// oberoende av varandra — vardera låser efter 5 försök i 15 minuter.
func (a *AuthManager) RecordFailedAttempt(ip, username string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.pruneLocked()
	recordFailedAttemptLocked(a.ipAttempts, a.ipLockouts, ip)
	recordFailedAttemptLocked(a.userAttempts, a.userLockouts, username)
}

func (a *AuthManager) CreateSession(user, role string, duration time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	a.mu.Lock()
	defer a.mu.Unlock()

	a.pruneLocked()
	a.sessions[token] = TokenSession{
		Token:     token,
		User:      user,
		Role:      role,
		ExpiresAt: time.Now().Add(duration),
	}

	return token, nil
}

// ValidateToken returnerar (användarnamn, roll, fel).
func (a *AuthManager) ValidateToken(token string) (string, string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	session, ok := a.sessions[token]
	if !ok {
		return "", "", fmt.Errorf("ogiltig token")
	}

	if time.Now().After(session.ExpiresAt) {
		return "", "", fmt.Errorf("token har gått ut")
	}

	return session.User, session.Role, nil
}
