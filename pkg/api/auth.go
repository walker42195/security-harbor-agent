package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
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

	// persistPath är filen (i data-dir) där aktiva sessioner sparas så att en
	// inloggning ÖVERLEVER en omstart av agenten. Utan detta töms sessions-
	// mappen vid varje omstart → alla tokens blir ogiltiga, vilket bl.a.
	// loggade ut användaren vid varje uppgradering och fick GUI:ts
	// uppgraderings-återkoppling att aldrig upptäcka att agenten kom tillbaka
	// (getSystemStatus gav 401). Tom sträng = ingen persistens (t.ex. i tester).
	persistPath string

	ipAttempts   map[string]attemptCounter
	ipLockouts   map[string]time.Time
	userAttempts map[string]attemptCounter
	userLockouts map[string]time.Time
}

// attemptCounter är en försöksräknare MED tidsstämpel. Tidsstämpeln finns
// för att posten ska kunna städas bort — se pruneLocked.
type attemptCounter struct {
	count int
	last  time.Time
}

// attemptTTL är hur länge en försöksräknare utan aktiv spärr är
// meningsfull. Efter det nollställs den (och posten släpps ur map:en).
// Samma storleksordning som lockoutens 15 minuter.
const attemptTTL = 15 * time.Minute

func NewAuthManager(persistPath string) *AuthManager {
	a := &AuthManager{
		sessions:     make(map[string]TokenSession),
		persistPath:  persistPath,
		ipAttempts:   make(map[string]attemptCounter),
		ipLockouts:   make(map[string]time.Time),
		userAttempts: make(map[string]attemptCounter),
		userLockouts: make(map[string]time.Time),
	}
	a.loadSessions()
	return a
}

// loadSessions läser in tidigare sparade, ej utgångna sessioner från disk.
// Anropas en gång vid start. Fel (saknad/trasig fil) ignoreras — då börjar
// agenten bara utan aktiva sessioner, precis som tidigare.
func (a *AuthManager) loadSessions() {
	if a.persistPath == "" {
		return
	}
	data, err := os.ReadFile(a.persistPath)
	if err != nil {
		return
	}
	var stored map[string]TokenSession
	if json.Unmarshal(data, &stored) != nil {
		return
	}
	now := time.Now()
	for tok, s := range stored {
		if now.Before(s.ExpiresAt) {
			a.sessions[tok] = s
		}
	}
}

// saveSessionsLocked skriver de aktiva sessionerna till disk (atomiskt via
// temp + rename). Anroparen MÅSTE hålla a.mu. Filen innehåller aktiva
// bearer-tokens och skrivs 0600 i den redan 0700-skyddade data-katalogen (som
// dessutom innehåller master-nyckel och TLS-nyckel — ingen ny exponering).
func (a *AuthManager) saveSessionsLocked() {
	if a.persistPath == "" {
		return
	}
	data, err := json.Marshal(a.sessions)
	if err != nil {
		return
	}
	tmp := a.persistPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, a.persistPath)
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

func recordFailedAttemptLocked(attempts map[string]attemptCounter, lockouts map[string]time.Time, key string) {
	now := time.Now()
	c := attempts[key]
	// En räknare som legat orörd längre än attemptTTL börjar om — annars
	// skulle enstaka spridda felslag över dygn ackumulera till en spärr.
	if !c.last.IsZero() && now.Sub(c.last) > attemptTTL {
		c.count = 0
	}
	c.count++
	c.last = now
	if c.count >= 5 {
		lockouts[key] = now.Add(15 * time.Minute)
		delete(attempts, key)
		return
	}
	attempts[key] = c
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
	sessionsChanged := false
	for token, sess := range a.sessions {
		if now.After(sess.ExpiresAt) {
			delete(a.sessions, token)
			sessionsChanged = true
		}
	}
	// Skriv tillbaka direkt när något faktiskt togs bort, så filen på disk
	// inte fortsätter innehålla utgångna tokens tills nästa inloggning.
	// (Ofarligt även utan — loadSessions filtrerar på utgång — men filen ska
	// spegla minnet.)
	if sessionsChanged {
		a.saveSessionsLocked()
	}
	for _, m := range []map[string]time.Time{a.ipLockouts, a.userLockouts} {
		for key, until := range m {
			if now.After(until) {
				delete(m, key)
			}
		}
	}
	// Försöksräknare släpps när de blivit för gamla för att betyda något.
	//
	// Kodgranskning 2026-08-25: den tidigare versionen tog bara bort poster
	// där räknaren var 0, men en post når bara 0 genom att passera 5 försök
	// (då sätts en lockout). En post som stannade på 1-4 försök raderades
	// därför ALDRIG. Eftersom nyckeln i userAttempts är det ANVÄNDARNAMN
	// klienten skickar in kunde en angripare låta map:en växa obegränsat —
	// exakt den minnesutmattning kommentaren ovan sade sig ha åtgärdat.
	// Nu styr tidsstämpeln städningen, oberoende av räknarvärdet.
	for _, m := range []map[string]attemptCounter{a.ipAttempts, a.userAttempts} {
		for key, c := range m {
			if now.Sub(c.last) > attemptTTL {
				delete(m, key)
			}
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
	a.saveSessionsLocked() // överlev en omstart av agenten

	return token, nil
}

// DeleteSession ogiltigförklarar EN session (utloggning). Okänd token är
// inte ett fel — utloggning ska alltid "lyckas" ur klientens perspektiv.
func (a *AuthManager) DeleteSession(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	delete(a.sessions, token)
	a.pruneLocked()
	a.saveSessionsLocked()
}

// DeleteSessionsForUser ogiltigförklarar ALLA aktiva sessioner för en
// användare. Måste anropas när kontot raderas eller när lösenordet byts/
// återställs.
//
// Kodgranskning 2026-08-25: utan detta fortsatte en raderad användares
// token att fungera i upp till 24 timmar, och "byt lösenord efter intrång"
// gjorde ingen nytta alls mot en angripare som redan hade en giltig token.
// Returnerar antalet borttagna sessioner (för revisionsloggen).
func (a *AuthManager) DeleteSessionsForUser(username string) int {
	return a.DeleteSessionsForUserExcept(username, "")
}

// DeleteSessionsForUserExcept är samma sak men sparar EN token — används vid
// eget lösenordsbyte, där administratören inte ska loggas ut av sin egen
// åtgärd men alla andra sessioner för kontot ska dö.
func (a *AuthManager) DeleteSessionsForUserExcept(username, keepToken string) int {
	a.mu.Lock()
	defer a.mu.Unlock()

	removed := 0
	for token, sess := range a.sessions {
		if token == keepToken {
			continue
		}
		if strings.EqualFold(sess.User, username) {
			delete(a.sessions, token)
			removed++
		}
	}
	if removed > 0 {
		a.saveSessionsLocked()
	}
	return removed
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
