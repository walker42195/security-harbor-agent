package api

import (
	"testing"
	"time"
)

// Regression: försöksräknare med 1-4 misslyckade försök städades ALDRIG
// (pruneLocked tog bara bort poster där count == 0, men en post når 0 bara
// genom att passera 5 och bli en lockout). Eftersom nyckeln i userAttempts
// är det angriparstyrda användarnamnet kunde map:en växa obegränsat.
func TestAttemptCountersAreEventuallyPruned(t *testing.T) {
	a := NewAuthManager("")

	for i := 0; i < 200; i++ {
		a.RecordFailedAttempt("10.0.0.1", string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	if len(a.userAttempts) == 0 {
		t.Fatal("förväntade poster i userAttempts efter misslyckade försök")
	}

	// Åldra alla poster förbi TTL:en och trigga en städning.
	a.mu.Lock()
	for k, c := range a.userAttempts {
		c.last = time.Now().Add(-2 * attemptTTL)
		a.userAttempts[k] = c
	}
	for k, c := range a.ipAttempts {
		c.last = time.Now().Add(-2 * attemptTTL)
		a.ipAttempts[k] = c
	}
	a.pruneLocked()
	nUser, nIP := len(a.userAttempts), len(a.ipAttempts)
	a.mu.Unlock()

	if nUser != 0 || nIP != 0 {
		t.Fatalf("gamla försöksräknare städades inte: userAttempts=%d ipAttempts=%d", nUser, nIP)
	}
}

// Spärren måste fortfarande slå till efter 5 försök.
func TestLockoutStillTriggers(t *testing.T) {
	a := NewAuthManager("")
	for i := 0; i < 5; i++ {
		a.RecordFailedAttempt("10.0.0.2", "admin")
	}
	if !a.IsLockedOut("10.0.0.2", "nagon-annan") {
		t.Error("IP-spärren utlöstes inte efter 5 försök")
	}
	if !a.IsLockedOut("192.0.2.9", "admin") {
		t.Error("användarnamnsspärren utlöstes inte efter 5 försök")
	}
}

// Sessioner måste gå att återkalla — utloggning och kontoändringar ska bita.
func TestSessionRevocation(t *testing.T) {
	a := NewAuthManager("")
	tok1, _ := a.CreateSession("alice", "admin", time.Hour)
	tok2, _ := a.CreateSession("alice", "admin", time.Hour)
	tokBob, _ := a.CreateSession("bob", "viewer", time.Hour)

	// Utloggning tar bara den egna token.
	a.DeleteSession(tok1)
	if _, _, err := a.ValidateToken(tok1); err == nil {
		t.Error("utloggad token är fortfarande giltig")
	}
	if _, _, err := a.ValidateToken(tok2); err != nil {
		t.Error("utloggning tog fel session")
	}

	// Radering/lösenordsåterställning tar alla för kontot, men inte andras.
	if n := a.DeleteSessionsForUser("alice"); n != 1 {
		t.Errorf("förväntade 1 borttagen session, fick %d", n)
	}
	if _, _, err := a.ValidateToken(tok2); err == nil {
		t.Error("sessionen levde vidare efter DeleteSessionsForUser")
	}
	if _, _, err := a.ValidateToken(tokBob); err != nil {
		t.Error("annan användares session togs bort felaktigt")
	}
}
