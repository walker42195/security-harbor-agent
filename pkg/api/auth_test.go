package api

import "testing"

func TestPerUsernameLockoutSurvivesIPRotation(t *testing.T) {
	a := NewAuthManager()

	// Simulera en angripare som roterar käll-IP mot SAMMA användarnamn -
	// den gamla, rent IP-baserade spärren hade inte fångat detta alls.
	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"}
	for _, ip := range ips {
		if a.IsLockedOut(ip, "master") {
			t.Fatalf("förväntade inte lockout ännu (ip=%s)", ip)
		}
		a.RecordFailedAttempt(ip, "master")
	}

	if !a.IsLockedOut("6.6.6.6", "master") {
		t.Fatal("förväntade att 'master' är låst efter 5 misslyckade försök oavsett käll-IP")
	}
	// En ANNAN användare från samma pool av IP:n ska INTE vara påverkad.
	if a.IsLockedOut("6.6.6.6", "annan-anvandare") {
		t.Fatal("en annan användares lockout ska inte påverkas")
	}
}

func TestPerIPLockoutStillWorks(t *testing.T) {
	a := NewAuthManager()

	for i := 0; i < 5; i++ {
		a.RecordFailedAttempt("9.9.9.9", "user1")
	}
	// Samma IP mot en HELT ANNAN username ska ändå vara låst (IP-spärren
	// gäller oavsett vilket username som prövas från den IP:n).
	if !a.IsLockedOut("9.9.9.9", "user2") {
		t.Fatal("förväntade IP-baserad lockout att gälla oavsett username")
	}
}
