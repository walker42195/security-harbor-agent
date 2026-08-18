package store

import (
	"os"
	"testing"
)

func newTestUserStore(t *testing.T) *UserStore {
	t.Helper()
	dir := t.TempDir()
	crypto, err := NewCryptoHandler([]byte("TestMasterKeyExactly32BytesLong!"))
	if err != nil {
		t.Fatalf("NewCryptoHandler misslyckades: %v", err)
	}
	us, err := newUserStore(dir, crypto)
	if err != nil {
		t.Fatalf("newUserStore misslyckades: %v", err)
	}
	return us
}

func TestUserStoreSeedsDefaultAdmin(t *testing.T) {
	us := newTestUserStore(t)
	user, err := us.VerifyCredentials("master", "SecurityHarbor2026!")
	if err != nil {
		t.Fatalf("förväntade lyckad inloggning mot seedad standardanvändare: %v", err)
	}
	if user.Role != RoleAdmin {
		t.Errorf("förväntade admin-roll för seedad användare, fick %q", user.Role)
	}
}

func TestUserStorePersistsAcrossReload(t *testing.T) {
	dir := os.TempDir() + "/sh-userstore-test"
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("MkdirAll misslyckades: %v", err)
	}
	defer os.RemoveAll(dir)

	crypto, err := NewCryptoHandler([]byte("TestMasterKeyExactly32BytesLong!"))
	if err != nil {
		t.Fatalf("NewCryptoHandler misslyckades: %v", err)
	}

	us1, err := newUserStore(dir, crypto)
	if err != nil {
		t.Fatalf("newUserStore misslyckades: %v", err)
	}
	if _, err := us1.CreateUser("viewer1", "viewerpassword1", RoleViewer); err != nil {
		t.Fatalf("CreateUser misslyckades: %v", err)
	}

	us2, err := newUserStore(dir, crypto)
	if err != nil {
		t.Fatalf("newUserStore (omladdning) misslyckades: %v", err)
	}
	if _, err := us2.VerifyCredentials("viewer1", "viewerpassword1"); err != nil {
		t.Errorf("förväntade att den skapade användaren finns kvar efter omladdning: %v", err)
	}
}

func TestCreateUserRejectsDuplicateUsername(t *testing.T) {
	us := newTestUserStore(t)
	if _, err := us.CreateUser("someone", "password123", RoleViewer); err != nil {
		t.Fatalf("första CreateUser misslyckades: %v", err)
	}
	if _, err := us.CreateUser("someone", "otherpassword", RoleAdmin); err == nil {
		t.Errorf("förväntade fel vid dublett-användarnamn, men lyckades")
	}
}

func TestCreateUserRejectsShortPassword(t *testing.T) {
	us := newTestUserStore(t)
	if _, err := us.CreateUser("shortpw", "1234567", RoleViewer); err == nil {
		t.Errorf("förväntade fel för lösenord kortare än 8 tecken")
	}
}

// TestDeleteUserProtectsLastAdmin skyddar mot att brandväggen blir
// omöjlig att administrera — om den sista admin-användaren kunde tas
// bort skulle ingen längre kunna ändra konfigurationen alls.
func TestDeleteUserProtectsLastAdmin(t *testing.T) {
	us := newTestUserStore(t)
	users := us.ListUsers()
	if len(users) != 1 {
		t.Fatalf("förväntade exakt en seedad användare, fick %d", len(users))
	}
	masterID := users[0].ID

	if err := us.DeleteUser(masterID); err == nil {
		t.Errorf("förväntade fel vid försök att ta bort den enda admin-användaren")
	}

	// Men OK att ta bort en admin om det finns en ANNAN admin kvar.
	other, err := us.CreateUser("otheradmin", "adminpassword1", RoleAdmin)
	if err != nil {
		t.Fatalf("CreateUser misslyckades: %v", err)
	}
	if err := us.DeleteUser(masterID); err != nil {
		t.Errorf("förväntade lyckad borttagning när en annan admin finns kvar: %v", err)
	}
	if err := us.DeleteUser(other.ID); err == nil {
		t.Errorf("förväntade fel vid försök att ta bort den nu SISTA admin-användaren")
	}
}

func TestChangePasswordRequiresCorrectCurrentPassword(t *testing.T) {
	us := newTestUserStore(t)
	users := us.ListUsers()
	masterID := users[0].ID

	if err := us.VerifyPasswordByID(masterID, "fel lösenord"); err == nil {
		t.Errorf("förväntade fel vid fel nuvarande lösenord")
	}
	if err := us.VerifyPasswordByID(masterID, "SecurityHarbor2026!"); err != nil {
		t.Errorf("förväntade lyckad verifiering med rätt lösenord: %v", err)
	}

	if err := us.ChangePassword(masterID, "nyttlosenord123"); err != nil {
		t.Fatalf("ChangePassword misslyckades: %v", err)
	}
	if _, err := us.VerifyCredentials("master", "SecurityHarbor2026!"); err == nil {
		t.Errorf("det gamla lösenordet ska inte längre fungera efter byte")
	}
	if _, err := us.VerifyCredentials("master", "nyttlosenord123"); err != nil {
		t.Errorf("det nya lösenordet borde fungera: %v", err)
	}
}
