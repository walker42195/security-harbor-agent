// Fas 8 — flera administrationsanvändare med roller ("admin" kan ändra
// allt, "viewer" kan bara läsa). Ersätter den tidigare hårdkodade
// enskilda admin/lösenord-strängen som stod inbränd i källkoden
// (pkg/api/server.go innan detta) — den gick inte att rotera eller
// bygga vidare på utan en kodändring + omdeploy.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Role är den enda uppsättning roller som stöds — "admin" (fullständig
// åtkomst) eller "viewer" (skrivskyddad, se authMiddlewareAdmin i
// pkg/api/server.go för vilka endpoints som kräver admin).
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleViewer Role = "viewer"
)

// AdminUser representerar en administrationsanvändare. PasswordHash
// (bcrypt) lämnar ALDRIG denna struct över API:t — se ToPublic.
type AdminUser struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Role         Role   `json:"role"`
	CreatedAt    string `json:"created_at"`
}

// PublicUser är den säkra representationen som faktiskt skickas över API:t.
type PublicUser struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Role      Role   `json:"role"`
	CreatedAt string `json:"created_at"`
}

func (u AdminUser) ToPublic() PublicUser {
	return PublicUser{ID: u.ID, Username: u.Username, Role: u.Role, CreatedAt: u.CreatedAt}
}

// UserStore hanterar administrationsanvändare, krypterade at rest (samma
// CryptoHandler/AES-256-GCM-mönster som WireGuard/OpenVPN-nycklarna) i en
// egen fil, separat från running/candidate.json.
type UserStore struct {
	mu      sync.RWMutex
	baseDir string
	crypto  *CryptoHandler
	users   []AdminUser
}

func newUserStore(baseDir string, crypto *CryptoHandler) (*UserStore, error) {
	us := &UserStore{baseDir: baseDir, crypto: crypto}
	if err := us.load(); err != nil {
		return nil, err
	}
	return us, nil
}

func (us *UserStore) path() string {
	return filepath.Join(us.baseDir, "users.enc")
}

func (us *UserStore) load() error {
	data, err := os.ReadFile(us.path())
	if err != nil {
		if os.IsNotExist(err) {
			// Första start: seeda en enda admin-användare med det
			// tidigare hårdkodade default-lösenordet, så befintliga
			// installationer inte blir utelåsta av denna migrering.
			// Byt lösenord direkt via GUI:t (Settings) efter första
			// inloggning.
			hash, hashErr := bcrypt.GenerateFromPassword([]byte("SecurityHarbor2026!"), bcrypt.DefaultCost)
			if hashErr != nil {
				return hashErr
			}
			us.users = []AdminUser{{
				ID:           "usr_master",
				Username:     "master",
				PasswordHash: string(hash),
				Role:         RoleAdmin,
				CreatedAt:    time.Now().Format(time.RFC3339),
			}}
			return us.saveLocked()
		}
		return err
	}

	plain, err := us.crypto.Decrypt(data)
	if err != nil {
		return fmt.Errorf("misslyckades dekryptera användarfilen: %w", err)
	}
	return json.Unmarshal(plain, &us.users)
}

func (us *UserStore) saveLocked() error {
	plain, err := json.MarshalIndent(us.users, "", "  ")
	if err != nil {
		return err
	}
	cipherBytes, err := us.crypto.Encrypt(plain)
	if err != nil {
		return fmt.Errorf("misslyckades kryptera användarfilen: %w", err)
	}
	return os.WriteFile(us.path(), cipherBytes, 0600)
}

// VerifyCredentials kontrollerar användarnamn/lösenord och returnerar
// användaren (utan hash) vid lyckad inloggning.
func (us *UserStore) VerifyCredentials(username, password string) (*PublicUser, error) {
	us.mu.RLock()
	defer us.mu.RUnlock()

	for _, u := range us.users {
		if !strings.EqualFold(u.Username, username) {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
			return nil, fmt.Errorf("fel lösenord")
		}
		pub := u.ToPublic()
		return &pub, nil
	}
	return nil, fmt.Errorf("okänt användarnamn")
}

// ListUsers returnerar alla användare utan lösenordshashar.
func (us *UserStore) ListUsers() []PublicUser {
	us.mu.RLock()
	defer us.mu.RUnlock()

	out := make([]PublicUser, 0, len(us.users))
	for _, u := range us.users {
		out = append(out, u.ToPublic())
	}
	return out
}

// CreateUser lägger till en ny administrationsanvändare.
func (us *UserStore) CreateUser(username, password string, role Role) (*PublicUser, error) {
	if strings.TrimSpace(username) == "" {
		return nil, fmt.Errorf("användarnamn saknas")
	}
	if len(password) < 8 {
		return nil, fmt.Errorf("lösenordet måste vara minst 8 tecken")
	}
	if role != RoleAdmin && role != RoleViewer {
		return nil, fmt.Errorf("ogiltig roll %q", role)
	}

	us.mu.Lock()
	defer us.mu.Unlock()

	for _, u := range us.users {
		if strings.EqualFold(u.Username, username) {
			return nil, fmt.Errorf("användarnamnet %q finns redan", username)
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	newUser := AdminUser{
		ID:           fmt.Sprintf("usr_%d", time.Now().UnixNano()),
		Username:     username,
		PasswordHash: string(hash),
		Role:         role,
		CreatedAt:    time.Now().Format(time.RFC3339),
	}
	us.users = append(us.users, newUser)
	if err := us.saveLocked(); err != nil {
		return nil, err
	}
	pub := newUser.ToPublic()
	return &pub, nil
}

// DeleteUser tar bort en användare. Vägrar ta bort den SISTA admin-
// användaren — annars går det inte längre att administrera brandväggen
// alls (samma skydd som "Critical"-policies i GUI:t, t.ex. SSH-regeln).
func (us *UserStore) DeleteUser(id string) error {
	us.mu.Lock()
	defer us.mu.Unlock()

	idx := -1
	for i, u := range us.users {
		if u.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("användaren hittades inte")
	}

	if us.users[idx].Role == RoleAdmin {
		adminCount := 0
		for _, u := range us.users {
			if u.Role == RoleAdmin {
				adminCount++
			}
		}
		if adminCount <= 1 {
			return fmt.Errorf("kan inte ta bort den sista admin-användaren")
		}
	}

	us.users = append(us.users[:idx], us.users[idx+1:]...)
	return us.saveLocked()
}

// ChangePassword byter lösenord för en given användare (matchad på ID).
func (us *UserStore) ChangePassword(id, newPassword string) error {
	if len(newPassword) < 8 {
		return fmt.Errorf("lösenordet måste vara minst 8 tecken")
	}

	us.mu.Lock()
	defer us.mu.Unlock()

	for i := range us.users {
		if us.users[i].ID != id {
			continue
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		us.users[i].PasswordHash = string(hash)
		return us.saveLocked()
	}
	return fmt.Errorf("användaren hittades inte")
}

// FindByUsername returnerar ID:t för en given användare (används för att
// slå upp "vem är jag" när endast användarnamnet är känt, t.ex. vid
// self-service lösenordsbyte).
func (us *UserStore) FindByUsername(username string) (*PublicUser, error) {
	us.mu.RLock()
	defer us.mu.RUnlock()
	for _, u := range us.users {
		if strings.EqualFold(u.Username, username) {
			pub := u.ToPublic()
			return &pub, nil
		}
	}
	return nil, fmt.Errorf("okänt användarnamn")
}

// VerifyPasswordByID kontrollerar ett lösenord mot en given användares
// hash (matchad på ID) — används vid self-service lösenordsbyte för att
// kräva att man anger sitt NUVARANDE lösenord.
func (us *UserStore) VerifyPasswordByID(id, password string) error {
	us.mu.RLock()
	defer us.mu.RUnlock()
	for _, u := range us.users {
		if u.ID != id {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
			return fmt.Errorf("fel nuvarande lösenord")
		}
		return nil
	}
	return fmt.Errorf("användaren hittades inte")
}
