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
	ExpiresAt time.Time
}

type AuthManager struct {
	mu       sync.RWMutex
	sessions map[string]TokenSession
	attempts map[string]int
	lockouts map[string]time.Time
}

func NewAuthManager() *AuthManager {
	return &AuthManager{
		sessions: make(map[string]TokenSession),
		attempts: make(map[string]int),
		lockouts: make(map[string]time.Time),
	}
}

func (a *AuthManager) IsLockedOut(ip string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	until, ok := a.lockouts[ip]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		return false
	}
	return true
}

func (a *AuthManager) RecordFailedAttempt(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.attempts[ip]++
	if a.attempts[ip] >= 5 {
		a.lockouts[ip] = time.Now().Add(15 * time.Minute)
		a.attempts[ip] = 0
	}
}

func (a *AuthManager) CreateSession(user string, duration time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	a.mu.Lock()
	defer a.mu.Unlock()

	a.sessions[token] = TokenSession{
		Token:     token,
		User:      user,
		ExpiresAt: time.Now().Add(duration),
	}

	return token, nil
}

func (a *AuthManager) ValidateToken(token string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	session, ok := a.sessions[token]
	if !ok {
		return "", fmt.Errorf("ogiltig token")
	}

	if time.Now().After(session.ExpiresAt) {
		return "", fmt.Errorf("token har gått ut")
	}

	return session.User, nil
}
