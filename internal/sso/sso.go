// Package sso implements the mock Identity Provider (OAuth-style
// authorization-code flow). Exchange returns ONLY the uum_user_id —
// modelling the "SSO returns just the user id" contract so a real SSO
// (KIP) can replace this package without touching the rest (D004).
package sso

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const codeTTL = 60 * time.Second

type codeEntry struct {
	uumUserID   string
	redirectURI string
	expiresAt   time.Time
}

type Provider struct {
	mu    sync.Mutex
	codes map[string]codeEntry
}

func New() *Provider {
	return &Provider{codes: map[string]codeEntry{}}
}

func newCode() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Issue creates a one-time authorization code bound to (user, redirectURI).
func (p *Provider) Issue(uumUserID, redirectURI string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweepLocked()
	code := newCode()
	p.codes[code] = codeEntry{uumUserID: uumUserID, redirectURI: redirectURI, expiresAt: time.Now().Add(codeTTL)}
	return code
}

// Exchange consumes a code (one-time). Returns the uum_user_id on success.
// The identity payload intentionally contains nothing but the user id.
func (p *Provider) Exchange(code, redirectURI string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.codes[code]
	if !ok {
		return "", false
	}
	delete(p.codes, code) // one-time use even when invalid
	if entry.expiresAt.Before(time.Now()) || entry.redirectURI != redirectURI {
		return "", false
	}
	return entry.uumUserID, true
}

func (p *Provider) sweepLocked() {
	now := time.Now()
	for c, e := range p.codes {
		if e.expiresAt.Before(now) {
			delete(p.codes, c)
		}
	}
}
