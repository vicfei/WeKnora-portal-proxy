package sso

import (
	"sync"
	"testing"
	"time"
)

func TestCodeOneTimeAndBinding(t *testing.T) {
	p := New()
	code := p.Issue("REVIEW-U0001", "/sso/callback")

	// wrong redirect_uri must fail and consume the code
	if _, ok := p.Exchange(code, "/evil"); ok {
		t.Fatal("code must be bound to redirect_uri")
	}
	// one-time: consumed even on failure
	if _, ok := p.Exchange(code, "/sso/callback"); ok {
		t.Fatal("code must be one-time (consumed on failed exchange)")
	}

	code2 := p.Issue("REVIEW-U0002", "/sso/callback")
	uum, ok := p.Exchange(code2, "/sso/callback")
	if !ok || uum != "REVIEW-U0002" {
		t.Fatalf("valid exchange failed: %q %v", uum, ok)
	}
	if _, ok := p.Exchange(code2, "/sso/callback"); ok {
		t.Fatal("second exchange must fail")
	}
}

func TestCodeExpiry(t *testing.T) {
	p := &Provider{codes: map[string]codeEntry{}}
	p.codes["c"] = codeEntry{
		uumUserID: "u", redirectURI: "/sso/callback",
		expiresAt: time.Now().Add(-time.Second),
	}
	if _, ok := p.Exchange("c", "/sso/callback"); ok {
		t.Fatal("expired code must fail")
	}
}

func TestConcurrentIssue(t *testing.T) {
	p := New()
	var wg sync.WaitGroup
	seen := make(chan string, 100)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			seen <- p.Issue("u", "/sso/callback")
		}()
	}
	wg.Wait()
	close(seen)
	uniq := map[string]bool{}
	for c := range seen {
		if uniq[c] {
			t.Fatal("duplicate code generated")
		}
		uniq[c] = true
	}
}
