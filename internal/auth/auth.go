// Package auth manages portal sessions (cookie ↔ portal_sessions row).
// The middleware re-checks employee.is_active on every request so a
// disabled employee loses access immediately (功能文档 模块一).
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/vicfei/WeKnora-portal-proxy/internal/store"
)

const (
	CookieName = "portal_session"
	SessionTTL = 8 * time.Hour
)

type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxAdmin
)

// Identity is the resolved portal user for the current request.
type Identity struct {
	UUMUserID   string
	DisplayName string
	IsAdmin     bool
}

// Middleware resolves the session cookie into an Identity. On failure it
// redirects browsers to /login and returns 401 for API paths (prefixed /api/ or /chat/).
func Middleware(st *store.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(CookieName)
			if err != nil || c.Value == "" {
				unauthorized(w, r)
				return
			}
			uum, err := st.GetSessionUser(r.Context(), c.Value)
			if err != nil {
				unauthorized(w, r)
				return
			}
			emp, err := st.GetEmployee(r.Context(), uum)
			if err != nil || !emp.IsActive {
				// disabled employee: drop the session, refuse
				_ = st.DeleteSession(r.Context(), c.Value)
				unauthorized(w, r)
				return
			}
			ctx := context.WithValue(r.Context(), ctxUser, Identity{
				UUMUserID: emp.UUMUserID, DisplayName: emp.DisplayName, IsAdmin: emp.IsAdmin,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func unauthorized(w http.ResponseWriter, r *http.Request) {
	if isAPIPath(r.URL.Path) {
		http.Error(w, `{"success":false,"error":{"code":"unauthorized","message":"未登录或会话已过期"}}`, http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func isAPIPath(p string) bool {
	return len(p) >= 5 && p[:5] == "/api/" || len(p) >= 6 && p[:6] == "/chat/"
}

// RequireAdmin wraps authed handlers with the is_admin gate.
func RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !FromContext(r.Context()).IsAdmin {
			http.Error(w, `{"success":false,"error":{"code":"forbidden","message":"需要管理员权限"}}`, http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// FromContext returns the Identity stored by the middleware.
func FromContext(ctx context.Context) Identity {
	if v, ok := ctx.Value(ctxUser).(Identity); ok {
		return v
	}
	return Identity{}
}

// StartSession creates a session row and sets the cookie.
func StartSession(w http.ResponseWriter, r *http.Request, st *store.Store, uumUserID string) error {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	if err := st.CreateSession(r.Context(), id, uumUserID, SessionTTL); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SessionTTL.Seconds()),
	})
	return nil
}

// EndSession removes the session row and clears the cookie.
func EndSession(w http.ResponseWriter, r *http.Request, st *store.Store) {
	if c, err := r.Cookie(CookieName); err == nil && c.Value != "" {
		_ = st.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1})
}
