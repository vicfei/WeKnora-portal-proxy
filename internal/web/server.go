// Package web wires HTTP routes, templates and handlers for the portal.
package web

import (
	"embed"
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/vicfei/WeKnora-portal-proxy/internal/auth"
	"github.com/vicfei/WeKnora-portal-proxy/internal/config"
	"github.com/vicfei/WeKnora-portal-proxy/internal/perm"
	"github.com/vicfei/WeKnora-portal-proxy/internal/sso"
	"github.com/vicfei/WeKnora-portal-proxy/internal/store"
	"github.com/vicfei/WeKnora-portal-proxy/internal/weknora"
	"golang.org/x/crypto/bcrypt"
)

//go:embed templates
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

type Server struct {
	Cfg *config.Config
	St  *store.Store
	IdP *sso.Provider
	WK  *weknora.Client
	Perm *perm.Engine
	tpl *template.Template
}

func NewServer(cfg *config.Config, st *store.Store, idp *sso.Provider, wk *weknora.Client, pe *perm.Engine) (*Server, error) {
	tpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{Cfg: cfg, St: st, IdP: idp, WK: wk, Perm: pe, tpl: tpl}, nil
}

// renderContent executes the named page template ("page_"+name) with a
// data map that must carry Title and (optionally) User.
func (s *Server) renderContent(w http.ResponseWriter, status int, name, title string, user *auth.Identity, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Title"] = title
	if user != nil {
		data["User"] = user
	} else {
		data["User"] = nil
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.tpl.ExecuteTemplate(w, "page_"+name, data); err != nil {
		println("template error:", err.Error())
	}
}

// denyKB answers 404 (never 403 — do not reveal KB existence, D008) and
// records the attempt in the audit log.
func (s *Server) denyKB(w http.ResponseWriter, r *http.Request, user auth.Identity, kbID string, via string) {
	_ = s.St.InsertAudit(r.Context(), user.UUMUserID, "denied", "kb:"+kbID, map[string]any{"via": via})
	http.NotFound(w, r)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"success": false, "error": map[string]string{"code": code, "message": msg}})
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// static & health
	mux.Handle("/static/", http.FileServer(http.FS(staticFS)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"success": true, "data": "ok"}) })
	mux.HandleFunc("GET /healthz/weknora", func(w http.ResponseWriter, r *http.Request) {
		if err := s.WK.Ping(); err != nil {
			writeErr(w, http.StatusBadGateway, "weknora_unreachable", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"success": true, "data": "weknora ok"})
	})

	// SSO mock + session
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/sso/authorize?redirect_uri=/sso/callback", http.StatusFound)
	})
	mux.HandleFunc("GET /sso/authorize", s.ssoAuthorizePage)
	mux.HandleFunc("POST /sso/authorize", s.ssoAuthorizeSubmit)
	mux.HandleFunc("GET /sso/callback", s.ssoCallback)
	mux.HandleFunc("POST /logout", s.logout)

	// authed pages / APIs
	authed := auth.Middleware(s.St)
	mux.Handle("GET /{$}", authed(http.HandlerFunc(s.home)))
	mux.Handle("GET /kb/{id}", authed(http.HandlerFunc(s.kbDetail)))
	mux.Handle("POST /kb/{id}/search", authed(http.HandlerFunc(s.kbSearch)))
	mux.Handle("POST /kb/{id}/upload", authed(http.HandlerFunc(s.kbUpload)))
	mux.Handle("GET /chat", authed(http.HandlerFunc(s.chatPage)))
	mux.Handle("POST /chat/session", authed(http.HandlerFunc(s.chatSessionCreate)))
	mux.Handle("POST /chat/{sid}", authed(http.HandlerFunc(s.chatSend)))

	// admin
	admin := auth.RequireAdmin
	mux.Handle("GET /admin", authed(admin(s.adminPage)))
	mux.Handle("GET /api/admin/employees", authed(admin(s.adminEmployees)))
	mux.Handle("GET /api/admin/kbs", authed(admin(s.adminKBs)))
	mux.Handle("GET /api/admin/permissions", authed(admin(s.adminPermissions)))
	mux.Handle("POST /api/admin/permissions", authed(admin(s.adminUpsertPermission)))
	mux.Handle("DELETE /api/admin/permissions/{id}", authed(admin(s.adminRevokePermission)))
	mux.Handle("GET /api/admin/audit", authed(admin(s.adminAudit)))

	return mux
}

// ── SSO mock ───────────────────────────────────────────────────────

func (s *Server) ssoAuthorizePage(w http.ResponseWriter, r *http.Request) {
	s.renderContent(w, 200, "sso_login", "登录", nil, map[string]any{
		"RedirectURI": r.URL.Query().Get("redirect_uri"),
		"Error":       r.URL.Query().Get("error"),
	})
}

func (s *Server) ssoAuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	uum := r.FormValue("uum_user_id")
	password := r.FormValue("password")
	redirectURI := r.FormValue("redirect_uri")
	if redirectURI == "" {
		redirectURI = "/sso/callback"
	}
	emp, err := s.St.GetEmployee(r.Context(), uum)
	deny := func(reason string) {
		http.Redirect(w, r, "/sso/authorize?redirect_uri="+redirectURI+"&error="+reason, http.StatusFound)
	}
	if err != nil || bcrypt.CompareHashAndPassword([]byte(emp.PasswordHash), []byte(password)) != nil {
		_ = s.St.InsertAudit(r.Context(), uum, "login", "sso", map[string]any{"ok": false, "reason": "bad_credentials"})
		deny("工号或密码错误")
		return
	}
	if !emp.IsActive {
		_ = s.St.InsertAudit(r.Context(), uum, "login", "sso", map[string]any{"ok": false, "reason": "inactive"})
		deny("账号已禁用")
		return
	}
	code := s.IdP.Issue(uum, redirectURI)
	http.Redirect(w, r, redirectURI+"?code="+code, http.StatusFound)
}

func (s *Server) ssoCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	// Exchange returns ONLY the user id — the "SSO gives just user_id" contract (D004).
	uum, ok := s.IdP.Exchange(code, "/sso/callback")
	if !ok {
		http.Redirect(w, r, "/sso/authorize?redirect_uri=/sso/callback&error=code 无效或已过期", http.StatusFound)
		return
	}
	if err := auth.StartSession(w, r, s.St, uum); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	_ = s.St.InsertAudit(r.Context(), uum, "login", "portal", map[string]any{"ok": true})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if id := auth.FromContext(r.Context()); id.UUMUserID != "" {
		_ = s.St.InsertAudit(r.Context(), id.UUMUserID, "logout", "portal", nil)
	}
	auth.EndSession(w, r, s.St)
	http.Redirect(w, r, "/login", http.StatusFound)
}
