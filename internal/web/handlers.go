package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/vicfei/WeKnora-portal-proxy/internal/auth"
	"github.com/vicfei/WeKnora-portal-proxy/internal/perm"
	"github.com/vicfei/WeKnora-portal-proxy/internal/store"
	"github.com/vicfei/WeKnora-portal-proxy/internal/weknora"
)

// ── end-user pages ─────────────────────────────────────────────────

type group struct {
	Category string
	KBs      any
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	user := auth.FromContext(r.Context())
	kbs, err := s.WK.ListKBs(user.UUMUserID)
	if err != nil {
		http.Error(w, "WeKnora 列表获取失败: "+err.Error(), http.StatusBadGateway)
		return
	}
	view, err := s.Perm.FilterKBs(r.Context(), user.UUMUserID, kbs)
	if err != nil {
		http.Error(w, "权限引擎错误", http.StatusInternalServerError)
		return
	}
	// group by category, keep a stable display order
	order := []string{"个人", "团队", "公共"}
	idx := map[string]int{}
	var groups []group
	for _, c := range order {
		groups = append(groups, group{Category: c})
		idx[c] = len(groups) - 1
	}
	byCat := map[string][]any{}
	for _, kb := range view {
		cat := kb.Category
		if _, ok := idx[cat]; !ok {
			groups = append(groups, group{Category: cat})
			idx[cat] = len(groups) - 1
		}
		byCat[cat] = append(byCat[cat], kb)
	}
	for i := range groups {
		groups[i].KBs = []perm.ViewKB{}
		if kbList, ok := byCat[groups[i].Category]; ok {
			groups[i].KBs = kbList
		}
	}
	s.renderContent(w, 200, "home", "知识库", &user, map[string]any{"Groups": groups})
}

func (s *Server) kbDetail(w http.ResponseWriter, r *http.Request) {
	user := auth.FromContext(r.Context())
	kbID := r.PathValue("id")
	g, ok := s.Perm.Authorize(r.Context(), user.UUMUserID, kbID)
	if !ok {
		s.denyKB(w, r, user, kbID, "page")
		return
	}
	kb, err := s.WK.GetKB(user.UUMUserID, kbID)
	if err != nil {
		http.Error(w, "WeKnora 详情获取失败: "+err.Error(), http.StatusBadGateway)
		return
	}
	docs, _ := s.WK.ListDocs(user.UUMUserID, kbID)
	if docs == nil {
		docs = []weknora.Doc{}
	}
	s.renderContent(w, 200, "kb", kb.Name, &user, map[string]any{
		"KB": kb, "Docs": docs, "Permission": g.Permission, "CanEdit": g.Permission == "editor",
	})
}

func (s *Server) kbSearch(w http.ResponseWriter, r *http.Request) {
	user := auth.FromContext(r.Context())
	kbID := r.PathValue("id")
	if _, ok := s.Perm.Authorize(r.Context(), user.UUMUserID, kbID); !ok {
		s.denyKB(w, r, user, kbID, "search")
		writeErr(w, http.StatusNotFound, "not_found", "知识库不存在")
		return
	}
	payload, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_body", err.Error())
		return
	}
	_ = s.St.InsertAudit(r.Context(), user.UUMUserID, "search", "kb:"+kbID, nil)
	data, err := s.WK.HybridSearch(user.UUMUserID, kbID, payload)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "weknora_error", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "data": json.RawMessage(data)})
}

func (s *Server) kbUpload(w http.ResponseWriter, r *http.Request) {
	user := auth.FromContext(r.Context())
	kbID := r.PathValue("id")
	if _, ok := s.Perm.Authorize(r.Context(), user.UUMUserID, kbID); !ok {
		s.denyKB(w, r, user, kbID, "upload") // no access at all → 404 (D008)
		return
	}
	if !s.Perm.CanEdit(r.Context(), user.UUMUserID, kbID) {
		_ = s.St.InsertAudit(r.Context(), user.UUMUserID, "denied", "kb:"+kbID, map[string]any{"via": "upload", "reason": "viewer"})
		writeErr(w, http.StatusForbidden, "forbidden", "需要 editor 权限")
		return
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_form", err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "no_file", "缺少 file 字段")
		return
	}
	defer file.Close()
	data, err := s.WK.UploadFile(user.UUMUserID, kbID, header.Filename, file)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "weknora_error", err.Error())
		return
	}
	_ = s.St.InsertAudit(r.Context(), user.UUMUserID, "upload", "kb:"+kbID, map[string]any{"file": header.Filename})
	writeJSON(w, 200, map[string]any{"success": true, "data": json.RawMessage(data)})
}

// ── chat ───────────────────────────────────────────────────────────

func (s *Server) chatPage(w http.ResponseWriter, r *http.Request) {
	user := auth.FromContext(r.Context())
	kbs, _ := s.WK.ListKBs(user.UUMUserID)
	view, _ := s.Perm.FilterKBs(r.Context(), user.UUMUserID, kbs)
	sessions, _ := s.WK.ListSessions(user.UUMUserID)
	initSession := ""
	if len(sessions) > 0 {
		initSession = sessions[0].ID
	}
	s.renderContent(w, 200, "chat", "问答", &user, map[string]any{
		"KBs": view, "Sessions": sessions, "InitSession": initSession,
	})
}

func (s *Server) chatSessionCreate(w http.ResponseWriter, r *http.Request) {
	user := auth.FromContext(r.Context())
	id, err := s.WK.CreateSession(user.UUMUserID)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "weknora_error", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "data": map[string]string{"session_id": id}})
}

func (s *Server) chatSend(w http.ResponseWriter, r *http.Request) {
	user := auth.FromContext(r.Context())
	sessionID := r.PathValue("sid")
	var body struct {
		QueryText string   `json:"query_text"`
		KBIDs     []string `json:"kb_ids"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || body.QueryText == "" {
		writeErr(w, http.StatusBadRequest, "bad_body", "query_text 必填")
		return
	}
	// Every referenced KB must pass the permission gate before forwarding.
	for _, kbID := range body.KBIDs {
		if _, ok := s.Perm.Authorize(r.Context(), user.UUMUserID, kbID); !ok {
			s.denyKB(w, r, user, kbID, "chat")
			writeErr(w, http.StatusNotFound, "not_found", "引用的知识库不存在: "+kbID)
			return
		}
	}
	// Portal contract uses query_text; WeKnora's QA DTO expects "query".
	payload, _ := json.Marshal(map[string]any{
		"query": body.QueryText, "knowledge_base_ids": body.KBIDs, "disable_title": false,
	})
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	err := s.WK.ChatSSE(user.UUMUserID, sessionID, payload, w, func() {
		if flusher != nil {
			flusher.Flush()
		}
	})
	if err != nil {
		// mid-stream failure: append an SSE error event if headers are out
		_, _ = w.Write([]byte("data: {\"response_type\":\"error\",\"error\":\"" + err.Error() + "\"}\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// ── admin ──────────────────────────────────────────────────────────

type grantRow struct {
	store.Grant
	KBName  string
	Expired bool
}

func (s *Server) adminPage(w http.ResponseWriter, r *http.Request) {
	user := auth.FromContext(r.Context())
	employees, _ := s.St.SearchEmployees(r.Context(), "", 100)
	allKBs, _ := s.WK.ListKBs(user.UUMUserID)
	grants, _ := s.St.ListGrants(r.Context(), "")
	kbName := map[string]string{}
	for _, kb := range allKBs {
		kbName[kb.ID] = kb.Name
	}
	var rows []grantRow
	for _, g := range grants {
		rows = append(rows, grantRow{Grant: g, KBName: kbName[g.KBID], Expired: g.Expired()})
	}
	audit, _ := s.St.ListAudit(r.Context(), "", "", 100)
	s.renderContent(w, 200, "admin", "管理后台", &user, map[string]any{
		"Employees": employees, "AllKBs": allKBs, "GrantRows": rows, "AuditRows": audit,
	})
}

func (s *Server) adminEmployees(w http.ResponseWriter, r *http.Request) {
	employees, err := s.St.SearchEmployees(r.Context(), r.URL.Query().Get("q"), 50)
	if err != nil {
		writeErr(w, 500, "db", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "data": employees})
}

func (s *Server) adminKBs(w http.ResponseWriter, r *http.Request) {
	user := auth.FromContext(r.Context())
	kbs, err := s.WK.ListKBs(user.UUMUserID)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "weknora_error", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "data": kbs})
}

func (s *Server) adminPermissions(w http.ResponseWriter, r *http.Request) {
	grants, err := s.St.ListGrants(r.Context(), r.URL.Query().Get("uum_user_id"))
	if err != nil {
		writeErr(w, 500, "db", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "data": grants})
}

func (s *Server) adminUpsertPermission(w http.ResponseWriter, r *http.Request) {
	actor := auth.FromContext(r.Context())
	var req struct {
		UUMUserID  string `json:"uum_user_id"`
		KBID       string `json:"kb_id"`
		Permission string `json:"permission"`
		Category   string `json:"category"`
		ValidUntil string `json:"valid_until"` // RFC3339, optional
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UUMUserID == "" || req.KBID == "" {
		writeErr(w, http.StatusBadRequest, "bad_body", "uum_user_id 与 kb_id 必填")
		return
	}
	if req.Permission == "" {
		req.Permission = "viewer"
	}
	if req.Category == "" {
		req.Category = "团队"
	}
	if req.Permission != "viewer" && req.Permission != "editor" {
		writeErr(w, http.StatusBadRequest, "bad_perm", "permission 仅支持 viewer/editor")
		return
	}
	g := &store.Grant{
		UUMUserID: req.UUMUserID, KBID: req.KBID, Permission: req.Permission,
		Category: req.Category, GrantedBy: actor.UUMUserID, Reason: req.Reason,
	}
	if req.ValidUntil != "" {
		t, err := time.Parse(time.RFC3339, req.ValidUntil)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_valid_until", "valid_until 须为 RFC3339")
			return
		}
		g.ValidUntil.Time, g.ValidUntil.Valid = t, true
	}
	if err := s.St.UpsertGrant(r.Context(), g); err != nil {
		writeErr(w, 500, "db", err.Error())
		return
	}
	_ = s.St.InsertAudit(r.Context(), actor.UUMUserID, "grant", "kb:"+req.KBID+" user:"+req.UUMUserID, map[string]any{
		"permission": req.Permission, "category": req.Category, "valid_until": req.ValidUntil,
	})
	writeJSON(w, 200, map[string]any{"success": true, "data": "ok"})
}

func (s *Server) adminRevokePermission(w http.ResponseWriter, r *http.Request) {
	actor := auth.FromContext(r.Context())
	var id int64
	if _, err := fmt.Sscanf(r.PathValue("id"), "%d", &id); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_id", "id 非法")
		return
	}
	g, err := s.St.GetGrant(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "授权不存在")
		return
	}
	if err := s.St.RevokeGrant(r.Context(), id); err != nil {
		writeErr(w, 500, "db", err.Error())
		return
	}
	_ = s.St.InsertAudit(r.Context(), actor.UUMUserID, "revoke", "kb:"+g.KBID+" user:"+g.UUMUserID, nil)
	writeJSON(w, 200, map[string]any{"success": true, "data": "ok"})
}

func (s *Server) adminAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	audit, err := s.St.ListAudit(r.Context(), q.Get("actor"), q.Get("action"), 100)
	if err != nil {
		writeErr(w, 500, "db", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "data": audit})
}
