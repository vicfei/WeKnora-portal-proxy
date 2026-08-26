// Package weknora is the HTTP client for the WeKnora API channel:
// tenant key + X-Tenant-ID + per-request X-External-User-Token (D002/D007).
// The external JWT carries sub=uum_user_id so WeKnora attributes sessions
// and audit to api_external_user:{tenant}:{sub}.
package weknora

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const externalJWTTTL = 30 * time.Minute // well under WeKnora's 24h cap (D007)

type Client struct {
	BaseURL   string // e.g. http://localhost:8080/api/v1
	TenantID  int64
	APIKey    string
	HMAC      string
	SecretKey []byte // raw key for HS256
	HTTP      *http.Client
}

func New(baseURL string, tenantID int64, apiKey, hmac string) *Client {
	return &Client{
		BaseURL:   baseURL,
		TenantID:  tenantID,
		APIKey:    apiKey,
		HMAC:      hmac,
		HTTP:      &http.Client{Timeout: 120 * time.Second},
	}
}

// SignExternalJWT mints the per-user virtual principal token.
func (c *Client) SignExternalJWT(sub string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":       sub,
		"tenant_id": c.TenantID,
		"aud":       "weknora",
		"iat":       now.Unix(),
		"exp":       now.Add(externalJWTTTL).Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(c.HMAC))
}

func (c *Client) newRequest(sub, method, path string, body io.Reader, contentType string) (*http.Request, error) {
	req, err := http.NewRequest(method, c.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	ext, err := c.SignExternalJWT(sub)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", c.APIKey)
	req.Header.Set("X-Tenant-ID", fmt.Sprintf("%d", c.TenantID))
	req.Header.Set("X-External-User-Token", ext)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req, nil
}

// do executes a request and returns the parsed envelope. data may be nil.
func (c *Client) do(req *http.Request) (json.RawMessage, error) {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	var env struct {
		Success bool            `json:"success"`
		Data    json.RawMessage `json:"data"`
		Error   *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("weknora %s: non-JSON response (HTTP %d)", req.URL.Path, resp.StatusCode)
	}
	if !env.Success {
		msg := "unknown error"
		if env.Error != nil {
			msg = env.Error.Message
		}
		return nil, fmt.Errorf("weknora %s: HTTP %d: %s", req.URL.Path, resp.StatusCode, msg)
	}
	return env.Data, nil
}

// ── knowledge bases ────────────────────────────────────────────────

type KB struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	Type           string `json:"type"`
	KnowledgeCount int64  `json:"knowledge_count"`
	ChunkCount     int64  `json:"chunk_count"`
}

func (c *Client) ListKBs(sub string) ([]KB, error) {
	req, err := c.newRequest(sub, http.MethodGet, "/knowledge-bases", nil, "")
	if err != nil {
		return nil, err
	}
	data, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var kbs []KB
	if err := json.Unmarshal(data, &kbs); err != nil {
		return nil, err
	}
	return kbs, nil
}

func (c *Client) GetKB(sub, kbID string) (*KB, error) {
	req, err := c.newRequest(sub, http.MethodGet, "/knowledge-bases/"+kbID, nil, "")
	if err != nil {
		return nil, err
	}
	data, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var kb KB
	if err := json.Unmarshal(data, &kb); err != nil {
		return nil, err
	}
	return &kb, nil
}

// Doc is a knowledge entry shown on the KB detail page.
type Doc struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Type        string `json:"type"`
	ParseStatus string `json:"parse_status"`
	CreatedAt   string `json:"created_at"`
}

func (c *Client) ListDocs(sub, kbID string) ([]Doc, error) {
	req, err := c.newRequest(sub, http.MethodGet, "/knowledge-bases/"+kbID+"/knowledge?page=1&page_size=50", nil, "")
	if err != nil {
		return nil, err
	}
	data, err := c.do(req)
	if err != nil {
		return nil, err
	}
	// Response may be a bare array or {list:[...]}: accept both.
	var docs []Doc
	if err := json.Unmarshal(data, &docs); err == nil {
		return docs, nil
	}
	var wrapped struct {
		List []Doc `json:"list"`
	}
	if err := json.Unmarshal(data, &wrapped); err == nil {
		return wrapped.List, nil
	}
	return nil, fmt.Errorf("unexpected knowledge list shape")
}

// HybridSearch passes the caller's search payload through and returns raw JSON.
func (c *Client) HybridSearch(sub, kbID string, payload []byte) (json.RawMessage, error) {
	req, err := c.newRequest(sub, http.MethodPost, "/knowledge-bases/"+kbID+"/hybrid-search",
		bytes.NewReader(payload), "application/json")
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

// UploadFile forwards a document upload (multipart field "file").
func (c *Client) UploadFile(sub, kbID, filename string, content io.Reader) (json.RawMessage, error) {
	pr, pw := io.Pipe()
	w := newMultipartWriter(pw, "file", filename)
	go func() {
		err := w.writeAndClose(content)
		_ = pw.CloseWithError(err)
	}()
	req, err := c.newRequest(sub, http.MethodPost, "/knowledge-bases/"+kbID+"/knowledge/file", pr, w.formDataContentType())
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

// ── chat sessions ──────────────────────────────────────────────────

func (c *Client) CreateSession(sub string) (string, error) {
	req, err := c.newRequest(sub, http.MethodPost, "/sessions", bytes.NewReader([]byte(`{}`)), "application/json")
	if err != nil {
		return "", err
	}
	data, err := c.do(req)
	if err != nil {
		return "", err
	}
	var sess struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &sess); err != nil {
		return "", err
	}
	return sess.ID, nil
}

type Session struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

func (c *Client) ListSessions(sub string) ([]Session, error) {
	req, err := c.newRequest(sub, http.MethodGet, "/sessions", nil, "")
	if err != nil {
		return nil, err
	}
	data, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var sessions []Session
	if err := json.Unmarshal(data, &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

// ChatSSE streams WeKnora's knowledge-chat response to dst verbatim
// (no parsing / rewriting — 架构设计.md 流 3). Flush is called per chunk.
func (c *Client) ChatSSE(sub, sessionID string, payload []byte, dst io.Writer, flush func()) error {
	req, err := c.newRequest(sub, http.MethodPost, "/knowledge-chat/"+sessionID,
		bytes.NewReader(payload), "application/json")
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	// long-lived stream: per-request client without the shared timeout
	streamClient := &http.Client{Timeout: 300 * time.Second}
	resp, err := streamClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("weknora chat: HTTP %d: %s", resp.StatusCode, body)
	}
	buf := make([]byte, 16*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr // client disconnected
			}
			if flush != nil {
				flush()
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}

// Ping checks WeKnora reachability + key validity (GET /knowledge-bases with a
// synthetic internal sub).
func (c *Client) Ping() error {
	_, err := c.ListKBs("system")
	return err
}
