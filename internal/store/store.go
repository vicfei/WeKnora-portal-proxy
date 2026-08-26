// Package store provides postgres access to the portal_proxy database
// (employees / kb_permissions / portal_sessions / audit_log).
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db *sql.DB
}

func Open(dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// ── employees ──────────────────────────────────────────────────────

type Employee struct {
	UUMUserID    string `json:"uum_user_id"`
	DisplayName  string `json:"display_name"`
	PasswordHash string `json:"-"`
	IsAdmin      bool   `json:"is_admin"`
	IsActive     bool   `json:"is_active"`
}

func (s *Store) GetEmployee(ctx context.Context, uumUserID string) (*Employee, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT uum_user_id, display_name, password_hash, is_admin, is_active
		 FROM employees WHERE uum_user_id = $1`, uumUserID)
	var e Employee
	if err := row.Scan(&e.UUMUserID, &e.DisplayName, &e.PasswordHash, &e.IsAdmin, &e.IsActive); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &e, nil
}

func (s *Store) SearchEmployees(ctx context.Context, q string, limit int) ([]Employee, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT uum_user_id, display_name, '' , is_admin, is_active
		 FROM employees
		 WHERE ($1 = '' OR uum_user_id ILIKE '%'||$1||'%' OR display_name ILIKE '%'||$1||'%')
		   AND is_active = true
		 ORDER BY uum_user_id LIMIT $2`, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Employee
	for rows.Next() {
		var e Employee
		if err := rows.Scan(&e.UUMUserID, &e.DisplayName, &e.PasswordHash, &e.IsAdmin, &e.IsActive); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ── portal_sessions ────────────────────────────────────────────────

func (s *Store) CreateSession(ctx context.Context, id, uumUserID string, ttl time.Duration) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO portal_sessions (id, uum_user_id, expires_at) VALUES ($1, $2, now() + $3::interval)`,
		id, uumUserID, ttl.String())
	return err
}

func (s *Store) GetSessionUser(ctx context.Context, id string) (string, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT uum_user_id FROM portal_sessions WHERE id = $1 AND expires_at > now()`, id)
	var uum string
	if err := row.Scan(&uum); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return uum, nil
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM portal_sessions WHERE id = $1`, id)
	return err
}

func (s *Store) SweepSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM portal_sessions WHERE expires_at <= now()`)
	return err
}

// ── kb_permissions ─────────────────────────────────────────────────

type Grant struct {
	ID         int64          `json:"id"`
	UUMUserID  string         `json:"uum_user_id"`
	KBID       string         `json:"kb_id"`
	Permission string         `json:"permission"` // viewer | editor
	Category   string         `json:"category"`   // 个人 | 团队 | 公共（展示分组）
	Status     string         `json:"status"`     // active | revoked
	ValidUntil sql.NullTime   `json:"valid_until"`
	GrantedBy  string         `json:"granted_by"`
	Reason     string         `json:"reason,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// Expired reports whether an active grant's validity window has passed.
// (Lazy expiry per decision D009: status stays "active" in DB; readers judge.)
func (g *Grant) Expired() bool {
	return g.ValidUntil.Valid && g.ValidUntil.Time.Before(time.Now())
}

// Effective: status active AND not expired.
func (g *Grant) Effective() bool {
	return g.Status == "active" && !g.Expired()
}

// ActiveGrantsByUser returns rows with status='active' (expiry judged by caller).
func (s *Store) ActiveGrantsByUser(ctx context.Context, uumUserID string) ([]Grant, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, uum_user_id, kb_id, permission, category, status, valid_until, granted_by, coalesce(reason,''), created_at, updated_at
		 FROM kb_permissions WHERE uum_user_id = $1 AND status = 'active'`, uumUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanGrants(rows)
}

func (s *Store) ListGrants(ctx context.Context, uumFilter string) ([]Grant, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, uum_user_id, kb_id, permission, category, status, valid_until, granted_by, coalesce(reason,''), created_at, updated_at
		 FROM kb_permissions
		 WHERE ($1 = '' OR uum_user_id = $1)
		 ORDER BY updated_at DESC LIMIT 500`, uumFilter)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanGrants(rows)
}

func scanGrants(rows *sql.Rows) ([]Grant, error) {
	var out []Grant
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.ID, &g.UUMUserID, &g.KBID, &g.Permission, &g.Category, &g.Status,
			&g.ValidUntil, &g.GrantedBy, &g.Reason, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// UpsertGrant inserts or updates the (uum_user_id, kb_id) row and reactivates it.
func (s *Store) UpsertGrant(ctx context.Context, g *Grant) error {
	var validUntil any
	if g.ValidUntil.Valid {
		validUntil = g.ValidUntil.Time
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO kb_permissions (uum_user_id, kb_id, permission, category, status, valid_until, granted_by, reason)
		 VALUES ($1,$2,$3,$4,'active',$5,$6,$7)
		 ON CONFLICT (uum_user_id, kb_id) DO UPDATE SET
		   permission = EXCLUDED.permission, category = EXCLUDED.category,
		   status = 'active', valid_until = EXCLUDED.valid_until,
		   granted_by = EXCLUDED.granted_by, reason = EXCLUDED.reason, updated_at = now()`,
		g.UUMUserID, g.KBID, g.Permission, g.Category, validUntil, g.GrantedBy, g.Reason)
	return err
}

func (s *Store) GetGrant(ctx context.Context, id int64) (*Grant, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, uum_user_id, kb_id, permission, category, status, valid_until, granted_by, coalesce(reason,''), created_at, updated_at
		 FROM kb_permissions WHERE id = $1`, id)
	var g Grant
	if err := row.Scan(&g.ID, &g.UUMUserID, &g.KBID, &g.Permission, &g.Category, &g.Status,
		&g.ValidUntil, &g.GrantedBy, &g.Reason, &g.CreatedAt, &g.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &g, nil
}

func (s *Store) RevokeGrant(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE kb_permissions SET status='revoked', updated_at=now() WHERE id=$1 AND status='active'`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ── audit_log ──────────────────────────────────────────────────────

func (s *Store) InsertAudit(ctx context.Context, actor, action, target string, detail map[string]any) error {
	if detail == nil {
		detail = map[string]any{}
	}
	b, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO audit_log (actor, action, target, detail) VALUES ($1,$2,$3,$4)`,
		actor, action, target, string(b))
	return err
}

type AuditEntry struct {
	ID        int64     `json:"id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Detail    string    `json:"detail"` // raw JSON
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) ListAudit(ctx context.Context, actor, action string, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, actor, action, target, detail::text, created_at
		 FROM audit_log
		 WHERE ($1='' OR actor=$1) AND ($2='' OR action=$2)
		 ORDER BY id DESC LIMIT $3`, actor, action, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(&a.ID, &a.Actor, &a.Action, &a.Target, &a.Detail, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
