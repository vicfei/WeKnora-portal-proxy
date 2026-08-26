// Package perm is the permission engine: the ONLY place that decides
// which KBs a user may see and at what level. WeKnora itself enforces
// nothing per-user for this key — correctness lives here (架构设计 §六-1),
// which is why every rule is unit-tested.
package perm

import (
	"context"

	"github.com/vicfei/WeKnora-portal-proxy/internal/store"
	"github.com/vicfei/WeKnora-portal-proxy/internal/weknora"
)

// GrantsReader is the store surface the engine needs (kept small for tests).
type GrantsReader interface {
	ActiveGrantsByUser(ctx context.Context, uumUserID string) ([]store.Grant, error)
}

type Engine struct {
	Store GrantsReader
}

func New(st GrantsReader) *Engine { return &Engine{Store: st} }

// ViewKB is a WeKnora KB decorated with the user's portal permission.
type ViewKB struct {
	weknora.KB
	Category   string `json:"category"`   // 个人 | 团队 | 公共（展示分组）
	Permission string `json:"permission"` // viewer | editor
}

// FilterKBs keeps only KBs with an effective grant and decorates them.
// Duplicate KB ids in grants: the editor permission wins (higher of the two).
func (e *Engine) FilterKBs(ctx context.Context, uumUserID string, kbs []weknora.KB) ([]ViewKB, error) {
	grants, err := e.Store.ActiveGrantsByUser(ctx, uumUserID)
	if err != nil {
		return nil, err
	}
	byKB := map[string]store.Grant{}
	for _, g := range grants {
		if !g.Effective() {
			continue // revoked or lazily expired (D009)
		}
		if prev, ok := byKB[g.KBID]; ok {
			if g.Permission == "editor" && prev.Permission != "editor" {
				byKB[g.KBID] = g
			}
			continue
		}
		byKB[g.KBID] = g
	}
	out := make([]ViewKB, 0, len(kbs))
	for _, kb := range kbs {
		g, ok := byKB[kb.ID]
		if !ok {
			continue
		}
		out = append(out, ViewKB{KB: kb, Category: g.Category, Permission: g.Permission})
	}
	return out, nil
}

// Authorize returns the effective grant for one KB. ok=false means the
// caller must answer 404 (not 403 — do not reveal existence, D008).
func (e *Engine) Authorize(ctx context.Context, uumUserID, kbID string) (store.Grant, bool) {
	grants, err := e.Store.ActiveGrantsByUser(ctx, uumUserID)
	if err != nil {
		return store.Grant{}, false
	}
	for _, g := range grants {
		if g.KBID == kbID && g.Effective() {
			return g, true
		}
	}
	return store.Grant{}, false
}

// CanEdit reports whether the user holds editor on the KB.
func (e *Engine) CanEdit(ctx context.Context, uumUserID, kbID string) bool {
	g, ok := e.Authorize(ctx, uumUserID, kbID)
	return ok && g.Permission == "editor"
}
