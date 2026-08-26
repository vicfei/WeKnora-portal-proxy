package perm

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/vicfei/WeKnora-portal-proxy/internal/store"
	"github.com/vicfei/WeKnora-portal-proxy/internal/weknora"
)

type fakeStore struct{ grants []store.Grant }

func (f *fakeStore) ActiveGrantsByUser(_ context.Context, _ string) ([]store.Grant, error) {
	return f.grants, nil
}

func grant(kbID, permission, status string, validUntil *time.Time) store.Grant {
	g := store.Grant{KBID: kbID, Permission: permission, Status: status, Category: "团队"}
	if validUntil != nil {
		g.ValidUntil = sql.NullTime{Time: *validUntil, Valid: true}
	}
	return g
}

func TestFilterKBs(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	cases := []struct {
		name   string
		grants []store.Grant
		kbs    []weknora.KB
		want   []string // expected KB ids (allowed)
	}{
		{"no grants sees nothing", nil,
			[]weknora.KB{{ID: "a"}}, nil},
		{"active permanent grant allows", []store.Grant{grant("a", "viewer", "active", nil)},
			[]weknora.KB{{ID: "a"}, {ID: "b"}}, []string{"a"}},
		{"expired grant denied (lazy expiry D009)", []store.Grant{grant("a", "viewer", "active", &past)},
			[]weknora.KB{{ID: "a"}}, nil},
		{"future valid_until allows", []store.Grant{grant("a", "viewer", "active", &future)},
			[]weknora.KB{{ID: "a"}}, []string{"a"}},
		{"revoked grant denied", []store.Grant{grant("a", "viewer", "revoked", nil)},
			[]weknora.KB{{ID: "a"}}, nil},
		{"editor wins over viewer on duplicate", []store.Grant{
			grant("a", "viewer", "active", nil), grant("a", "editor", "active", nil)},
			[]weknora.KB{{ID: "a"}}, []string{"a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New(&fakeStore{grants: tc.grants})
			got, err := e.FilterKBs(context.Background(), "u1", tc.kbs)
			if err != nil {
				t.Fatalf("FilterKBs: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("allowed=%d want=%d (got %+v)", len(got), len(tc.want), got)
			}
			for i, want := range tc.want {
				if got[i].ID != want {
					t.Fatalf("allowed[%d]=%s want %s", i, got[i].ID, want)
				}
			}
		})
	}
}

func TestAuthorizeAndCanEdit(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	e := New(&fakeStore{grants: []store.Grant{
		grant("kb1", "editor", "active", nil),
		grant("kb2", "viewer", "active", &past), // expired
	}})
	ctx := context.Background()

	if _, ok := e.Authorize(ctx, "u", "kb1"); !ok {
		t.Fatal("kb1 should be authorized")
	}
	if !e.CanEdit(ctx, "u", "kb1") {
		t.Fatal("kb1 editor should pass CanEdit")
	}
	if _, ok := e.Authorize(ctx, "u", "kb2"); ok {
		t.Fatal("expired grant must be denied (kb2)")
	}
	if _, ok := e.Authorize(ctx, "u", "kb3"); ok {
		t.Fatal("ungranted kb must be denied (kb3)")
	}
}

func TestEditorWinsDecoration(t *testing.T) {
	e := New(&fakeStore{grants: []store.Grant{
		grant("a", "viewer", "active", nil),
		grant("a", "editor", "active", nil),
	}})
	got, err := e.FilterKBs(context.Background(), "u", []weknora.KB{{ID: "a"}})
	if err != nil || len(got) != 1 {
		t.Fatalf("unexpected: %+v err=%v", got, err)
	}
	if got[0].Permission != "editor" {
		t.Fatalf("permission=%s want editor", got[0].Permission)
	}
}
