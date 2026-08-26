// Command proxy is the entrypoint of the WeKnora portal proxy (route B1).
// See .context/design/架构设计.md for the system positioning and
// .context/design/外部接口.md for the full HTTP surface.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/vicfei/WeKnora-portal-proxy/internal/config"
	"github.com/vicfei/WeKnora-portal-proxy/internal/perm"
	"github.com/vicfei/WeKnora-portal-proxy/internal/sso"
	"github.com/vicfei/WeKnora-portal-proxy/internal/store"
	"github.com/vicfei/WeKnora-portal-proxy/internal/web"
	"github.com/vicfei/WeKnora-portal-proxy/internal/weknora"
)

func main() {
	envFile := flag.String("env", ".env", "env file path (real env vars take precedence)")
	flag.Parse()

	cfg := config.Load(*envFile)
	if missing := cfg.Validate(); len(missing) > 0 {
		log.Fatalf("missing required config: %v (see .context/design/外部接口.md §六)", missing)
	}

	st, err := store.Open(cfg.DBDSN)
	if err != nil {
		log.Fatalf("portal db: %v", err)
	}
	defer st.Close()

	idp := sso.New()
	wk := weknora.New(cfg.WeKnoraBaseURL, cfg.WeKnoraTenantID, cfg.WeKnoraAPIKey, cfg.WeKnoraHMAC)
	engine := perm.New(st)

	srv, err := web.NewServer(cfg, st, idp, wk, engine)
	if err != nil {
		log.Fatalf("web: %v", err)
	}

	// background session sweeper (every 10 min)
	go func() {
		for range time.Tick(10 * time.Minute) {
			_ = st.SweepSessions(nil)
		}
	}()

	addr := cfg.Addr
	log.Printf("portal-proxy listening on %s (B1 POC, WeKnora tenant=%d)", addr, cfg.WeKnoraTenantID)
	server := &http.Server{
		Addr:              addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
