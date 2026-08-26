// Package main is the entrypoint of the WeKnora portal proxy (route B1).
//
// Position: a standalone service sitting between the company portal and
// WeKnora. It holds the user↔KB permission table, calls WeKnora via the
// tenant-key API channel, and filters every response per user. The WeKnora
// fork stays untouched — all integration is runtime configuration.
package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	addr := os.Getenv("PROXY_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	log.Printf("portal-proxy listening on %s (skeleton, no business logic yet)", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
