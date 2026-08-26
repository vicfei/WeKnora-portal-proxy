// Package config loads portal-proxy configuration from environment
// variables with an optional .env file (KEY=VALUE lines) as fallback.
// Secrets must live only in env/.env — never in the repo (decision D010).
package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	Addr            string // PROXY_ADDR, default ":8081"
	DBDSN           string // PORTAL_DB_DSN
	WeKnoraBaseURL  string // WEKNORA_BASE_URL, e.g. http://localhost:8080/api/v1
	WeKnoraTenantID int64  // WEKNORA_TENANT_ID
	WeKnoraAPIKey   string // WEKNORA_TENANT_KEY (plaintext tenant key)
	WeKnoraHMAC     string // WEKNORA_HMAC_SECRET (signed_token secret)
	CookieSecret    string // PORTAL_COOKIE_SECRET
}

// Load reads the optional envFile first, then real environment variables
// (env wins over file). Missing required fields are reported by the caller.
func Load(envFile string) *Config {
	fileVals := map[string]string{}
	if f, err := os.Open(envFile); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			fileVals[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	get := func(key, def string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		if v := fileVals[key]; v != "" {
			return v
		}
		return def
	}
	tenantID := int64(0)
	if raw := get("WEKNORA_TENANT_ID", ""); raw != "" {
		if _, err := fmt.Sscanf(raw, "%d", &tenantID); err != nil {
			tenantID = 0
		}
	}
	return &Config{
		Addr:            get("PROXY_ADDR", ":8081"),
		DBDSN:           get("PORTAL_DB_DSN", ""),
		WeKnoraBaseURL:  get("WEKNORA_BASE_URL", ""),
		WeKnoraTenantID: tenantID,
		WeKnoraAPIKey:   get("WEKNORA_TENANT_KEY", ""),
		WeKnoraHMAC:     get("WEKNORA_HMAC_SECRET", ""),
		CookieSecret:    get("PORTAL_COOKIE_SECRET", ""),
	}
}

// Validate reports missing required configuration values.
func (c *Config) Validate() []string {
	var missing []string
	if c.DBDSN == "" {
		missing = append(missing, "PORTAL_DB_DSN")
	}
	if c.WeKnoraBaseURL == "" {
		missing = append(missing, "WEKNORA_BASE_URL")
	}
	if c.WeKnoraTenantID == 0 {
		missing = append(missing, "WEKNORA_TENANT_ID")
	}
	if c.WeKnoraAPIKey == "" {
		missing = append(missing, "WEKNORA_TENANT_KEY")
	}
	if c.WeKnoraHMAC == "" {
		missing = append(missing, "WEKNORA_HMAC_SECRET")
	}
	return missing
}
