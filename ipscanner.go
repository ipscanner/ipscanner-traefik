// Package ipscanner_traefik is the IPScanner middleware plugin for Traefik.
// It checks every visitor with POST /v1/edge/check, applies the site policy
// from the IPScanner dashboard (or the local configuration), adds
// X-IPScanner-* headers for the upstream and fails open.
//
// The plugin runs under Yaegi and uses the standard library and
// github.com/ipscanner/ipscanner-edge-go only.
package ipscanner_traefik //nolint:revive,stylecheck // Traefik derives the package name from the import path.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	edge "github.com/ipscanner/ipscanner-edge-go"
)

// Version is the plugin version, sent as User-Agent ipscanner-traefik/<Version>.
const Version = "0.1.0"

// Source is sent as X-IPScanner-Source.
const Source = "traefik"

// KeyEnv is read when neither apiKey nor apiKeyFile is set.
const KeyEnv = "IPSCANNER_API_KEY"

// Config is the plugin configuration. Durations are strings such as
// "1500ms", "30s" or "10m". Empty values use the defaults of the core.
type Config struct {
	// APIKey is the IPScanner API key. Prefer apiKeyFile or the
	// IPSCANNER_API_KEY environment variable of the Traefik process: plugin
	// options are visible in the Traefik dashboard and API.
	APIKey string `json:"apiKey,omitempty" yaml:"apiKey,omitempty"`
	// APIKeyFile is a file holding the API key, read once per configuration.
	APIKeyFile string `json:"apiKeyFile,omitempty" yaml:"apiKeyFile,omitempty"`
	// SiteID is the dashboard site (site_...). Mode and policy then come
	// from the dashboard.
	SiteID string `json:"siteId,omitempty" yaml:"siteId,omitempty"`
	// Mode is monitor or enforce. Without siteId default monitor. With
	// siteId only monitor has an effect.
	Mode string `json:"mode,omitempty" yaml:"mode,omitempty"`
	// BlockClasses are blocked in enforce mode without siteId. Default
	// malicious_automation.
	BlockClasses []string `json:"blockClasses,omitempty" yaml:"blockClasses,omitempty"`
	// TrustedProxies are addresses and CIDR ranges whose IP headers are
	// trusted, plus the keywords private and cloudflare.
	TrustedProxies []string `json:"trustedProxies,omitempty" yaml:"trustedProxies,omitempty"`
	// IPHeaders are read in order from a trusted proxy. Default X-Forwarded-For.
	IPHeaders []string `json:"ipHeaders,omitempty" yaml:"ipHeaders,omitempty"`
	// Timeout is the budget for one check. Default 1500ms.
	Timeout string `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	// CacheTTL is how long a verdict is reused per visitor. Default 10m.
	CacheTTL string `json:"cacheTTL,omitempty" yaml:"cacheTTL,omitempty"`
	// CacheSize bounds the verdict cache. Default 10000.
	CacheSize int `json:"cacheSize,omitempty" yaml:"cacheSize,omitempty"`
	// PolicyTTL is how long the site policy is reused. Default 30s.
	PolicyTTL string `json:"policyTTL,omitempty" yaml:"policyTTL,omitempty"`
	// SkipPaths is a case insensitive regex on the path. Default: static
	// assets, robots.txt, sitemap.xml, favicon.ico. "none" checks every path.
	SkipPaths string `json:"skipPaths,omitempty" yaml:"skipPaths,omitempty"`
	// BlockMessage is the text of the 403 page.
	BlockMessage string `json:"blockMessage,omitempty" yaml:"blockMessage,omitempty"`
	// Debug adds X-IPScanner-Status, -Class and -Action to responses and
	// logs every decision.
	Debug bool `json:"debug,omitempty" yaml:"debug,omitempty"`
	// APIURL is the API base URL. Default https://ipscanner.io.
	APIURL string `json:"apiUrl,omitempty" yaml:"apiUrl,omitempty"`
}

// CreateConfig returns the default configuration. Lists stay nil: Traefik
// decodes into this value, and a default list would keep extra entries.
func CreateConfig() *Config {
	return &Config{}
}

// Middleware is the Traefik handler.
type Middleware struct {
	next  http.Handler
	guard *edge.Guard
}

// New builds the middleware. Traefik calls it for every router that uses
// the middleware and again on every configuration reload; guards with the
// same configuration are shared, so the caches and the backoff survive.
func New(_ context.Context, next http.Handler, config *Config, _ string) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}
	cfg, err := edgeConfig(config)
	if err != nil {
		return nil, err
	}
	guard, err := guardFor(cfg)
	if err != nil {
		return nil, err
	}
	return &Middleware{next: next, guard: guard}, nil
}

// ServeHTTP checks the visitor and passes the request on unless it is blocked.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.guard.Handle(w, r); !ok {
		return
	}
	m.next.ServeHTTP(w, r)
}

// edgeConfig turns the plugin options into the core configuration.
func edgeConfig(c *Config) (edge.Config, error) {
	key, err := apiKey(c)
	if err != nil {
		return edge.Config{}, err
	}
	timeout, err := duration("timeout", c.Timeout)
	if err != nil {
		return edge.Config{}, err
	}
	cacheTTL, err := duration("cacheTTL", c.CacheTTL)
	if err != nil {
		return edge.Config{}, err
	}
	policyTTL, err := duration("policyTTL", c.PolicyTTL)
	if err != nil {
		return edge.Config{}, err
	}
	if c.CacheSize < 0 {
		return edge.Config{}, errors.New("ipscanner: cacheSize must not be negative")
	}
	return edge.Config{
		APIKey:         key,
		APIURL:         c.APIURL,
		SiteID:         c.SiteID,
		Mode:           c.Mode,
		BlockClasses:   c.BlockClasses,
		TrustedProxies: c.TrustedProxies,
		IPHeaders:      c.IPHeaders,
		Timeout:        timeout,
		CacheTTL:       cacheTTL,
		CacheSize:      c.CacheSize,
		PolicyTTL:      policyTTL,
		SkipPaths:      c.SkipPaths,
		Source:         Source,
		Client:         "traefik",
		Version:        Version,
		BlockMessage:   c.BlockMessage,
		Debug:          c.Debug,
		Logger:         logLine,
	}, nil
}

// logLine writes one JSON line to stdout, where Traefik expects plugin logs.
func logLine(line string) {
	_, _ = os.Stdout.WriteString(line + "\n")
}

// apiKey resolves the key: apiKey, then apiKeyFile, then IPSCANNER_API_KEY.
func apiKey(c *Config) (string, error) {
	if key := strings.TrimSpace(c.APIKey); key != "" {
		return key, nil
	}
	if path := strings.TrimSpace(c.APIKeyFile); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", errors.New("ipscanner: apiKeyFile: " + err.Error())
		}
		key := strings.TrimSpace(string(raw))
		if key == "" {
			return "", errors.New("ipscanner: apiKeyFile " + path + " is empty")
		}
		return key, nil
	}
	return strings.TrimSpace(os.Getenv(KeyEnv)), nil
}

// duration parses a Go duration ("1500ms", "30s", "10m"). Empty means the
// default.
func duration(name, value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil || d < 0 {
		return 0, errors.New("ipscanner: " + name + " must be a duration such as 1500ms, 30s or 10m")
	}
	return d, nil
}

// maxGuards bounds the shared guards. Each distinct configuration has one;
// old ones go when a reload brings new configurations.
const maxGuards = 32

var (
	guardsMu    sync.Mutex
	guards      = map[string]*edge.Guard{}
	guardsOrder []string
)

// guardFor returns the shared guard for cfg, creating it when needed.
func guardFor(cfg edge.Config) (*edge.Guard, error) {
	id := configID(cfg)
	guardsMu.Lock()
	defer guardsMu.Unlock()
	if g, ok := guards[id]; ok {
		return g, nil
	}
	g, err := edge.New(cfg)
	if err != nil {
		return nil, err
	}
	guards[id] = g
	guardsOrder = append(guardsOrder, id)
	for len(guardsOrder) > maxGuards {
		delete(guards, guardsOrder[0])
		guardsOrder = guardsOrder[1:]
	}
	return g, nil
}

// configID identifies a configuration without keeping the key in memory
// twice in clear text.
func configID(c edge.Config) string {
	parts := []string{
		c.APIKey, c.APIURL, c.SiteID, c.Mode,
		strings.Join(c.BlockClasses, ","), strings.Join(c.TrustedProxies, ","), strings.Join(c.IPHeaders, ","),
		c.Timeout.String(), c.CacheTTL.String(), strconv.Itoa(c.CacheSize), c.PolicyTTL.String(),
		c.SkipPaths, c.BlockMessage, strconv.FormatBool(c.Debug),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}
