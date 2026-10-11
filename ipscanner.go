// Package ipscanner_traefik is the IPScanner Traefik middleware; Yaegi loads it, so stdlib and the edge core only.
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

const Version = "0.1.0"

const Source = "traefik"

// KeyEnv is read when neither apiKey nor apiKeyFile is set.
const KeyEnv = "IPSCANNER_API_KEY"

// Config durations are Go duration strings; empty values use the core defaults.
type Config struct {
	// APIKey shows in the Traefik dashboard and API; prefer apiKeyFile or IPSCANNER_API_KEY.
	APIKey     string `json:"apiKey,omitempty" yaml:"apiKey,omitempty"`
	APIKeyFile string `json:"apiKeyFile,omitempty" yaml:"apiKeyFile,omitempty"`
	SiteID     string `json:"siteId,omitempty" yaml:"siteId,omitempty"`
	// Mode is monitor or enforce; with siteId only monitor has an effect.
	Mode string `json:"mode,omitempty" yaml:"mode,omitempty"`
	// BlockClasses apply in enforce mode without siteId.
	BlockClasses []string `json:"blockClasses,omitempty" yaml:"blockClasses,omitempty"`
	// TrustedProxies are the only peers whose IP headers are believed (also private, cloudflare).
	TrustedProxies []string `json:"trustedProxies,omitempty" yaml:"trustedProxies,omitempty"`
	IPHeaders      []string `json:"ipHeaders,omitempty" yaml:"ipHeaders,omitempty"`
	Timeout        string   `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	CacheTTL       string   `json:"cacheTTL,omitempty" yaml:"cacheTTL,omitempty"`
	CacheSize      int      `json:"cacheSize,omitempty" yaml:"cacheSize,omitempty"`
	PolicyTTL      string   `json:"policyTTL,omitempty" yaml:"policyTTL,omitempty"`
	// SkipPaths is a case insensitive regex; "none" checks every path.
	SkipPaths    string `json:"skipPaths,omitempty" yaml:"skipPaths,omitempty"`
	BlockMessage string `json:"blockMessage,omitempty" yaml:"blockMessage,omitempty"`
	// Debug adds X-IPScanner-Status, -Class and -Action to responses and logs every decision.
	Debug  bool   `json:"debug,omitempty" yaml:"debug,omitempty"`
	APIURL string `json:"apiUrl,omitempty" yaml:"apiUrl,omitempty"`
}

// CreateConfig leaves lists nil: Traefik decodes into it and a default list would keep extra entries.
func CreateConfig() *Config {
	return &Config{}
}

type Middleware struct {
	next  http.Handler
	guard *edge.Guard
}

// New shares one guard per configuration, since Traefik calls it per router and on every reload.
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

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.guard.Handle(w, r); !ok {
		return
	}
	m.next.ServeHTTP(w, r)
}

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

// logLine writes to stdout, where Traefik expects plugin logs.
func logLine(line string) {
	_, _ = os.Stdout.WriteString(line + "\n")
}

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

// maxGuards drops the oldest guards that reloads leave behind.
const maxGuards = 32

var (
	guardsMu    sync.Mutex
	guards      = map[string]*edge.Guard{}
	guardsOrder []string
)

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

// configID hashes the config so the key is not kept twice in clear text.
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
