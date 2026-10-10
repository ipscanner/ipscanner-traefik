// Package edge is the shared core of the IPScanner proxy integrations
// (Traefik, Caddy, forward auth). It checks a visitor with
// POST /v1/edge/check, applies the site policy from
// GET /v1/sites/{id}/policy or the local configuration, and fails open.
//
// The package uses the standard library only and runs under Yaegi.
package edge

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Version is the version of this package.
const Version = "0.1.0"

// Modes.
const (
	ModeMonitor = "monitor"
	ModeEnforce = "enforce"
)

// Actions a policy assigns to a traffic class.
const (
	ActionAllow = "allow"
	ActionFlag  = "flag"
	ActionBlock = "block"
)

// Statuses of a check (Decision.Status, header X-IPScanner-Status).
const (
	StatusOK      = "ok"
	StatusError   = "error"
	StatusTimeout = "timeout"
	StatusBackoff = "backoff"
	StatusSkipped = "skipped"
)

// Traffic classes returned by the edge check.
const (
	ClassHuman               = "human"
	ClassVerifiedBot         = "verified_bot"
	ClassAIAgent             = "ai_agent"
	ClassMaliciousAutomation = "malicious_automation"
	ClassTor                 = "tor"
	ClassVPN                 = "vpn"
	ClassProxy               = "proxy"
	ClassHosting             = "hosting"
	ClassRelay               = "relay"
)

// Classes lists every traffic class.
var Classes = []string{
	ClassHuman, ClassVerifiedBot, ClassAIAgent, ClassMaliciousAutomation,
	ClassTor, ClassVPN, ClassProxy, ClassHosting, ClassRelay,
}

// BlockableClasses are the classes Config.BlockClasses accepts.
var BlockableClasses = []string{
	ClassMaliciousAutomation, ClassAIAgent, ClassTor, ClassVPN,
	ClassProxy, ClassHosting, ClassRelay,
}

// Defaults.
const (
	DefaultAPIURL    = "https://ipscanner.io"
	DefaultTimeout   = 1500 * time.Millisecond
	DefaultCacheTTL  = 10 * time.Minute
	DefaultPolicyTTL = 30 * time.Second
	DefaultCacheSize = 10000
	// DefaultSkipPaths is the Cloudflare Worker's SKIP_PATHS default:
	// robots.txt, sitemap.xml, favicon.ico and static assets.
	DefaultSkipPaths = `^/(robots\.txt|sitemap\.xml|favicon\.ico)$|\.(css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|otf|eot|mp4|webm)$`
	// DefaultBlockMessage is the text of the block page.
	DefaultBlockMessage = "Blocked by IPScanner edge guard."
)

// Fixed timings, the same as the WordPress plugin and the Worker.
const (
	policyStale      = 24 * time.Hour
	policyRetryGap   = 5 * time.Second
	policyMinRefresh = 5 * time.Second
	backoffError     = 30 * time.Second
	backoffAuth      = 5 * time.Minute
)

// None turns off SkipPaths or BlockClasses.
const None = "none"

// Config configures a Guard. The zero value of every field is a usable
// default except APIKey: without a key every request passes unchecked.
type Config struct {
	// APIKey is the IPScanner API key (pk_live_... or pk_test_...).
	APIKey string
	// APIURL is the API base URL. Default https://ipscanner.io.
	APIURL string
	// SiteID is the dashboard site (site_...). When set, mode and per class
	// policy come from the dashboard.
	SiteID string
	// Mode is monitor or enforce. Without SiteID it decides whether blocked
	// classes get a 403 (default monitor). With SiteID, "monitor" keeps the
	// guard in monitor mode whatever the dashboard says; other values follow
	// the dashboard.
	Mode string
	// BlockClasses are blocked in enforce mode without SiteID. Default
	// malicious_automation. "none" blocks nothing. The network class counts
	// too: blocking vpn also blocks a bot on a VPN.
	BlockClasses []string
	// TrustedProxies are addresses or CIDR ranges whose IP headers are
	// trusted. "private" adds the private and loopback ranges, "cloudflare"
	// the Cloudflare edge ranges. Default none: the peer address is used.
	TrustedProxies []string
	// IPHeaders are read, in order, when the peer is a trusted proxy.
	// Default X-Forwarded-For.
	IPHeaders []string
	// Timeout is the budget for one check, verdict and policy together.
	// Default 1.5s. On timeout the request passes.
	Timeout time.Duration
	// CacheTTL is how long a verdict is reused per site, IP and user agent.
	// Default 10m.
	CacheTTL time.Duration
	// CacheSize bounds the verdict cache. Default 10000 entries.
	CacheSize int
	// PolicyTTL is how long a site policy is reused. Default 30s.
	PolicyTTL time.Duration
	// SkipPaths is a case insensitive regular expression on the path.
	// Matching requests are not checked. Default DefaultSkipPaths, "none"
	// checks every path.
	SkipPaths string
	// Source is sent as X-IPScanner-Source (traefik, caddy, forward_auth).
	Source string
	// Client and Version make the User-Agent ipscanner-<Client>/<Version>.
	// Default ipscanner-edge-go/<package version>.
	Client  string
	Version string
	// BlockMessage is the text of the 403 page. Default DefaultBlockMessage.
	BlockMessage string
	// Debug adds X-IPScanner-Status, -Class and -Action to responses and
	// logs every decision.
	Debug bool
	// HTTPClient makes the API calls. Default: a client that does not
	// follow redirects.
	HTTPClient *http.Client
	// Logger receives one JSON line per failure (and per decision with
	// Debug). Default: the standard logger.
	Logger func(line string)
}

// DefaultConfig returns a Config with every default filled in.
func DefaultConfig() Config {
	return Config{
		APIURL:       DefaultAPIURL,
		Mode:         ModeMonitor,
		BlockClasses: []string{ClassMaliciousAutomation},
		IPHeaders:    []string{"X-Forwarded-For"},
		Timeout:      DefaultTimeout,
		CacheTTL:     DefaultCacheTTL,
		CacheSize:    DefaultCacheSize,
		PolicyTTL:    DefaultPolicyTTL,
		SkipPaths:    DefaultSkipPaths,
		BlockMessage: DefaultBlockMessage,
	}
}

// settings is a validated Config.
type settings struct {
	apiKey       string
	apiURL       string
	siteID       string
	mode         string // "", monitor or enforce, as configured
	block        map[string]bool
	local        map[string]string // block as a policy: class -> block
	trusted      []ipRange
	ipHeaders    []string
	timeout      time.Duration
	cacheTTL     time.Duration
	cacheSize    int
	policyTTL    time.Duration
	skip         *regexp.Regexp
	source       string
	userAgent    string
	blockMessage string
	debug        bool
}

// splitList splits every entry on commas and trims it, so "tor, vpn" and
// ["tor", "vpn"] mean the same.
func splitList(in []string) []string {
	var out []string
	for _, entry := range in {
		for _, part := range strings.Split(entry, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func validSiteID(id string) bool {
	if len(id) <= len("site_") || len(id) > 32 || !strings.HasPrefix(id, "site_") {
		return false
	}
	for _, r := range id[len("site_"):] {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func validToken(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == '+') {
			return false
		}
	}
	return true
}

func validate(cfg Config) (settings, error) {
	s := settings{
		apiKey:       strings.TrimSpace(cfg.APIKey),
		siteID:       strings.TrimSpace(cfg.SiteID),
		mode:         strings.ToLower(strings.TrimSpace(cfg.Mode)),
		source:       strings.ToLower(strings.TrimSpace(cfg.Source)),
		blockMessage: strings.TrimSpace(cfg.BlockMessage),
		debug:        cfg.Debug,
		timeout:      cfg.Timeout,
		cacheTTL:     cfg.CacheTTL,
		cacheSize:    cfg.CacheSize,
		policyTTL:    cfg.PolicyTTL,
	}

	base := strings.TrimRight(strings.TrimSpace(cfg.APIURL), "/")
	if base == "" {
		base = DefaultAPIURL
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return s, errors.New("ipscanner: apiUrl must be an http or https URL")
	}
	s.apiURL = base

	if s.siteID != "" && !validSiteID(s.siteID) {
		return s, errors.New("ipscanner: siteId must look like site_ followed by letters and digits")
	}
	if s.mode != "" && s.mode != ModeMonitor && s.mode != ModeEnforce {
		return s, errors.New("ipscanner: mode must be monitor or enforce")
	}

	s.block = map[string]bool{}
	classes := splitList(cfg.BlockClasses)
	if len(classes) == 0 {
		classes = []string{ClassMaliciousAutomation}
	}
	for _, c := range classes {
		c = strings.ToLower(c)
		if c == None {
			s.block = map[string]bool{}
			break
		}
		if !contains(BlockableClasses, c) {
			return s, errors.New("ipscanner: blockClasses: " + c + " is not one of " + strings.Join(BlockableClasses, ", "))
		}
		s.block[c] = true
	}

	s.local = map[string]string{}
	for c := range s.block {
		s.local[c] = ActionBlock
	}

	trusted, err := parseRanges(splitList(cfg.TrustedProxies))
	if err != nil {
		return s, err
	}
	s.trusted = trusted

	for _, h := range splitList(cfg.IPHeaders) {
		s.ipHeaders = append(s.ipHeaders, http.CanonicalHeaderKey(h))
	}
	if len(s.ipHeaders) == 0 {
		s.ipHeaders = []string{"X-Forwarded-For"}
	}

	if s.timeout <= 0 {
		s.timeout = DefaultTimeout
	}
	if s.cacheTTL <= 0 {
		s.cacheTTL = DefaultCacheTTL
	}
	if s.cacheSize <= 0 {
		s.cacheSize = DefaultCacheSize
	}
	if s.policyTTL <= 0 {
		s.policyTTL = DefaultPolicyTTL
	}

	skip := strings.TrimSpace(cfg.SkipPaths)
	if skip == "" {
		skip = DefaultSkipPaths
	}
	if !strings.EqualFold(skip, None) {
		re, err := regexp.Compile("(?i)" + skip)
		if err != nil {
			return s, errors.New("ipscanner: skipPaths is not a valid regular expression: " + err.Error())
		}
		s.skip = re
	}

	if s.source != "" && !validToken(s.source) {
		return s, errors.New("ipscanner: source must be a short token such as traefik")
	}
	client := strings.TrimSpace(cfg.Client)
	version := strings.TrimSpace(cfg.Version)
	if client == "" {
		client = "edge-go"
		if version == "" {
			version = Version
		}
	}
	if version == "" {
		version = "0.0.0"
	}
	if !validToken(client) || !validToken(version) {
		return s, errors.New("ipscanner: client and version must be short tokens")
	}
	s.userAgent = "ipscanner-" + client + "/" + version

	if s.blockMessage == "" {
		s.blockMessage = DefaultBlockMessage
	}
	return s, nil
}
