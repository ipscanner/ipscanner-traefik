package ipscanner_traefik //nolint:revive,stylecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	torIP         = "185.220.101.1"
	vpnIP         = "185.217.69.166"
	residentialIP = "84.128.0.1"
	googlebotIP   = "66.249.66.1"
	testKey       = "pk_test_unit"
	testSite      = "site_traefikunit000000001"
	chrome        = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)

type stubAPI struct {
	*httptest.Server
	mu       sync.Mutex
	checks   int
	policies int
	policy   string // "" = 404
	mode     string // top level edge check mode, "" = absent
	headers  http.Header
	body     map[string]interface{}
}

func newStub(t *testing.T, policy string) *stubAPI {
	t.Helper()
	s := &stubAPI{policy: policy}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

func (s *stubAPI) setPolicy(p string) {
	s.mu.Lock()
	s.policy = p
	s.mu.Unlock()
}

func (s *stubAPI) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checks, s.policies
}

func (s *stubAPI) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+testKey {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if strings.HasPrefix(r.URL.Path, "/v1/sites/") {
		s.policies++
		if s.policy == "" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not found"}`)
			return
		}
		fmt.Fprint(w, s.policy)
		return
	}
	if r.URL.Path != "/v1/edge/check" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	s.checks++
	s.headers = r.Header.Clone()
	s.body = map[string]interface{}{}
	_ = json.NewDecoder(r.Body).Decode(&s.body)
	class, network := "human", "residential_clean"
	agent := `{"class":"human","confidence":0.9,"action":"allow","signals":{}}`
	ip, _ := s.body["ip"].(string) // a typed switch: Yaegi cannot switch on interface{} against strings
	switch ip {
	case torIP:
		class, network = "tor", "tor"
	case vpnIP:
		class, network = "vpn", "vpn"
	case googlebotIP:
		class, network = "verified_bot", "hosting"
		agent = `{"class":"known_bot","confidence":0.99,"action":"allow","signals":{"allowlist_verified":true}}`
	}
	mode := ""
	if s.mode != "" {
		mode = fmt.Sprintf(`"mode":%q,`, s.mode)
	}
	fmt.Fprintf(w, `{"class":%q,%s"agent":%s,"network":{"networkClass":%q,"anonymized":%t,"riskScore":40,"country":"DE"},"site":null}`,
		class, mode, agent, network, class == "tor" || class == "vpn")
}

type upstream struct {
	called bool
	header http.Header
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.called = true
	u.header = r.Header.Clone()
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func newMiddleware(t *testing.T, c *Config) (http.Handler, *upstream) {
	t.Helper()
	next := &upstream{}
	h, err := New(context.Background(), next, c, "ipscanner-test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h, next
}

func visit(h http.Handler, ip, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "http://example.test"+path, nil)
	r.RemoteAddr = "10.0.0.2:41000"
	r.Header.Set("X-Forwarded-For", ip)
	r.Header.Set("User-Agent", chrome)
	r.Header.Set("Accept-Language", "en")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func base(api *stubAPI) *Config {
	c := CreateConfig()
	c.APIKey = testKey
	c.APIURL = api.URL
	c.TrustedProxies = []string{"private"}
	return c
}

func TestCreateConfigIsEmpty(t *testing.T) {
	c := CreateConfig()
	if c.BlockClasses != nil || c.TrustedProxies != nil || c.IPHeaders != nil || c.Mode != "" || c.Debug {
		t.Fatalf("CreateConfig must leave defaults to the core, got %+v", c)
	}
}

func TestLocalEnforceBlocksClass(t *testing.T) {
	api := newStub(t, "")
	c := base(api)
	c.Mode = "enforce"
	c.BlockClasses = []string{"tor"}
	h, next := newMiddleware(t, c)

	w := visit(h, torIP, "/")
	if w.Code != http.StatusForbidden || next.called {
		t.Fatalf("tor: code %d, upstream called %t", w.Code, next.called)
	}
	if !strings.Contains(w.Body.String(), "Request ID") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("block page: %q", w.Body.String())
	}

	w = visit(h, residentialIP, "/")
	if w.Code != http.StatusOK || !next.called {
		t.Fatalf("residential: code %d", w.Code)
	}
	if got := next.header.Get("X-IPScanner-Class"); got != "human" {
		t.Fatalf("upstream class %q", got)
	}
	if got := next.header.Get("X-IPScanner-Action"); got != "allow" {
		t.Fatalf("upstream action %q", got)
	}
	if got := next.header.Get("X-IPScanner-Status"); got != "ok" {
		t.Fatalf("upstream status %q", got)
	}
}

func TestMonitorAccountNeverBlocks(t *testing.T) {
	api := newStub(t, "")
	api.mode = "monitor"
	c := base(api)
	c.Mode = "enforce"
	c.BlockClasses = []string{"tor"}
	h, next := newMiddleware(t, c)
	w := visit(h, torIP, "/")
	if w.Code != http.StatusOK || !next.called {
		t.Fatalf("blocked on a monitor account: %d", w.Code)
	}
	if got := next.header.Get("X-IPScanner-Action"); got != "would_block" {
		t.Fatalf("upstream action %q", got)
	}
}

func TestDefaultsMonitorNeverBlocks(t *testing.T) {
	api := newStub(t, "")
	c := base(api)
	c.BlockClasses = []string{"tor"}
	h, next := newMiddleware(t, c)
	w := visit(h, torIP, "/")
	if w.Code != http.StatusOK || !next.called {
		t.Fatalf("monitor blocked: %d", w.Code)
	}
	if got := next.header.Get("X-IPScanner-Action"); got != "would_block" {
		t.Fatalf("upstream action %q", got)
	}
	if w.Header().Get("X-IPScanner-Class") != "" {
		t.Fatal("response leaked the class without debug")
	}
}

func TestRequestShape(t *testing.T) {
	api := newStub(t, "")
	h, _ := newMiddleware(t, base(api))
	visit(h, residentialIP, "/page")
	api.mu.Lock()
	defer api.mu.Unlock()
	if got := api.headers.Get("User-Agent"); got != "ipscanner-traefik/"+Version {
		t.Fatalf("user agent %q", got)
	}
	if got := api.headers.Get("X-IPScanner-Source"); got != "traefik" {
		t.Fatalf("source %q", got)
	}
	if api.body["ip"] != residentialIP || api.body["user_agent"] != chrome {
		t.Fatalf("body %+v", api.body)
	}
	headers, _ := api.body["headers"].(map[string]interface{})
	if headers["accept-language"] != "en" {
		t.Fatalf("signal headers %+v", headers)
	}
}

func TestSitePolicyBlockFlagAndVerified(t *testing.T) {
	api := newStub(t, `{"mode":"enforce","policy":{"tor":"block","vpn":"flag","verified_bot":"block"},"version":4}`)
	c := base(api)
	c.SiteID = testSite
	c.Debug = true
	h, next := newMiddleware(t, c)

	w := visit(h, torIP, "/")
	if w.Code != http.StatusForbidden || next.called {
		t.Fatalf("tor not blocked: %d", w.Code)
	}
	if w.Header().Get("X-IPScanner-Action") != "block" || w.Header().Get("X-IPScanner-Class") != "tor" {
		t.Fatalf("debug headers %v", w.Header())
	}

	w = visit(h, vpnIP, "/")
	if w.Code != http.StatusOK || next.header.Get("X-IPScanner-Action") != "flag" {
		t.Fatalf("vpn flag: %d %q", w.Code, next.header.Get("X-IPScanner-Action"))
	}
	if next.header.Get("X-IPScanner-Site") != testSite {
		t.Fatalf("site header %q", next.header.Get("X-IPScanner-Site"))
	}

	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.RemoteAddr = googlebotIP + ":5000"
	r.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("X-IPScanner-Class") != "verified_bot" {
		t.Fatalf("verified crawler: %d %v", w.Code, w.Header())
	}
}

func TestSiteMonitorOverride(t *testing.T) {
	api := newStub(t, `{"mode":"enforce","policy":{"tor":"block"},"version":1}`)
	c := base(api)
	c.SiteID = testSite
	c.Mode = "monitor"
	h, next := newMiddleware(t, c)
	w := visit(h, torIP, "/")
	if w.Code != http.StatusOK || next.header.Get("X-IPScanner-Action") != "would_block" {
		t.Fatalf("monitor override: %d %q", w.Code, next.header.Get("X-IPScanner-Action"))
	}
}

func TestSiteWithoutPolicyPasses(t *testing.T) {
	api := newStub(t, "")
	c := base(api)
	c.SiteID = testSite
	h, next := newMiddleware(t, c)
	if w := visit(h, torIP, "/"); w.Code != http.StatusOK || !next.called {
		t.Fatalf("no policy: %d", w.Code)
	}
}

func TestPolicyRefreshAfterTTL(t *testing.T) {
	api := newStub(t, `{"mode":"enforce","policy":{"tor":"allow"},"version":1}`)
	c := base(api)
	c.SiteID = testSite
	c.PolicyTTL = "200ms"
	h, _ := newMiddleware(t, c)
	if w := visit(h, torIP, "/"); w.Code != http.StatusOK {
		t.Fatalf("allowed before change: %d", w.Code)
	}
	api.setPolicy(`{"mode":"enforce","policy":{"tor":"block"},"version":2}`)
	if w := visit(h, torIP, "/"); w.Code != http.StatusOK {
		t.Fatalf("policy changed inside the TTL: %d", w.Code)
	}
	time.Sleep(300 * time.Millisecond)
	if w := visit(h, torIP, "/"); w.Code != http.StatusForbidden {
		t.Fatalf("new policy not applied after the TTL: %d", w.Code)
	}
}

func TestVerdictCacheSharedAcrossReloads(t *testing.T) {
	api := newStub(t, "")
	c := base(api)
	h, _ := newMiddleware(t, c)
	visit(h, residentialIP, "/")
	visit(h, residentialIP, "/other")

	// Traefik calls New again on a reload or for another router: same guard.
	again, _ := newMiddleware(t, base(api))
	visit(again, residentialIP, "/")
	if checks, _ := api.counts(); checks != 1 {
		t.Fatalf("edge checks %d, want 1", checks)
	}
}

func TestSkipPathsAndOptions(t *testing.T) {
	api := newStub(t, "")
	h, next := newMiddleware(t, base(api))
	visit(h, torIP, "/app.css")
	visit(h, torIP, "/robots.txt")
	if next.header.Get("X-IPScanner-Status") != "skipped" {
		t.Fatalf("status %q", next.header.Get("X-IPScanner-Status"))
	}
	r := httptest.NewRequest(http.MethodOptions, "http://example.test/", nil)
	r.RemoteAddr = torIP + ":1"
	h.ServeHTTP(httptest.NewRecorder(), r)
	if checks, _ := api.counts(); checks != 0 {
		t.Fatalf("skipped requests were checked: %d", checks)
	}

	c := base(api)
	c.SkipPaths = "none"
	h, _ = newMiddleware(t, c)
	visit(h, torIP, "/app.css")
	if checks, _ := api.counts(); checks != 1 {
		t.Fatalf("skipPaths none: checks %d", checks)
	}
}

func TestSpoofedForwardedForIgnored(t *testing.T) {
	api := newStub(t, "")
	c := base(api)
	c.TrustedProxies = nil
	c.Mode = "enforce"
	c.BlockClasses = []string{"tor"}
	h, next := newMiddleware(t, c)
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.RemoteAddr = residentialIP + ":4000"
	r.Header.Set("X-Forwarded-For", torIP)
	r.Header.Set("X-IPScanner-Class", "human")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("spoofed tor header blocked a residential peer: %d", w.Code)
	}
	if got := next.header.Get("X-IPScanner-Class"); got != "human" {
		t.Fatalf("class %q", got)
	}
	api.mu.Lock()
	ip := api.body["ip"]
	api.mu.Unlock()
	if ip != residentialIP {
		t.Fatalf("checked %v, want the peer", ip)
	}
}

func TestIncomingHeadersStripped(t *testing.T) {
	h, next := newMiddleware(t, &Config{APIURL: "http://127.0.0.1:1"})
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.Header.Set("X-IPScanner-Class", "verified_bot")
	r.Header.Set("X-Ipscanner-Action", "allow")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if next.header.Get("X-IPScanner-Class") != "" || next.header.Get("X-IPScanner-Action") != "" {
		t.Fatalf("spoofed verdict reached the upstream: %v", next.header)
	}
}

func TestFailOpenWithBackoff(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	dead := srv.URL
	srv.Close()

	c := &Config{APIKey: testKey, APIURL: dead, Mode: "enforce", BlockClasses: []string{"tor"}, TrustedProxies: []string{"private"}, Timeout: "300ms"}
	h, next := newMiddleware(t, c)
	start := time.Now()
	w := visit(h, torIP, "/")
	if w.Code != http.StatusOK || !next.called || next.header.Get("X-IPScanner-Status") != "error" {
		t.Fatalf("fail open: %d %q", w.Code, next.header.Get("X-IPScanner-Status"))
	}
	w = visit(h, torIP, "/")
	if w.Code != http.StatusOK || next.header.Get("X-IPScanner-Status") != "backoff" {
		t.Fatalf("backoff: %d %q", w.Code, next.header.Get("X-IPScanner-Status"))
	}
	if time.Since(start) > time.Second {
		t.Fatalf("fail open took %s", time.Since(start))
	}
}

func TestTimeoutFailsOpen(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	t.Cleanup(slow.Close)
	c := &Config{APIKey: testKey, APIURL: slow.URL, Mode: "enforce", BlockClasses: []string{"tor"}, TrustedProxies: []string{"private"}, Timeout: "200ms"}
	h, next := newMiddleware(t, c)
	start := time.Now()
	w := visit(h, torIP, "/")
	if w.Code != http.StatusOK || next.header.Get("X-IPScanner-Status") != "timeout" {
		t.Fatalf("timeout: %d %q", w.Code, next.header.Get("X-IPScanner-Status"))
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("timeout took %s", d)
	}
}

func TestNoKeyPassesThrough(t *testing.T) {
	t.Setenv(KeyEnv, "")
	h, next := newMiddleware(t, &Config{Mode: "enforce", APIURL: "http://127.0.0.1:1"})
	w := visit(h, torIP, "/")
	if w.Code != http.StatusOK || next.header.Get("X-IPScanner-Status") != "skipped" {
		t.Fatalf("no key: %d %q", w.Code, next.header.Get("X-IPScanner-Status"))
	}
}

func TestAPIKeySources(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "key")
	if err := os.WriteFile(file, []byte(" pk_test_file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(KeyEnv, "pk_test_env")

	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{"literal wins", Config{APIKey: "pk_test_literal", APIKeyFile: file}, "pk_test_literal"},
		{"file", Config{APIKeyFile: file}, "pk_test_file"},
		{"env", Config{}, "pk_test_env"},
	} {
		if tc.name == "env" && os.Getenv(KeyEnv) != "pk_test_env" {
			// yaegi test keeps its own environment; the Traefik e2e covers it.
			continue
		}
		got, err := apiKey(&tc.cfg)
		if err != nil || got != tc.want {
			t.Fatalf("%s: got %q, %v", tc.name, got, err)
		}
	}

	if _, err := apiKey(&Config{APIKeyFile: filepath.Join(dir, "missing")}); err == nil {
		t.Fatal("missing key file must fail")
	}
	empty := filepath.Join(dir, "empty")
	_ = os.WriteFile(empty, []byte("\n"), 0o600)
	if _, err := apiKey(&Config{APIKeyFile: empty}); err == nil {
		t.Fatal("empty key file must fail")
	}
}

func TestInvalidConfig(t *testing.T) {
	for _, c := range []Config{
		{Mode: "block"},
		{SiteID: "abc"},
		{BlockClasses: []string{"human"}},
		{TrustedProxies: []string{"not-an-ip"}},
		{Timeout: "2"},
		{CacheTTL: "soon"},
		{PolicyTTL: "-1s"},
		{CacheSize: -1},
		{SkipPaths: "("},
		{APIURL: "ftp://example.com"},
	} {
		c := c
		if _, err := New(context.Background(), http.NotFoundHandler(), &c, "x"); err == nil {
			t.Fatalf("config %+v accepted", c)
		} else if !strings.HasPrefix(err.Error(), "ipscanner: ") {
			t.Fatalf("error %q", err)
		}
	}
}

func TestCommaSeparatedLists(t *testing.T) {
	api := newStub(t, "")
	c := base(api)
	c.Mode = "enforce"
	c.BlockClasses = []string{"vpn, tor"}
	h, _ := newMiddleware(t, c)
	if w := visit(h, vpnIP, "/"); w.Code != http.StatusForbidden {
		t.Fatalf("vpn: %d", w.Code)
	}
	if w := visit(h, torIP, "/"); w.Code != http.StatusForbidden {
		t.Fatalf("tor: %d", w.Code)
	}
}

func TestGuardsBounded(t *testing.T) {
	for i := 0; i < maxGuards+5; i++ {
		c := &Config{APIURL: fmt.Sprintf("http://127.0.0.1:%d", 20000+i)}
		if _, err := New(context.Background(), http.NotFoundHandler(), c, "x"); err != nil {
			t.Fatal(err)
		}
	}
	guardsMu.Lock()
	n, order := len(guards), len(guardsOrder)
	guardsMu.Unlock()
	if n > maxGuards || order != n {
		t.Fatalf("guards %d order %d", n, order)
	}
}
