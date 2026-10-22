package ipscanner_traefik //nolint:revive,stylecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	edge "github.com/ipscanner/ipscanner-edge-go"
)

func sameConfig(a, b edge.Config) bool {
	return a.APIKey == b.APIKey && a.APIURL == b.APIURL && a.SiteID == b.SiteID && a.Mode == b.Mode &&
		strings.Join(a.BlockClasses, ",") == strings.Join(b.BlockClasses, ",") &&
		strings.Join(a.TrustedProxies, ",") == strings.Join(b.TrustedProxies, ",") &&
		strings.Join(a.IPHeaders, ",") == strings.Join(b.IPHeaders, ",") &&
		a.Timeout == b.Timeout && a.CacheTTL == b.CacheTTL && a.CacheSize == b.CacheSize && a.PolicyTTL == b.PolicyTTL &&
		a.SkipPaths == b.SkipPaths && a.BlockMessage == b.BlockMessage && a.Debug == b.Debug
}

// FuzzConfigID checks that two routers share a guard only when their configurations are the same.
func FuzzConfigID(f *testing.F) {
	f.Add("pk_a", "https://ipscanner.io", "site_a", "tor", "Blocked", "pk_a", "https://ipscanner.io", "site_a", "tor", "Blocked")
	f.Add("pk_a", "", "", "tor,vpn", "", "pk_a", "", "", "tor, vpn", "")
	f.Add("pk_a\x00x", "", "site_a", "", "", "pk_a", "x\x00", "site_a", "", "")
	f.Add("pk_a", "u", "", "", "msg", "pk_a", "", "u", "", "msg")
	f.Fuzz(func(t *testing.T, key1, url1, site1, classes1, msg1, key2, url2, site2, classes2, msg2 string) {
		a := edge.Config{APIKey: key1, APIURL: url1, SiteID: site1, BlockClasses: []string{classes1}, BlockMessage: msg1, Timeout: time.Second}
		b := edge.Config{APIKey: key2, APIURL: url2, SiteID: site2, BlockClasses: []string{classes2}, BlockMessage: msg2, Timeout: time.Second}
		if (configID(a) == configID(b)) != sameConfig(a, b) {
			t.Fatalf("configID collision or split:\n%+v\n%+v", a, b)
		}
	})
}

type fuzzUpstream struct {
	called bool
	header http.Header
}

func (u *fuzzUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.called = true
	u.header = r.Header.Clone()
	w.WriteHeader(http.StatusOK)
}

// FuzzMiddleware feeds dynamic configuration and visitor headers through the plugin:
// bad config fails with an ipscanner error, and forged X-IPScanner-* headers never reach the upstream.
func FuzzMiddleware(f *testing.F) {
	api := &stubAPI{}
	api.Server = httptest.NewServer(http.HandlerFunc(api.serve))
	defer api.Close()

	f.Add("enforce", "tor,vpn", "private", "", "1500ms", "10m", "30s", 0, "", false, "203.0.113.9:443", torIP, "X-IPScanner-Class", "human")
	f.Add("enforce", "tor", "private", "X-Real-IP", "", "", "", 10, "none", true, "10.0.0.2:443", torIP, "x-ipscanner-action", "allow")
	f.Add("monitor", "", "10.0.0.0/8, cloudflare", "", "2s", "", "", 0, `\.css$`, false, "10.0.0.2:443", "1.2.3.4, "+vpnIP, "X-Ipscanner-Status", "ok")
	f.Add("", "none", "", "", "1ns", "-1s", "soon", -1, "(", false, "[2001:db8::1]:1", "", "Cookie", "c=1")
	f.Add("block", "human", "not-an-ip", "", "2", "", "", 0, "", false, "nonsense", residentialIP, "X-IPSCANNER-SITE", "site_x")
	f.Fuzz(func(t *testing.T, mode, classes, trusted, ipHeader, timeout, cacheTTL, policyTTL string, cacheSize int, skip string, debug bool,
		remote, xff, forgedName, forgedValue string) {
		c := &Config{
			APIKey: testKey, APIURL: api.URL, Mode: mode, BlockClasses: []string{classes},
			TrustedProxies: []string{trusted}, IPHeaders: []string{ipHeader},
			Timeout: timeout, CacheTTL: cacheTTL, PolicyTTL: policyTTL, CacheSize: cacheSize,
			SkipPaths: skip, Debug: debug,
		}
		if cfg, err := edgeConfig(c); err == nil {
			if cfg.Timeout < 0 || cfg.CacheTTL < 0 || cfg.PolicyTTL < 0 || cfg.CacheSize < 0 {
				t.Fatalf("negative limits accepted: %+v", cfg)
			}
		}
		next := &fuzzUpstream{}
		h, err := New(context.Background(), next, c, "fuzz")
		if err != nil {
			if !strings.HasPrefix(err.Error(), "ipscanner: ") {
				t.Fatalf("error %q", err)
			}
			return
		}

		r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", xff)
		r.Header.Set("User-Agent", chrome)
		r.Header.Set("X-IPScanner-Class", "verified_bot")
		r.Header[forgedName] = append(r.Header[forgedName], forgedValue)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		if w.Code == http.StatusForbidden {
			if next.called {
				t.Fatal("blocked request reached the upstream")
			}
			return
		}
		if !next.called {
			t.Fatalf("request neither blocked nor passed: %d", w.Code)
		}
		status := next.header.Get("X-IPScanner-Status")
		if status == "" {
			t.Fatal("upstream got no X-IPScanner-Status")
		}
		allowed := map[string]bool{
			"X-Ipscanner-Status": true, "X-Ipscanner-Class": true, "X-Ipscanner-Action": true,
			"X-Ipscanner-Risk": true, "X-Ipscanner-Country": true, "X-Ipscanner-Network-Class": true,
			"X-Ipscanner-Anonymized": true, "X-Ipscanner-Site": true,
		}
		for name, values := range next.header {
			canonical := http.CanonicalHeaderKey(name)
			if !strings.HasPrefix(canonical, edge.HeaderPrefix) {
				continue
			}
			if name != canonical || !allowed[name] || len(values) != 1 {
				t.Fatalf("visitor header %s: %q reached the upstream", name, values)
			}
			if status != edge.StatusOK && name != "X-Ipscanner-Status" {
				t.Fatalf("status %s but upstream got %s: %q", status, name, values)
			}
		}
	})
}
