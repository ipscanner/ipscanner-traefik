package edge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Guard is safe for concurrent use; keep one per configuration, it holds the caches and the backoff.
type Guard struct {
	s     settings
	http  *http.Client
	log   func(string)
	now   func() time.Time
	cache *verdictCache

	mu           sync.Mutex
	flights      map[string]*flight
	backoffUntil time.Time
	lastStatus   string
	lastCode     int
	lastError    string
	lastErrorAt  time.Time

	pmu          sync.Mutex
	policy       *policyEntry
	policyRetry  time.Time
	policyFlight chan struct{}
}

// flight lets concurrent requests from one visitor share a single API call.
type flight struct {
	done    chan struct{}
	verdict *Verdict
	status  string
}

type policyEntry struct {
	policy    *Policy
	fetchedAt time.Time
}

type Visitor struct {
	IP        string
	UserAgent string
	Method    string
	Path      string
	JA4       string
	// RequestID is generated when empty.
	RequestID string
	Headers   map[string]string
}

// New returns a Guard that, without an API key, passes every request with status skipped.
func New(cfg Config) (*Guard, error) {
	s, err := validate(cfg)
	if err != nil {
		return nil, err
	}
	g := &Guard{
		s:       s,
		http:    cfg.HTTPClient,
		log:     cfg.Logger,
		now:     time.Now,
		cache:   newVerdictCache(s.cacheSize, s.cacheTTL),
		flights: map[string]*flight{},
	}
	if g.http == nil {
		g.http = defaultHTTPClient()
	}
	if g.log == nil {
		g.log = func(line string) { log.Println(line) }
	}
	if s.apiKey == "" {
		g.logJSON(map[string]interface{}{"ipscanner": "no API key is set, passing requests through unchecked"})
	}
	return g, nil
}

// Enabled reports whether an API key is set.
func (g *Guard) Enabled() bool { return g.s.apiKey != "" }

func (g *Guard) Debug() bool { return g.s.debug }

func (g *Guard) SiteID() string { return g.s.siteID }

func (g *Guard) UserAgent() string { return g.s.userAgent }

func (g *Guard) logJSON(fields map[string]interface{}) {
	line, err := json.Marshal(fields)
	if err != nil {
		return
	}
	g.log(string(line))
}

func VisitorFrom(r *http.Request, ip string) Visitor {
	v := Visitor{
		IP:        ip,
		UserAgent: r.Header.Get("User-Agent"),
		Method:    r.Method,
		Headers:   SignalHeaders(r.Header),
	}
	if r.URL != nil {
		v.Path = r.URL.Path
	}
	if id := strings.TrimSpace(r.Header.Get("X-Request-Id")); validToken(id) {
		v.RequestID = id
	}
	return v
}

// SignalHeaders keeps Accept*, Sec-CH-UA* and Sec-Fetch-* with lower case names and values cut to 512 bytes.
func SignalHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for name, values := range h {
		lower := strings.ToLower(name)
		keep := lower == "accept" || lower == "accept-language" || lower == "accept-encoding" ||
			strings.HasPrefix(lower, "sec-ch-ua") || strings.HasPrefix(lower, "sec-fetch-")
		if !keep || len(values) == 0 {
			continue
		}
		value := strings.Join(values, ", ")
		if len(value) > 512 {
			value = value[:512]
		}
		out[lower] = value
	}
	return out
}

const HeaderPrefix = "X-Ipscanner-"

// StripHeaders drops incoming X-IPScanner-* headers so a client cannot forge a verdict upstream.
func StripHeaders(h http.Header) {
	var drop []string
	for name := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), HeaderPrefix) {
			drop = append(drop, name)
		}
	}
	for _, name := range drop {
		delete(h, name)
	}
}

// Check never fails: on timeout, error or backoff the request is allowed and Status says why.
func (g *Guard) Check(ctx context.Context, r *http.Request, ip string) Decision {
	return g.CheckVisitor(ctx, VisitorFrom(r, ip))
}

// Handle is the whole middleware step; it returns false after writing the block page.
func (g *Guard) Handle(w http.ResponseWriter, r *http.Request) (Decision, bool) {
	StripHeaders(r.Header)
	d := g.Check(r.Context(), r, g.ClientIP(r))
	for name, value := range d.Headers() {
		r.Header.Set(name, value)
	}
	if g.s.debug {
		for name, value := range d.DebugHeaders() {
			w.Header().Set(name, value)
		}
	}
	if d.Blocked() {
		g.WriteBlocked(w, d)
		return d, false
	}
	return d, true
}

func (g *Guard) CheckVisitor(ctx context.Context, v Visitor) Decision {
	v.IP = normalizeIP(v.IP)
	d := Decision{
		Status:  StatusSkipped,
		Action:  ActionAllow,
		Outcome: ActionAllow,
		Site:    g.s.siteID,
		IP:      v.IP,
	}
	if g.s.apiKey == "" || v.IP == "" || !isPublic(v.IP) || strings.EqualFold(v.Method, http.MethodOptions) ||
		(g.s.skip != nil && g.s.skip.MatchString(v.Path)) {
		return d
	}
	if v.RequestID == "" {
		v.RequestID = newRequestID()
	}
	if len(v.UserAgent) > 512 {
		v.UserAgent = v.UserAgent[:512]
	}
	if v.Headers == nil {
		v.Headers = map[string]string{}
	}
	d.RequestID = v.RequestID

	ctx, cancel := context.WithTimeout(ctx, g.s.timeout)
	defer cancel()

	key := cacheKey(g.s.siteID, v.IP, v.UserAgent)
	verdict, status := g.lookup(key)
	d.Cached = verdict != nil
	if status == StatusBackoff {
		d.Status = status
		return d
	}

	var policy *Policy
	source := "config"
	if verdict == nil {
		if g.s.siteID != "" {
			ch := make(chan policyResult, 1)
			go func() {
				p, src := g.sitePolicy(ctx, 0)
				ch <- policyResult{policy: p, source: src}
			}()
			verdict, status = g.await(ctx, key, v)
			res := <-ch
			policy, source = res.policy, res.source
		} else {
			verdict, status = g.await(ctx, key, v)
		}
	} else if g.s.siteID != "" {
		policy, source = g.sitePolicy(ctx, 0)
	}

	if verdict == nil {
		d.Status = status
		g.logJSON(map[string]interface{}{"ip": v.IP, "path": v.Path, "site": g.s.siteID, "status": status, "decision": ActionAllow})
		return d
	}

	if g.s.siteID != "" && verdict.Site != nil && verdict.Site.PolicyVersion > policyVersion(policy) {
		policy, source = g.sitePolicy(ctx, verdict.Site.PolicyVersion)
	}

	d.Status = StatusOK
	d.Verdict = verdict
	d.PolicySource = source
	d.PolicyVersion = policyVersion(policy)

	var actions map[string]string
	matchNetwork := false
	d.Mode = ModeMonitor
	if g.s.siteID != "" {
		if policy != nil {
			actions = policy.Actions
			if policy.Mode == ModeEnforce && g.s.mode != ModeMonitor {
				d.Mode = ModeEnforce
			}
		}
	} else {
		actions = g.s.local
		matchNetwork = true
		if g.s.mode == ModeEnforce {
			d.Mode = ModeEnforce
		}
	}
	if verdict.Mode == ModeMonitor {
		d.Mode = ModeMonitor
	}

	d.Class, d.Action = decide(verdict, actions, matchNetwork)
	d.Outcome = d.Action
	if d.Action != ActionAllow && d.Mode != ModeEnforce {
		d.Outcome = "would_" + d.Action
		d.Action = ActionAllow
	}

	if g.s.debug {
		cache := "miss"
		if d.Cached {
			cache = "hit"
		}
		networkClass := ""
		if verdict.Network != nil {
			networkClass = verdict.Network.NetworkClass
		}
		g.logJSON(map[string]interface{}{
			"ip":           v.IP,
			"path":         v.Path,
			"site":         g.s.siteID,
			"trafficClass": d.Class,
			"networkClass": networkClass,
			"decision":     d.Outcome,
			"mode":         d.Mode,
			"policy":       map[string]interface{}{"source": d.PolicySource, "version": d.PolicyVersion},
			"cache":        map[string]interface{}{"edge": cache},
		})
	}
	return d
}

type policyResult struct {
	policy *Policy
	source string
}

func policyVersion(p *Policy) int {
	if p == nil {
		return 0
	}
	return p.Version
}

func cacheKey(site, ip, userAgent string) string {
	sum := sha256.Sum256([]byte(site + "|" + ip + "|" + userAgent))
	return hex.EncodeToString(sum[:])
}

func newRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func (g *Guard) lookup(key string) (*Verdict, string) {
	now := g.now()
	if v := g.cache.get(key, now); v != nil {
		return v, StatusOK
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Before(g.backoffUntil) {
		return nil, StatusBackoff
	}
	return nil, ""
}

// await runs the call detached with its own timeout, so a slow answer is still cached.
func (g *Guard) await(ctx context.Context, key string, v Visitor) (*Verdict, string) {
	g.mu.Lock()
	f := g.flights[key]
	if f == nil {
		f = &flight{done: make(chan struct{})}
		g.flights[key] = f
		go g.runCheck(key, f, v)
	}
	g.mu.Unlock()

	select {
	case <-f.done:
		return f.verdict, f.status
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return nil, StatusTimeout
		}
		return nil, StatusError
	}
}

func (g *Guard) runCheck(key string, f *flight, v Visitor) {
	var verdict *Verdict
	status := StatusError
	defer func() {
		if p := recover(); p != nil {
			verdict, status = nil, StatusError
			g.logJSON(map[string]interface{}{"ipscanner": "edge check panic", "message": fmt.Sprint(p)})
		}
		g.mu.Lock()
		delete(g.flights, key)
		f.verdict, f.status = verdict, status
		g.mu.Unlock()
		close(f.done)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), g.s.timeout)
	defer cancel()
	out, res := g.postCheck(ctx, v)
	if out != nil {
		g.cache.set(key, out, g.now())
		verdict, status = out, StatusOK
		return
	}
	status = res.status
	g.fail(res)
}

// fail backs off 30s, or 5m on 401/402/403/429; a 400 concerns one visitor and pauses nothing.
func (g *Guard) fail(res apiResult) {
	pause := backoffError
	switch res.code {
	case 400:
		pause = 0
	case 401, 402, 403, 429:
		pause = backoffAuth
	}
	message := ""
	if res.err != nil {
		message = res.err.Error()
	}
	now := g.now()
	g.mu.Lock()
	if pause > 0 {
		g.backoffUntil = now.Add(pause)
	}
	g.lastStatus, g.lastCode, g.lastError, g.lastErrorAt = res.status, res.code, message, now
	g.mu.Unlock()
	g.logJSON(map[string]interface{}{
		"ipscanner": "upstream failure",
		"key":       "edge",
		"status":    res.status,
		"code":      res.code,
		"message":   message,
		"backoff":   int(pause / time.Second),
	})
}

// sitePolicy falls back to the last policy for 24h on failure; minVersion forces a refresh at most every 5s.
func (g *Guard) sitePolicy(ctx context.Context, minVersion int) (*Policy, string) {
	g.pmu.Lock()
	now := g.now()
	before := g.policy
	if before != nil {
		age := now.Sub(before.fetchedAt)
		if age < g.s.policyTTL && (policyVersion(before.policy) >= minVersion || age < policyMinRefresh) {
			g.pmu.Unlock()
			return before.policy, sourceOf(before.policy, "cache")
		}
	}
	if now.Before(g.policyRetry) {
		p, src := g.stalePolicy(now)
		g.pmu.Unlock()
		return p, src
	}
	ch := g.policyFlight
	if ch == nil {
		ch = make(chan struct{})
		g.policyFlight = ch
		go g.fetchPolicy(ch)
	}
	g.pmu.Unlock()

	select {
	case <-ch:
	case <-ctx.Done():
	}

	g.pmu.Lock()
	defer g.pmu.Unlock()
	now = g.now()
	if e := g.policy; e != nil && e != before && now.Sub(e.fetchedAt) < g.s.policyTTL {
		return e.policy, sourceOf(e.policy, "fetch")
	}
	if e := g.policy; e != nil && now.Sub(e.fetchedAt) < g.s.policyTTL {
		return e.policy, sourceOf(e.policy, "cache")
	}
	return g.stalePolicy(now)
}

func sourceOf(p *Policy, source string) string {
	if p == nil {
		return "none"
	}
	return source
}

// stalePolicy requires pmu held.
func (g *Guard) stalePolicy(now time.Time) (*Policy, string) {
	if e := g.policy; e != nil && e.policy != nil && now.Sub(e.fetchedAt) < policyStale {
		return e.policy, "stale"
	}
	return nil, "none"
}

func (g *Guard) fetchPolicy(ch chan struct{}) {
	defer func() {
		if p := recover(); p != nil {
			g.logJSON(map[string]interface{}{"ipscanner": "policy fetch panic", "message": fmt.Sprint(p)})
		}
		g.pmu.Lock()
		g.policyFlight = nil
		g.pmu.Unlock()
		close(ch)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), g.s.timeout)
	defer cancel()
	p, res := g.getPolicy(ctx)

	g.pmu.Lock()
	now := g.now()
	switch {
	case res.status == StatusOK:
		g.policy = &policyEntry{policy: p, fetchedAt: now}
		g.policyRetry = time.Time{}
	case res.code == 404:
		g.policy = &policyEntry{fetchedAt: now}
		g.policyRetry = time.Time{}
	default:
		gap := policyRetryGap
		if g.s.policyTTL < gap {
			gap = g.s.policyTTL
		}
		g.policyRetry = now.Add(gap)
	}
	g.pmu.Unlock()

	if res.status != StatusOK && res.code != 404 {
		message := ""
		if res.err != nil {
			message = res.err.Error()
		}
		g.logJSON(map[string]interface{}{
			"ipscanner": "upstream failure",
			"key":       "policy",
			"status":    res.status,
			"code":      res.code,
			"message":   message,
		})
	}
}

type State struct {
	Enabled      bool
	SiteID       string
	BackoffUntil time.Time
	// LastStatus, LastCode and LastError describe the last failed edge check.
	LastStatus      string
	LastCode        int
	LastError       string
	LastErrorAt     time.Time
	Policy          *Policy
	PolicyFetchedAt time.Time
	CachedVerdicts  int
}

func (g *Guard) State() State {
	st := State{Enabled: g.Enabled(), SiteID: g.s.siteID, CachedVerdicts: g.cache.len()}
	g.mu.Lock()
	if g.now().Before(g.backoffUntil) {
		st.BackoffUntil = g.backoffUntil
	}
	st.LastStatus, st.LastCode, st.LastError, st.LastErrorAt = g.lastStatus, g.lastCode, g.lastError, g.lastErrorAt
	g.mu.Unlock()
	g.pmu.Lock()
	if g.policy != nil {
		st.Policy, st.PolicyFetchedAt = g.policy.policy, g.policy.fetchedAt
	}
	g.pmu.Unlock()
	return st
}
