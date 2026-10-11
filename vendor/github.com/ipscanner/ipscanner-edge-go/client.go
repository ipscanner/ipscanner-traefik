package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
)

// Verdict is the POST /v1/edge/check answer; Agent, Network and Site are nil when missing.
type Verdict struct {
	Class    string   `json:"class"`
	Agent    *Agent   `json:"agent"`
	Network  *Network `json:"network"`
	Site     *SiteRef `json:"site"`
	Degraded []string `json:"degraded,omitempty"`
}

// Agent is the Agentscan half of a verdict.
type Agent struct {
	Class      string                 `json:"class"`
	Confidence float64                `json:"confidence"`
	Action     string                 `json:"action"`
	Signals    map[string]interface{} `json:"signals"`
}

type Network struct {
	NetworkClass string   `json:"networkClass"`
	Anonymized   bool     `json:"anonymized"`
	RiskScore    *float64 `json:"riskScore"`
	Provider     string   `json:"provider,omitempty"`
	Country      string   `json:"country,omitempty"`
	ASN          int64    `json:"asn,omitempty"`
	ASNName      string   `json:"asnName,omitempty"`
}

type SiteRef struct {
	ID            string `json:"id"`
	Mode          string `json:"mode"`
	PolicyVersion int    `json:"policyVersion"`
}

type Policy struct {
	Mode    string
	Actions map[string]string
	Version int
}

type checkBody struct {
	Site      string            `json:"site,omitempty"`
	IP        string            `json:"ip"`
	UserAgent string            `json:"user_agent"`
	JA4       string            `json:"ja4,omitempty"`
	Headers   map[string]string `json:"headers"`
	RequestID string            `json:"request_id,omitempty"`
}

type policyBody struct {
	Mode    string            `json:"mode"`
	Policy  map[string]string `json:"policy"`
	Version int               `json:"version"`
}

type apiResult struct {
	code   int
	body   []byte
	status string
	err    error
}

const maxBody = 1 << 20

// defaultHTTPClient never follows redirects.
func defaultHTTPClient() *http.Client {
	var transport http.RoundTripper = http.DefaultTransport
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		clone := t.Clone()
		clone.MaxIdleConnsPerHost = 32
		transport = clone
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (g *Guard) call(ctx context.Context, method, path string, body interface{}) apiResult {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return apiResult{status: StatusError, err: err}
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, g.s.apiURL+path, reader)
	if err != nil {
		return apiResult{status: StatusError, err: err}
	}
	req.Header.Set("Authorization", "Bearer "+g.s.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", g.s.userAgent)
	if g.s.source != "" {
		req.Header.Set("X-IPScanner-Source", g.s.source)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := g.http.Do(req)
	if err != nil {
		return apiResult{status: failureStatus(ctx, err), err: err}
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return apiResult{code: res.StatusCode, status: failureStatus(ctx, err), err: err}
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		msg := string(data)
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return apiResult{code: res.StatusCode, body: data, status: StatusError,
			err: errors.New("ipscanner " + path + " " + strconv.Itoa(res.StatusCode) + " " + msg)}
	}
	return apiResult{code: res.StatusCode, body: data, status: StatusOK}
}

func failureStatus(ctx context.Context, err error) string {
	if ctx.Err() == context.DeadlineExceeded || errors.Is(err, context.DeadlineExceeded) {
		return StatusTimeout
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return StatusTimeout
	}
	return StatusError
}

func (g *Guard) postCheck(ctx context.Context, v Visitor) (*Verdict, apiResult) {
	res := g.call(ctx, http.MethodPost, "/v1/edge/check", checkBody{
		Site:      g.s.siteID,
		IP:        v.IP,
		UserAgent: v.UserAgent,
		JA4:       v.JA4,
		Headers:   v.Headers,
		RequestID: v.RequestID,
	})
	if res.status != StatusOK {
		return nil, res
	}
	var out Verdict
	if err := json.Unmarshal(res.body, &out); err != nil || out.Class == "" {
		res.status = StatusError
		res.err = errors.New("ipscanner /v1/edge/check: unexpected response")
		return nil, res
	}
	return &out, res
}

func (g *Guard) getPolicy(ctx context.Context) (*Policy, apiResult) {
	res := g.call(ctx, http.MethodGet, "/v1/sites/"+url.PathEscape(g.s.siteID)+"/policy", nil)
	if res.status != StatusOK {
		return nil, res
	}
	var body policyBody
	if err := json.Unmarshal(res.body, &body); err != nil {
		res.status = StatusError
		res.err = errors.New("ipscanner policy: unexpected response")
		return nil, res
	}
	return toPolicy(body), res
}

func toPolicy(b policyBody) *Policy {
	p := &Policy{Mode: ModeMonitor, Actions: map[string]string{}, Version: b.Version}
	if b.Mode == ModeEnforce {
		p.Mode = ModeEnforce
	}
	for class, action := range b.Policy {
		if !contains(Classes, class) {
			continue
		}
		if action == ActionAllow || action == ActionFlag || action == ActionBlock {
			p.Actions[class] = action
		}
	}
	return p
}
