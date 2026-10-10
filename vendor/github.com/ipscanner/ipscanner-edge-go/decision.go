package edge

import (
	"html"
	"net/http"
	"strconv"
)

// Decision is the outcome of a check.
type Decision struct {
	// Status is ok, error, timeout, backoff or skipped. Anything but ok
	// means the request passes unchecked (fail open).
	Status string
	// Class is the traffic class, "" when Status is not ok.
	Class string
	// Action is what to do with the request: allow, flag or block. It is
	// allow in monitor mode whatever the policy says.
	Action string
	// Outcome is the policy result: allow, flag, block, or would_flag and
	// would_block in monitor mode.
	Outcome string
	// Mode is monitor or enforce, "" when Status is not ok.
	Mode string
	// Site is the configured site, or "".
	Site string
	// PolicyVersion and PolicySource (cache, fetch, stale, none, or config
	// without a site) describe the policy that was applied.
	PolicyVersion int
	PolicySource  string
	// Cached is true when the verdict came from the cache (no API call).
	Cached bool
	// IP is the visitor address that was checked.
	IP string
	// RequestID was sent with the check and is shown on the block page.
	RequestID string
	// Verdict is the API answer, nil when Status is not ok.
	Verdict *Verdict
}

// Blocked reports whether the request must get the block page.
func (d Decision) Blocked() bool { return d.Action == ActionBlock }

// Headers are the X-IPScanner-* headers for the upstream request. When the
// check failed or was skipped only X-IPScanner-Status is set.
func (d Decision) Headers() map[string]string {
	h := map[string]string{"X-IPScanner-Status": d.Status}
	if d.Status != StatusOK || d.Verdict == nil {
		return h
	}
	h["X-IPScanner-Class"] = d.Class
	h["X-IPScanner-Action"] = d.Outcome
	v := d.Verdict
	networkClass := ""
	anonymized := false
	if v.Network != nil {
		networkClass = v.Network.NetworkClass
		anonymized = v.Network.Anonymized
		if v.Network.RiskScore != nil {
			h["X-IPScanner-Risk"] = strconv.FormatFloat(*v.Network.RiskScore, 'f', -1, 64)
		}
		if v.Network.Country != "" {
			h["X-IPScanner-Country"] = v.Network.Country
		}
	}
	if v.Agent != nil {
		if networkClass == "" {
			if s, ok := v.Agent.Signals["network_origin"].(string); ok {
				networkClass = s
			}
		}
		if b, ok := v.Agent.Signals["anonymized"].(bool); ok && b {
			anonymized = true
		}
	}
	if networkClass != "" {
		h["X-IPScanner-Network-Class"] = networkClass
	}
	h["X-IPScanner-Anonymized"] = strconv.FormatBool(anonymized)
	if d.Site != "" {
		h["X-IPScanner-Site"] = d.Site
	}
	return h
}

// DebugHeaders are the headers added to the response with Config.Debug:
// X-IPScanner-Status, -Class and -Action.
func (d Decision) DebugHeaders() map[string]string {
	h := map[string]string{"X-IPScanner-Status": d.Status}
	if d.Class != "" {
		h["X-IPScanner-Class"] = d.Class
	}
	if d.Status == StatusOK && d.Outcome != "" {
		h["X-IPScanner-Action"] = d.Outcome
	}
	return h
}

// isVerified reports whether the visitor is a verified crawler. Verified
// crawlers always pass.
func isVerified(v *Verdict) bool {
	if v.Class == ClassVerifiedBot {
		return true
	}
	if v.Agent != nil {
		if b, ok := v.Agent.Signals["allowlist_verified"].(bool); ok && b {
			return true
		}
	}
	return false
}

// networkTrafficClass is the traffic class a network class implies, or "".
func networkTrafficClass(networkClass string) string {
	switch networkClass {
	case "tor":
		return ClassTor
	case "vpn":
		return ClassVPN
	case "residential_proxy":
		return ClassProxy
	case "relay":
		return ClassRelay
	case "hosting", "datacenter":
		return ClassHosting
	}
	return ""
}

func rank(action string) int {
	switch action {
	case ActionBlock:
		return 2
	case ActionFlag:
		return 1
	}
	return 0
}

// decide maps a verdict to a class and the policy action for it. With
// matchNetwork the network class counts too, so a bot on a VPN is blocked
// when either malicious_automation or vpn is blocked. The site policy
// matches the traffic class only, like the Worker.
func decide(v *Verdict, actions map[string]string, matchNetwork bool) (string, string) {
	class := v.Class
	if class == "" {
		class = ClassHuman
	}
	if isVerified(v) {
		return class, ActionAllow
	}
	candidates := []string{class}
	if matchNetwork && v.Network != nil {
		if implied := networkTrafficClass(v.Network.NetworkClass); implied != "" && implied != class {
			candidates = append(candidates, implied)
		}
	}
	action := ActionAllow
	for _, c := range candidates {
		if a, ok := actions[c]; ok && rank(a) > rank(action) {
			action = a
		}
	}
	return class, action
}

// BlockPage is the HTML of the 403 page.
func BlockPage(requestID, message string) []byte {
	if message == "" {
		message = DefaultBlockMessage
	}
	body := `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Blocked</title><style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;line-height:1.5}code{background:#eee;padding:0 .25rem}</style></head><body><h1>Access denied</h1><p>` +
		html.EscapeString(message) + `</p>`
	if requestID != "" {
		body += `<p>Request ID: <code>` + html.EscapeString(requestID) + `</code></p>`
	}
	return []byte(body + `</body></html>`)
}

// WriteBlocked writes the 403 block page.
func (g *Guard) WriteBlocked(w http.ResponseWriter, d Decision) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(BlockPage(d.RequestID, g.s.blockMessage))
}
