package edge

import (
	"html"
	"net/http"
	"strconv"
)

type Decision struct {
	// Status other than ok means the request passed unchecked (fail open).
	Status string
	Class  string
	// Action is always allow in monitor mode.
	Action string
	// Outcome is the policy result, would_flag or would_block in monitor mode.
	Outcome string
	Mode    string
	Site    string
	// PolicySource is cache, fetch, stale, none, or config without a site.
	PolicyVersion int
	PolicySource  string
	Cached        bool
	IP            string
	RequestID     string
	Verdict       *Verdict
}

func (d Decision) Blocked() bool { return d.Action == ActionBlock }

// Headers are the upstream X-IPScanner-* headers; only Status unless the check succeeded.
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
	return safeHeaders(h)
}

func (d Decision) DebugHeaders() map[string]string {
	h := map[string]string{"X-IPScanner-Status": d.Status}
	if d.Class != "" {
		h["X-IPScanner-Class"] = d.Class
	}
	if d.Status == StatusOK && d.Outcome != "" {
		h["X-IPScanner-Action"] = d.Outcome
	}
	return safeHeaders(h)
}

// safeHeaders drops values with control characters, which would make the proxied request fail.
func safeHeaders(h map[string]string) map[string]string {
	for name, value := range h {
		for i := 0; i < len(value); i++ {
			if c := value[i]; (c < 0x20 && c != '\t') || c == 0x7f {
				delete(h, name)
				break
			}
		}
	}
	return h
}

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

// decide matches the network class only with matchNetwork; site policies match the traffic class only, like the Worker.
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

func (g *Guard) WriteBlocked(w http.ResponseWriter, d Decision) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(BlockPage(d.RequestID, g.s.blockMessage))
}
