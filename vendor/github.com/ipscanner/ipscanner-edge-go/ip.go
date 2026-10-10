package edge

import (
	"errors"
	"net"
	"net/http"
	"strings"
)

// cloudflareRanges are the Cloudflare edge ranges from
// https://www.cloudflare.com/ips/ (same list as the WordPress plugin).
var cloudflareRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

// privateRanges are the private, loopback and unique local ranges, where a
// proxy in the same network or on the same host lives.
var privateRanges = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
	"::1/128", "fc00::/7",
}

type ipRange struct {
	net *net.IPNet
}

// parseRanges parses addresses, CIDR ranges and the keywords "private" and
// "cloudflare".
func parseRanges(entries []string) ([]ipRange, error) {
	var out []ipRange
	for _, entry := range entries {
		switch strings.ToLower(entry) {
		case "private":
			more, _ := parseRanges(privateRanges)
			out = append(out, more...)
			continue
		case "cloudflare":
			more, _ := parseRanges(cloudflareRanges)
			out = append(out, more...)
			continue
		}
		cidr := entry
		if !strings.Contains(cidr, "/") {
			ip := normalizeIP(cidr)
			if ip == "" {
				return nil, errors.New("ipscanner: trustedProxies: " + entry + " is not an address or CIDR range")
			}
			if strings.Contains(ip, ":") {
				cidr = ip + "/128"
			} else {
				cidr = ip + "/32"
			}
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, errors.New("ipscanner: trustedProxies: " + entry + " is not an address or CIDR range")
		}
		out = append(out, ipRange{net: n})
	}
	return out, nil
}

func inRanges(ip string, ranges []ipRange) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, r := range ranges {
		if r.net.Contains(parsed) {
			return true
		}
	}
	return false
}

// normalizeIP returns the address in canonical form, or "" when the value is
// not an IP. It accepts "1.2.3.4:80" and "[2001:db8::1]:443" as sent by some
// proxies, and turns IPv4-mapped IPv6 into IPv4.
func normalizeIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if value[0] == '[' {
		end := strings.IndexByte(value, ']')
		if end < 0 {
			return ""
		}
		value = value[1:end]
	} else if strings.Count(value, ":") == 1 && strings.Contains(value, ".") {
		value = value[:strings.IndexByte(value, ':')]
	}
	if i := strings.IndexByte(value, '%'); i >= 0 {
		value = value[:i]
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// isPublic reports whether the address is routable on the internet. Private,
// loopback, link local and unspecified addresses are never checked.
func isPublic(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsUnspecified() ||
		parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() ||
		parsed.IsMulticast() || parsed.IsInterfaceLocalMulticast() {
		return false
	}
	return true
}

// remoteIP is the peer address of the request.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return normalizeIP(host)
}

// ClientIP returns the visitor's address. IP headers are read only when the
// peer (RemoteAddr) is a trusted proxy, so visitors cannot spoof them. In an
// X-Forwarded-For chain the nearest hop that is not a trusted proxy is the
// visitor. Returns "" when no valid address is known.
func (g *Guard) ClientIP(r *http.Request) string {
	return clientIP(r, g.s.trusted, g.s.ipHeaders)
}

// TrustedPeer reports whether the peer (RemoteAddr) of r is a trusted proxy,
// so headers it sets, such as X-Forwarded-Uri in a forward auth request, can
// be believed.
func (g *Guard) TrustedPeer(r *http.Request) bool {
	remote := remoteIP(r)
	return remote != "" && inRanges(remote, g.s.trusted)
}

func clientIP(r *http.Request, trusted []ipRange, headers []string) string {
	remote := remoteIP(r)
	if remote == "" || len(trusted) == 0 || !inRanges(remote, trusted) {
		return remote
	}
	for _, name := range headers {
		values := r.Header.Values(name)
		if len(values) == 0 {
			continue
		}
		var chain []string
		for _, v := range values {
			chain = append(chain, strings.Split(v, ",")...)
		}
		return walkChain(chain, trusted, remote)
	}
	return remote
}

// walkChain walks the chain from the nearest hop back. The first hop that is
// not a trusted proxy is the visitor. An invalid hop stops the walk: the
// last valid hop (or the peer) is used, since anything before it is not
// vouched for.
func walkChain(chain []string, trusted []ipRange, remote string) string {
	first := ""
	for i := len(chain) - 1; i >= 0; i-- {
		hop := normalizeIP(chain[i])
		if hop == "" {
			if first == "" {
				return remote
			}
			return first
		}
		first = hop
		if !inRanges(hop, trusted) {
			return hop
		}
	}
	if first == "" {
		return remote
	}
	return first
}
