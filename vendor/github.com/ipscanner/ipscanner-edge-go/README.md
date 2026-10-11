# ipscanner-edge-go

Shared Go core of the [IPScanner](https://ipscanner.io) proxy integrations: the Traefik plugin, the Caddy module and the forward auth gate. It checks a visitor with `POST /v1/edge/check`, applies the site policy from the [dashboard](https://ipscanner.io/dashboard/sites) or the local configuration, and fails open.

## Install

```sh
go get github.com/ipscanner/ipscanner-edge-go
```

Requires Go 1.22 or later.

## Usage

```go
import edge "github.com/ipscanner/ipscanner-edge-go"

guard, err := edge.New(edge.Config{
	APIKey:  os.Getenv("IPSCANNER_API_KEY"),
	SiteID:  "site_...",
	Source:  "caddy",
	Client:  "caddy",
	Version: "0.1.0",
})
```

Create one `Guard` per configuration and keep it: the caches and the backoff live in it.

```go
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.guard.Handle(w, r); !ok {
		return // 403 page written
	}
	m.next.ServeHTTP(w, r)
}
```

`Handle` strips incoming `X-IPScanner-*` headers, resolves the client IP, checks it, adds the verdict headers to the request for the upstream and writes the block page when needed. For a forward auth endpoint use the parts: `ClientIP`, `TrustedPeer` (whether to believe `X-Forwarded-Uri` and friends), `CheckVisitor`, `Decision.Headers`, `WriteBlocked`.

## How it works

| | |
|---|---|
| Classes | `human`, `verified_bot`, `ai_agent`, `malicious_automation`, `tor`, `vpn`, `proxy`, `hosting`, `relay` |
| Without `SiteID` | `Mode` (default `monitor`) and `BlockClasses` (default `malicious_automation`) from the config. The network class counts too, so blocking `vpn` also blocks a bot on a VPN. |
| With `SiteID` | Mode and per class policy (`allow`, `flag`, `block`) from `GET /v1/sites/{id}/policy`, cached 30 s, last good policy kept for 24 h if a refresh fails, retried after 5 s. A 404 means no policy: requests pass. `Mode: monitor` keeps the guard in monitor mode whatever the dashboard says. |
| Always pass | Verified crawlers, `OPTIONS`, private and loopback addresses, paths matching `SkipPaths`. |
| Cache | One check per visitor (site, IP, user agent) per 10 minutes, in memory, bounded to 10000 entries. Concurrent requests from one visitor share one call. |
| Fail open | One 1.5 s budget for verdict and policy. On a timeout or error the request passes and checks pause for 30 s (5 minutes on 401, 402, 403 or 429). |
| Blocked | 403 page with the request ID. `monitor` never blocks: the outcome is `would_block` or `would_flag`. |
| Visitor IP | The peer address. IP headers (default `X-Forwarded-For`) only when the peer is a trusted proxy; in a chain the nearest untrusted hop is the visitor. |
| Debug | `Debug: true` adds `X-IPScanner-Status`, `-Class` and `-Action` to responses and logs every decision as JSON. |

Requests send `Authorization: Bearer <key>`, `X-IPScanner-Source: <Source>` and `User-Agent: ipscanner-<Client>/<Version>`. Each uncached visitor costs one edge check (2 request units).

## Configuration

| Field | Default | Description |
|---|---|---|
| `APIKey` | | API key. Without it every request passes with status `skipped`. |
| `APIURL` | `https://ipscanner.io` | API base URL. |
| `SiteID` | | Dashboard site (`site_...`). Mode and policy then come from the dashboard. |
| `Mode` | `monitor` | `monitor` or `enforce`. With `SiteID` only `monitor` has an effect. |
| `BlockClasses` | `malicious_automation` | Classes blocked in enforce mode without `SiteID`. Any of `malicious_automation`, `ai_agent`, `tor`, `vpn`, `proxy`, `hosting`, `relay`, or `none`. |
| `TrustedProxies` | | Addresses and CIDR ranges whose IP headers are trusted. `private` adds the private and loopback ranges, `cloudflare` the Cloudflare edge ranges. |
| `IPHeaders` | `X-Forwarded-For` | Headers read, in order, from a trusted proxy. Behind Cloudflare: `CF-Connecting-IP`. |
| `Timeout` | `1.5s` | Budget for one check. |
| `CacheTTL` | `10m` | Verdict cache per site, IP and user agent. |
| `CacheSize` | `10000` | Verdict cache entries. |
| `PolicyTTL` | `30s` | Site policy cache. |
| `SkipPaths` | static assets | Case insensitive regex on the path, the Worker's default. `none` checks every path. |
| `Source` | | `X-IPScanner-Source` value: `traefik`, `caddy`, `forward_auth`. |
| `Client`, `Version` | `edge-go`, package version | User-Agent `ipscanner-<Client>/<Version>`. |
| `BlockMessage` | `Blocked by IPScanner edge guard.` | Text of the 403 page. |
| `Debug` | `false` | Response debug headers and one log line per decision. |
| `HTTPClient` | no redirects | Client for the API calls. |
| `Logger` | standard logger | Receives JSON log lines. |

List fields accept comma separated entries (`"tor, vpn"`). `New` returns an error for an invalid value.

## Decision

| Field | Values |
|---|---|
| `Status` | `ok`, `error`, `timeout`, `backoff`, `skipped` |
| `Class` | Traffic class, empty unless `ok` |
| `Action` | `allow`, `flag`, `block`: what to do with the request |
| `Outcome` | `allow`, `flag`, `block`, `would_flag`, `would_block` |
| `Mode` | `monitor`, `enforce` |
| `PolicySource` | `cache`, `fetch`, `stale`, `none`, or `config` without a site |
| `Cached` | Verdict served from the cache |

## Headers

Added to the upstream request by `Handle` (`Decision.Headers`):

| Header | Example |
|---|---|
| `X-IPScanner-Status` | `ok`, `error`, `timeout`, `backoff` or `skipped` |
| `X-IPScanner-Class` | `human`, `verified_bot`, `vpn`, ... |
| `X-IPScanner-Action` | `allow`, `flag`, `block`, `would_flag`, `would_block` |
| `X-IPScanner-Network-Class` | `residential_clean`, `hosting`, `vpn`, `tor`, ... |
| `X-IPScanner-Anonymized` | `true` or `false` |
| `X-IPScanner-Risk` | `0` to `100` |
| `X-IPScanner-Country` | `DE` |
| `X-IPScanner-Site` | `site_...`, set with `SiteID` |

When a check fails or is skipped, only `X-IPScanner-Status` is set.

## Develop

```sh
go test -race ./...
sh test/yaegi/run.sh     # runs test/yaegi/main.go under Yaegi against a stub API
IPSCANNER_KEY_FILE=/path/to/key IPSCANNER_E2E_SITE_HELPER=/path/to/site.cjs sh test/e2e/run.sh
```

The end to end run needs an API on `IPSCANNER_API_URL` (default `http://localhost:3050`) and a helper script that upserts a test site and lists request log rows.

API reference: [ipscanner.io/api-documentation](https://ipscanner.io/api-documentation).

## License

MIT
