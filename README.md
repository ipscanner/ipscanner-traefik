# IPScanner for Traefik

Traefik middleware plugin that checks every visitor with [IPScanner](https://ipscanner.io) and blocks bots, Tor, VPN and proxy traffic by your site policy from the [dashboard](https://ipscanner.io/dashboard/sites).

## Install

Declare the plugin in the static configuration:

```yaml
experimental:
  plugins:
    ipscanner:
      moduleName: github.com/ipscanner/ipscanner-traefik
      version: v0.1.2
```

CLI flags: `--experimental.plugins.ipscanner.modulename=github.com/ipscanner/ipscanner-traefik` and `--experimental.plugins.ipscanner.version=v0.1.2`.

Then add a middleware with your Site ID and put it on a router.

### Coolify

1. Servers > your server > Proxy. Add the two flags to the `command` list and the key to `environment` (create it next to `command` if it is missing). Save, then Restart Proxy:

   ```yaml
   services:
     traefik:
       command:
         # ...the flags Coolify set
         - '--experimental.plugins.ipscanner.modulename=github.com/ipscanner/ipscanner-traefik'
         - '--experimental.plugins.ipscanner.version=v0.1.2'
       environment:
         - IPSCANNER_API_KEY=pk_live_...
   ```

   See [API key](#api-key) for other ways to pass the key.

2. Your app > Container Labels. Set Label management to edit by hand (older Coolify: untick Readonly labels), or the next deploy overwrites your labels. Append the middleware to the `middlewares` label of each `https-N-<uuid>` router Coolify generated, define it, then Deploy:

   ```
   traefik.http.routers.https-0-<uuid>.middlewares=gzip,ipscanner-myapp
   traefik.http.middlewares.ipscanner-myapp.plugin.ipscanner.siteId=site_...
   ```

   Behind Cloudflare (orange cloud), also add:

   ```
   traefik.http.middlewares.ipscanner-myapp.plugin.ipscanner.trustedProxies=cloudflare
   traefik.http.middlewares.ipscanner-myapp.plugin.ipscanner.ipHeaders=CF-Connecting-IP
   ```

   Use one middleware name per app. Traefik drops a middleware that two containers define differently, and every router using it.

### Docker Compose

```yaml
services:
  traefik:
    image: traefik:v3.7
    command:
      - --providers.docker=true
      - --entrypoints.web.address=:80
      - --experimental.plugins.ipscanner.modulename=github.com/ipscanner/ipscanner-traefik
      - --experimental.plugins.ipscanner.version=v0.1.2
    environment:
      IPSCANNER_API_KEY: ${IPSCANNER_API_KEY}
    ports: ["80:80"]
    volumes: ["/var/run/docker.sock:/var/run/docker.sock:ro"]

  app:
    image: traefik/whoami:v1.11.0
    labels:
      - traefik.enable=true
      - traefik.http.routers.app.rule=Host(`example.com`)
      - traefik.http.routers.app.middlewares=ipscanner
      - traefik.http.middlewares.ipscanner.plugin.ipscanner.siteId=site_...
```

Other routers reuse it as `ipscanner@docker`. Full file: [examples/docker-compose.yml](examples/docker-compose.yml).

### Kubernetes

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: ipscanner
spec:
  plugin:
    ipscanner:
      apiKey: urn:k8s:secret:ipscanner:apiKey
      siteId: site_...
```

Reference it from an `IngressRoute` (`middlewares: [{name: ipscanner}]`) or an `Ingress` (`traefik.ingress.kubernetes.io/router.middlewares: <namespace>-ipscanner@kubernetescrd`). With Secret and IngressRoute: [examples/kubernetes.yml](examples/kubernetes.yml).

### File provider

```yaml
http:
  middlewares:
    ipscanner:
      plugin:
        ipscanner:
          apiKeyFile: /run/secrets/ipscanner_api_key
          siteId: site_...
```

More: [examples/dynamic.yml](examples/dynamic.yml).

## API key

Plugin options show in the Traefik dashboard and API. Keep the key out of them:

| Where | How |
|---|---|
| Environment | `IPSCANNER_API_KEY` on the Traefik container. Used by every middleware without `apiKey` or `apiKeyFile`. |
| File | `apiKeyFile: /run/secrets/ipscanner_api_key`, a Docker or Kubernetes secret mounted into Traefik. |
| Kubernetes | `apiKey: urn:k8s:secret:<secret>:<key>`, resolved by the Kubernetes CRD provider. |
| Inline | `apiKey: pk_live_...`. Simplest, visible in the dashboard. |

Without a key every request passes with `X-IPScanner-Status: skipped`.

## How it works

| | |
|---|---|
| Classes | `human`, `verified_bot`, `ai_agent`, `malicious_automation`, `tor`, `vpn`, `proxy`, `hosting`, `relay` |
| Without `siteId` | `mode` (default `monitor`) and `blockClasses` (default `malicious_automation`) from the options. The network class counts too, so blocking `vpn` also blocks a bot on a VPN. |
| With `siteId` | Mode and per class policy (`allow`, `flag`, `block`) from `GET /v1/sites/{id}/policy`, cached 30 s, last good policy kept for 24 h if a refresh fails. Changes apply without a reload. |
| Always pass | Verified crawlers, `OPTIONS`, private addresses, paths matching `skipPaths`. |
| Cache | One check per visitor (site, IP, user agent) per 10 minutes, in memory, up to 10000 visitors. Kept across configuration reloads. |
| Fail open | Timeout 1.5 s. On a timeout or error the request passes and checks pause for 30 s (5 minutes on 401, 402, 403 or 429). |
| Blocked | 403 page with the request ID. `monitor` never blocks. |
| Visitor IP | The address Traefik sees. `X-Forwarded-For` (or `ipHeaders`) only from `trustedProxies`. Traefik drops `X-Forwarded-For` from peers outside the entry point's `forwardedHeaders.trustedIPs`, so set both or use `CF-Connecting-IP`. |
| Debug | `debug: true` adds `X-IPScanner-Status`, `-Class` and `-Action` to responses and logs every decision. |

Requests send `X-IPScanner-Source: traefik` and `User-Agent: ipscanner-traefik/<version>`.

## Configuration

| Option | Default | Description |
|---|---|---|
| `apiKey` | | API key. See [API key](#api-key). |
| `apiKeyFile` | | File holding the API key. |
| `siteId` | | Dashboard site (`site_...`). Mode and policy then come from the dashboard. |
| `mode` | `monitor` | `monitor` or `enforce`. With `siteId` only `monitor` has an effect: it keeps the site in monitor mode. |
| `blockClasses` | `malicious_automation` | Classes blocked in enforce mode without `siteId`: `malicious_automation`, `ai_agent`, `tor`, `vpn`, `proxy`, `hosting`, `relay`, or `none`. |
| `trustedProxies` | | Addresses and CIDR ranges whose IP headers are trusted. `private` adds the private ranges, `cloudflare` the Cloudflare ranges. |
| `ipHeaders` | `X-Forwarded-For` | Headers read from a trusted proxy, in order. Behind Cloudflare: `CF-Connecting-IP`. |
| `timeout` | `1500ms` | Budget for one check. |
| `cacheTTL` | `10m` | Verdict cache per visitor. |
| `cacheSize` | `10000` | Verdict cache entries. |
| `policyTTL` | `30s` | Site policy cache. |
| `skipPaths` | static assets | Case insensitive regex on the path, unchecked when it matches. `none` checks every path. |
| `blockMessage` | `Blocked by IPScanner edge guard.` | Text of the 403 page. |
| `debug` | `false` | Response headers and one log line per decision. |
| `apiUrl` | `https://ipscanner.io` | API base URL. |

Lists take YAML lists or comma separated values (`blockClasses=tor,vpn` in labels). Durations use Go syntax: `1500ms`, `30s`, `10m`. An invalid option disables the router with an error in the Traefik log.

## Headers

Added to the request your upstream receives. Incoming `X-IPScanner-*` headers are removed first.

| Header | Example |
|---|---|
| `X-IPScanner-Status` | `ok`, `error`, `timeout`, `backoff` or `skipped` |
| `X-IPScanner-Class` | `human`, `verified_bot`, `vpn`, ... |
| `X-IPScanner-Action` | `allow`, `flag`, `block`, `would_flag`, `would_block` |
| `X-IPScanner-Network-Class` | `residential_clean`, `hosting`, `vpn`, `tor`, ... |
| `X-IPScanner-Anonymized` | `true` or `false` |
| `X-IPScanner-Risk` | `0` to `100` |
| `X-IPScanner-Country` | `DE` |
| `X-IPScanner-Site` | `site_...` |

## Develop

```sh
go test -race ./...
sh test/yaegi/run.sh         # unit tests under Yaegi, as Traefik runs them
IPSCANNER_KEY_FILE=/path/to/key IPSCANNER_E2E_SITE_HELPER=/path/to/site.cjs bash test/e2e/run.sh
IPSCANNER_KEY_FILE=/path/to/key bash test/e2e/k8s.sh
```

The end to end runs start Traefik in Docker with this checkout as a local plugin (`experimental.localPlugins`) on ports 18080 to 18083, and need an API on `host.docker.internal:3050` (`IPSCANNER_API_URL_DOCKER`) that classifies the test IPs. `k8s.sh` adds k3s and the Kubernetes CRD provider.

Dependencies are vendored (`go mod vendor`), as the Plugin Catalog requires.

## License

MIT
