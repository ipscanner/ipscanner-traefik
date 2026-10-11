#!/usr/bin/env bash
# Needs an API that classifies the test IPs (local, DEV database); KEEP=1 keeps the containers.
set -euo pipefail
cd "$(dirname "$0")"

: "${IPSCANNER_KEY_FILE:?set IPSCANNER_KEY_FILE}"
: "${IPSCANNER_E2E_SITE_HELPER:?set IPSCANNER_E2E_SITE_HELPER}"
IPSCANNER_API_URL=${IPSCANNER_API_URL:-http://localhost:3050}
export IPSCANNER_API_URL_DOCKER=${IPSCANNER_API_URL_DOCKER:-http://host.docker.internal:3050}
export E2E_SITE_ENFORCE=${E2E_SITE_ENFORCE:-site_traefike2e0000000001}
export E2E_SITE_MONITOR=${E2E_SITE_MONITOR:-site_traefike2e0000000002}
export E2E_TIMEOUT=${E2E_TIMEOUT:-1500ms}
WEB=http://localhost:18080
ADMIN=http://localhost:18081
HELPER=$IPSCANNER_E2E_SITE_HELPER

RESIDENTIAL=84.128.0.1
TOR=185.220.101.1
VPN=185.217.69.166
HOSTING=5.9.0.1
GOOGLEBOT_IP=66.249.66.1
CHROME="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 e2e-$RANDOM$RANDOM"
HEADLESS="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/141.0.0.0 Safari/537.36"
GOOGLEBOT="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
ENFORCE_POLICY='{"tor":"block","vpn":"flag","verified_bot":"block","malicious_automation":"block"}'

# The key goes to a git ignored file and the container env; never print it.
install -m 600 "$IPSCANNER_KEY_FILE" .key
IPSCANNER_API_KEY=$(tr -d '[:space:]' < .key)
export IPSCANNER_API_KEY

cleanup() {
	if [ -z "${KEEP:-}" ]; then
		docker compose down -v --remove-orphans >/dev/null 2>&1 || true
		rm -f .key
	fi
	rm -rf "$tmp"
}
tmp=$(mktemp -d)
trap cleanup EXIT

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok   $*"; }
bad() { fail=$((fail + 1)); echo "FAIL $*"; }
expect() { # name got want
	if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: got '$2', want '$3'"; fi
}

# visit <host> <ip|-> [ua] [path] [extra header]: sets code, took, $tmp/h and $tmp/b.
visit() {
	local host=$1 ip=$2 ua=${3:-$CHROME} path=${4:-/} extra=${5:-X-E2E: 1}
	local args=(-s -o "$tmp/b" -D "$tmp/h" -H "Host: $host" -A "$ua" -H "Accept-Language: en" -H "$extra" -w '%{http_code} %{time_total}\n')
	[ "$ip" != "-" ] && args+=(-H "X-Forwarded-For: $ip")
	read -r code took < <(curl "${args[@]}" "$WEB$path")
}
upstream() { grep -i "^$1:" "$tmp/b" | head -1 | cut -d' ' -f2- | tr -d '\r'; }
response() { grep -i "^$1:" "$tmp/h" | head -1 | cut -d' ' -f2- | tr -d '\r'; }
faster() { awk -v t="$1" -v max="$2" 'BEGIN { exit !(t < max) }'; }

helper() { # the helper, retried: the test database can be far away
	local i out
	for i in 1 2 3 4 5; do
		if out=$(node "$HELPER" "$@" 2>/dev/null); then printf '%s\n' "$out"; return 0; fi
		sleep 3
	done
	echo "site helper failed: $1" >&2
	return 1
}

# request_log is flushed about every 5 s, so wait before reading rows.
FLUSH=7
mark() {
	sleep "$FLUSH"
	helper rows traefik 500 | node -e '
		let s = ""; process.stdin.on("data", d => s += d).on("end", () =>
			console.log(JSON.parse(s).map(r => new Date(r.created_at).toISOString()).sort().pop() || ""));'
}
rows_since() { # site mark -> rows of source traefik for the site after mark
	sleep "$FLUSH"
	helper rows traefik 500 | node -e '
		let s = ""; process.stdin.on("data", d => s += d).on("end", () =>
			console.log(JSON.parse(s).filter(r => r.site === process.argv[1] &&
				new Date(r.created_at).toISOString() > process.argv[2]).length));' "$1" "$2"
}
now() { node -e 'console.log(Date.now() / 1000)'; }

upsert() { helper "$1" traefik "$2" "$3"; }

echo "# sites"
upsert "$E2E_SITE_ENFORCE" enforce "$ENFORCE_POLICY" >/dev/null
upsert "$E2E_SITE_MONITOR" monitor '{"tor":"block","vpn":"flag"}' >/dev/null

echo "# warm up the API"
for i in $(seq 1 30); do
	status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X POST "$IPSCANNER_API_URL/v1/edge/check" \
		-H "Authorization: Bearer $IPSCANNER_API_KEY" -H 'Content-Type: application/json' \
		-d "{\"ip\":\"$RESIDENTIAL\",\"user_agent\":\"warmup $RANDOM\"}" || true)
	[ "$status" = 200 ] && break
	sleep 5
done
[ "$status" = 200 ] || { echo "API at $IPSCANNER_API_URL is not answering"; exit 1; }

run=$(FLUSH=1 mark)
echo "# traefik"
docker compose up -d --quiet-pull >/dev/null 2>&1
for i in $(seq 1 60); do
	n=$(curl -s "$ADMIN/api/http/routers" | grep -o '"status":"enabled"' | wc -l || true)
	[ "$n" -ge 10 ] && break
	sleep 1
done
logs() { docker logs ipscanner-traefik-e2e-proxy 2>&1; }
grep -q 'Plugins loaded' <<<"$(logs)" && ok "plugin loaded from /plugins-local" || bad "plugin not loaded"
errors=$(curl -s "$ADMIN/api/http/routers" "$ADMIN/api/http/middlewares" | grep -o '"error":\[[^]]*\]' || true)
expect "routers and middlewares without errors" "$errors" ""
sleep 2

echo "# enforce site (labels, key from the environment)"
visit enforce.localhost $RESIDENTIAL "$CHROME" / "X-IPScanner-Class: verified_bot"
expect "residential passes" "$code" 200
expect "residential upstream status" "$(upstream X-Ipscanner-Status)" ok
expect "residential upstream class" "$(upstream X-Ipscanner-Class)" human
expect "residential upstream action" "$(upstream X-Ipscanner-Action)" allow
expect "residential upstream site" "$(upstream X-Ipscanner-Site)" "$E2E_SITE_ENFORCE"
expect "debug header on the response" "$(response X-Ipscanner-Class)" human

visit enforce.localhost $TOR
expect "tor blocked" "$code" 403
grep -q "Request ID" "$tmp/b" && ok "block page" || bad "block page"
expect "tor debug action" "$(response X-Ipscanner-Action)" block

visit enforce.localhost $VPN
expect "vpn flagged passes" "$code" 200
expect "vpn upstream action" "$(upstream X-Ipscanner-Action)" flag
expect "vpn upstream class" "$(upstream X-Ipscanner-Class)" vpn

visit enforce.localhost $GOOGLEBOT_IP "$GOOGLEBOT"
expect "verified crawler passes a verified_bot block" "$code" 200
expect "verified crawler class" "$(upstream X-Ipscanner-Class)" verified_bot

echo "# coolify labels"
visit coolify.localhost $TOR
expect "coolify router blocks tor" "$code" 403
visit coolify.localhost $VPN
expect "coolify router passes vpn" "$code" 200
expect "coolify vpn flagged upstream" "$(upstream X-Ipscanner-Action)" flag

echo "# verdict cache"
since=$(mark)
visit enforce.localhost $RESIDENTIAL "$CHROME" /second-page
expect "cached visitor passes" "$code" 200
expect "cached visitor upstream class" "$(upstream X-Ipscanner-Class)" human
visit enforce.localhost $TOR "$CHROME" /again
expect "cached tor still blocked" "$code" 403
expect "cached requests made no API call" "$(rows_since "$E2E_SITE_ENFORCE" "$since")" 0
visit enforce.localhost $RESIDENTIAL "$CHROME other" /third-page
expect "new user agent is checked" "$(upstream X-Ipscanner-Status)" ok
expect "one API call for the new visitor" "$(rows_since "$E2E_SITE_ENFORCE" "$since")" 1
grep '"path":"/second-page"' <<<"$(logs)" | grep -c '"edge":"hit"' >/dev/null && ok "debug log shows a cache hit" || bad "no cache hit logged"

echo "# monitor site (key from apiKeyFile)"
visit monitor.localhost $TOR
expect "monitor never blocks tor" "$code" 200
expect "monitor upstream action" "$(upstream X-Ipscanner-Action)" would_block
expect "monitor upstream class" "$(upstream X-Ipscanner-Class)" tor
expect "no debug headers on the response" "$(response X-Ipscanner-Class)" ""
visit monitor.localhost $VPN
expect "monitor vpn" "$(upstream X-Ipscanner-Action)" would_flag

echo "# no site: defaults"
visit defaults.localhost $HOSTING "$HEADLESS"
expect "headless on hosting passes in monitor" "$code" 200
expect "headless class" "$(upstream X-Ipscanner-Class)" malicious_automation
expect "headless would be blocked" "$(upstream X-Ipscanner-Action)" would_block
visit defaults.localhost $TOR
expect "tor allowed by default classes" "$(upstream X-Ipscanner-Action)" allow

echo "# no site: enforce, blockClasses=tor,vpn"
visit local.localhost $TOR
expect "tor blocked" "$code" 403
visit local.localhost $VPN
expect "vpn blocked" "$code" 403
visit local.localhost $RESIDENTIAL
expect "residential passes" "$code" 200
visit local.localhost $TOR "$CHROME" /static/app.txt
expect "skipPaths passes" "$code" 200
expect "skipPaths status" "$(upstream X-Ipscanner-Status)" skipped

echo "# file provider"
visit file.localhost $TOR
expect "file provider blocks tor" "$code" 403
visit file.localhost $RESIDENTIAL
expect "file provider passes residential" "$code" 200
visit example.com -
expect "examples/dynamic.yml router" "$code" 200
visit example-local.localhost -
expect "examples/dynamic.yml second middleware" "$code" 200

echo "# spoofed X-Forwarded-For from an untrusted peer"
since=$(mark)
visit untrusted.localhost $TOR
expect "spoofed tor is not blocked" "$code" 200
expect "peer address used (private, skipped)" "$(upstream X-Ipscanner-Status)" skipped
expect "no API call for the spoofed address" "$(rows_since "$E2E_SITE_ENFORCE" "$since")" 0

echo "# fail open"
visit dead.localhost $TOR
expect "dead API passes" "$code" 200
expect "dead API status" "$(upstream X-Ipscanner-Status)" error
faster "$took" 1 && ok "dead API fast ($took s)" || bad "dead API took $took s"
visit dead.localhost $TOR
expect "backoff engaged" "$(upstream X-Ipscanner-Status)" backoff
faster "$took" 0.2 && ok "backoff fast ($took s)" || bad "backoff took $took s"
visit slow.localhost $TOR
expect "silent API passes" "$code" 200
expect "silent API status" "$(upstream X-Ipscanner-Status)" timeout
faster "$took" 1.2 && ok "timeout after 500ms ($took s)" || bad "timeout took $took s"
visit slow.localhost $TOR
expect "backoff after timeout" "$(upstream X-Ipscanner-Status)" backoff

echo "# policy change after policyTTL (5s)"
sleep 6
visit enforce.localhost $TOR
expect "tor blocked, policy refreshed" "$code" 403
start=$(now)
upsert "$E2E_SITE_ENFORCE" enforce '{"tor":"allow","vpn":"flag","verified_bot":"block"}' >/dev/null
visit enforce.localhost $TOR
expect "old policy kept within policyTTL" "$code" 403
changed=""
for i in $(seq 1 40); do
	visit enforce.localhost $TOR
	if [ "$code" = 200 ]; then changed=$(node -e 'console.log((process.argv[2] - process.argv[1]).toFixed(1))' "$start" "$(now)"); break; fi
	sleep 0.5
done
[ -n "$changed" ] && ok "tor allowed after the policy change (${changed}s)" || bad "policy change not picked up"
[ -n "$changed" ] && faster "$changed" 8 && ! faster "$changed" 3.5 && ok "picked up after policyTTL" || bad "policy change at ${changed}s, want 4 to 8"
expect "cached verdict, new policy" "$(upstream X-Ipscanner-Action)" allow
upsert "$E2E_SITE_ENFORCE" enforce "$ENFORCE_POLICY" >/dev/null
sleep 6
visit enforce.localhost $TOR
expect "tor blocked again" "$code" 403

echo "# request log and client version"
rows=$(sleep "$FLUSH"; helper rows traefik 500)
count() { # site -> edge check rows of source traefik for the site in this run
	printf '%s' "$rows" | node -e '
		let s = ""; process.stdin.on("data", d => s += d).on("end", () =>
			console.log(JSON.parse(s).filter(r => r.site === process.argv[1] && r.source === "traefik" &&
				r.endpoint === "/v1/edge/check" && new Date(r.created_at).toISOString() > process.argv[2]).length));' "$1" "$run"
}
n=$(count "$E2E_SITE_ENFORCE")
[ "$n" -gt 0 ] && ok "request_log rows with source traefik and the enforce site ($n)" || bad "no request_log rows for the enforce site"
n=$(count "$E2E_SITE_MONITOR")
[ "$n" -gt 0 ] && ok "request_log rows with source traefik and the monitor site ($n)" || bad "no request_log rows for the monitor site"
site=$(upsert "$E2E_SITE_ENFORCE" enforce "$ENFORCE_POLICY")
field() { printf '%s' "$site" | node -e '
	let s = ""; process.stdin.on("data", d => s += d).on("end", () => {
		const v = JSON.parse(s)[process.argv[1]]; console.log(v && process.argv[1] === "last_seen_at" ? new Date(v).toISOString() : v); });' "$1"; }
expect "sites.client_version" "$(field client_version)" 0.1.0
[[ "$(field last_seen_at)" > "$run" ]] && ok "sites.last_seen_at updated in this run" || bad "sites.last_seen_at not updated: $(field last_seen_at)"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
