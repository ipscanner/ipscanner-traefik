#!/usr/bin/env bash
# KEEP=1 leaves the containers running.
set -euo pipefail
cd "$(dirname "$0")"
root=$(cd ../.. && pwd)

: "${IPSCANNER_KEY_FILE:?set IPSCANNER_KEY_FILE}"
TRAEFIK_VERSION=${TRAEFIK_VERSION:-v3.7}
TRAEFIK_CRD_REF=${TRAEFIK_CRD_REF:-v3.7.14}
K3S_IMAGE=${K3S_IMAGE:-rancher/k3s:v1.31.4-k3s1}
IPSCANNER_API_URL_DOCKER=${IPSCANNER_API_URL_DOCKER:-http://host.docker.internal:3050}
NET=ipscanner-traefik-e2e-k8s
K3S=ipscanner-traefik-e2e-k8s-server
PROXY=ipscanner-traefik-e2e-k8s-proxy
APP=ipscanner-traefik-e2e-k8s-whoami
WEB=http://localhost:18082
ADMIN=http://localhost:18083

tmp=$(mktemp -d "$PWD/.k8s.XXXXXX")
cleanup() {
	if [ -z "${KEEP:-}" ]; then
		docker rm -f "$PROXY" "$APP" "$K3S" >/dev/null 2>&1 || true
		docker network rm "$NET" >/dev/null 2>&1 || true
	fi
	rm -rf "$tmp"
}
trap cleanup EXIT

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok   $*"; }
bad() { fail=$((fail + 1)); echo "FAIL $*"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: got '$2', want '$3'"; fi; }
kubectl() { docker exec -i "$K3S" kubectl "$@"; }

echo "# k3s"
docker network create "$NET" >/dev/null
docker run -d --name "$K3S" --network "$NET" --privileged "$K3S_IMAGE" \
	server --disable=traefik --disable=metrics-server --tls-san="$K3S" >/dev/null
docker run -d --name "$APP" --network "$NET" traefik/whoami:v1.11.0 >/dev/null
for i in $(seq 1 90); do
	kubectl get --raw /readyz >/dev/null 2>&1 && break
	sleep 2
done
curl -fsS "https://raw.githubusercontent.com/traefik/traefik/$TRAEFIK_CRD_REF/docs/content/reference/dynamic-configuration/kubernetes-crd-definition-v1.yml" >"$tmp/crd.yml"
kubectl apply -f - <"$tmp/crd.yml" >/dev/null
kubectl wait --for condition=established --timeout=60s crd/middlewares.traefik.io crd/ingressroutes.traefik.io >/dev/null

echo "# examples/kubernetes.yml"
kubectl create namespace example >/dev/null
if kubectl apply -n example -f - <"$root/examples/kubernetes.yml" >"$tmp/out" 2>&1; then
	ok "API server accepts examples/kubernetes.yml"
	kubectl -n example create service externalname app --external-name "$APP" --tcp=80:80 >/dev/null
else
	bad "examples/kubernetes.yml: $(cat "$tmp/out")"
fi

echo "# middleware with the key from a Secret"
kubectl create namespace e2e >/dev/null
kubectl -n e2e create secret generic ipscanner --from-file=apiKey=/dev/stdin <"$IPSCANNER_KEY_FILE" >/dev/null
kubectl apply -f - >/dev/null <<EOF
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: ipscanner
  namespace: e2e
spec:
  plugin:
    ipscanner:
      apiKey: urn:k8s:secret:ipscanner:apiKey
      apiUrl: $IPSCANNER_API_URL_DOCKER
      mode: enforce
      blockClasses:
        - tor
      trustedProxies:
        - private
---
apiVersion: v1
kind: Service
metadata:
  name: whoami
  namespace: e2e
spec:
  type: ExternalName
  externalName: $APP
  ports:
    - port: 80
---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: whoami
  namespace: e2e
spec:
  entryPoints:
    - web
  routes:
    - match: Host(\`k8s.localhost\`)
      kind: Rule
      middlewares:
        - name: ipscanner
      services:
        - name: whoami
          port: 80
EOF

# Traefik runs outside the cluster with a cluster-admin token.
kubectl -n kube-system create serviceaccount traefik-e2e >/dev/null
kubectl create clusterrolebinding traefik-e2e --clusterrole=cluster-admin --serviceaccount=kube-system:traefik-e2e >/dev/null
token=$(kubectl -n kube-system create token traefik-e2e --duration=1h)
docker exec "$K3S" cat /var/lib/rancher/k3s/server/tls/server-ca.crt >"$tmp/ca.crt"
printf '%s' "$token" >"$tmp/token"
chmod 644 "$tmp/ca.crt" "$tmp/token"

# The token is read from a file so it does not show in `docker inspect`.
docker run -d --name "$PROXY" --network "$NET" --add-host host.docker.internal:host-gateway \
	-p 18082:80 -p 18083:8080 \
	-v "$root:/plugins-local/src/github.com/ipscanner/ipscanner-traefik:ro" \
	-v "$tmp:/k8s:ro" \
	--entrypoint sh "traefik:$TRAEFIK_VERSION" -c '
	exec traefik --log.level=INFO --api.insecure=true \
		--entrypoints.web.address=:80 \
		--entrypoints.web.forwardedheaders.trustedips=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 \
		--providers.kubernetescrd.endpoint=https://'"$K3S"':6443 \
		--providers.kubernetescrd.token="$(cat /k8s/token)" \
		--providers.kubernetescrd.certauthfilepath=/k8s/ca.crt \
		--providers.kubernetescrd.allowexternalnameservices=true \
		--providers.kubernetescrd.namespaces=e2e,example \
		--experimental.localplugins.ipscanner.modulename=github.com/ipscanner/ipscanner-traefik' >/dev/null

for i in $(seq 1 60); do
	curl -s "$ADMIN/api/http/middlewares" | grep -q 'e2e-ipscanner@kubernetescrd' && break
	sleep 1
done
mw=$(curl -s "$ADMIN/api/http/middlewares/e2e-ipscanner@kubernetescrd")
grep -q '"status":"enabled"' <<<"$mw" && ok "middleware e2e-ipscanner@kubernetescrd enabled" || bad "middleware: $(grep -o '"error":[^]]*]' <<<"$mw")"
for i in $(seq 1 30); do
	curl -s "$ADMIN/api/http/middlewares" | grep -q 'example-ipscanner@kubernetescrd' && break
	sleep 1
done
mw=$(curl -s "$ADMIN/api/http/middlewares/example-ipscanner@kubernetescrd")
grep -q '"status":"enabled"' <<<"$mw" && ok "examples/kubernetes.yml middleware enabled in Traefik" || bad "example middleware: $mw"
rt=$(curl -s "$ADMIN/api/http/routers?search=example-app-" | { grep -o '"status":"[a-z]*"' || true; } | cut -d'"' -f4 | paste -sd, -)
expect "examples/kubernetes.yml IngressRoute enabled" "$rt" enabled
sleep 2

visit() { # ip -> code
	curl -s -o "$tmp/b" -w '%{http_code}' -H 'Host: k8s.localhost' -H "X-Forwarded-For: $1" \
		-A 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36' \
		-H 'Accept-Language: en' "$WEB/"
}
expect "residential passes" "$(visit 84.128.0.1)" 200
expect "residential checked with the Secret key" "$(grep -i '^X-Ipscanner-Status:' "$tmp/b" | cut -d' ' -f2 | tr -d '\r')" ok
expect "tor blocked" "$(visit 185.220.101.1)" 403

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
