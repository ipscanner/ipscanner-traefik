#!/bin/sh
# Runs the unit tests under Yaegi with a GOPATH layout and the vendored core,
# the way Traefik loads the plugin. YAEGI_VERSION must match the Traefik
# release (v0.16.1 for Traefik v3.7).
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
version=${YAEGI_VERSION:-v0.16.1}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
GOBIN="$work/bin" go install "github.com/traefik/yaegi/cmd/yaegi@$version"
pkg="$work/gopath/src/github.com/ipscanner/ipscanner-traefik"
mkdir -p "$(dirname "$pkg")"
cp -R "$root" "$pkg"
rm -rf "$pkg/.git"
cd "$work/gopath"
GOPATH="$work/gopath" GO111MODULE=off "$work/bin/yaegi" test -v github.com/ipscanner/ipscanner-traefik
