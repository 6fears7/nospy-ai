#!/usr/bin/env bash
set -euo pipefail

here=$(cd "$(dirname "$0")/../.." && pwd)
version_file="$here/VERSION"
chart="$here/deploy/helm/nospy/Chart.yaml"
helpers="$here/deploy/helm/nospy/templates/_helpers.tpl"
example="$here/deploy/helm/nospy/examples/sidecar-deployment.yaml"

check=false
if [ "${1:-}" = "--check" ]; then
  check=true
fi

v=$(tr -d '[:space:]' <"$version_file")
if [[ ! "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "VERSION must be MAJOR.MINOR.PATCH, got: $v" >&2
  exit 1
fi

chart_version_pattern='^version: [0-9]+\.[0-9]+\.[0-9]+$'
chart_appversion_pattern='^appVersion: "[0-9]+\.[0-9]+\.[0-9]+"$'
helper_pattern='^\{\{- define "nospy\.appVersion" -\}\}[0-9]+\.[0-9]+\.[0-9]+\{\{- end -\}\}$'
example_pattern='^( *)image: "nospy:[0-9]+\.[0-9]+\.[0-9]+"$'

assert_one() {
  local file=$1 pattern=$2 label=$3 n
  n=$(grep -cE -- "$pattern" "$file")
  if [ "$n" -ne 1 ]; then
    echo "$label: expected exactly 1 match in $file, got $n" >&2
    exit 1
  fi
}

assert_one "$chart" "$chart_version_pattern" "Chart.yaml version"
assert_one "$chart" "$chart_appversion_pattern" "Chart.yaml appVersion"
assert_one "$helpers" "$helper_pattern" "_helpers.tpl nospy.appVersion"
assert_one "$example" "$example_pattern" "examples/sidecar-deployment.yaml image"

want_version="version: $v"
want_appversion="appVersion: \"$v\""
want_helper="{{- define \"nospy.appVersion\" -}}${v}{{- end -}}"
example_indent=$(grep -E -- "$example_pattern" "$example" | sed -E "s/$example_pattern/\1/")
want_example="${example_indent}image: \"nospy:${v}\""

if $check; then
  fail=0
  cur_version=$(grep -E -- "$chart_version_pattern" "$chart")
  if [ "$cur_version" != "$want_version" ]; then
    echo "Chart.yaml: version is '$cur_version', want '$want_version'" >&2
    fail=1
  fi
  cur_appversion=$(grep -E -- "$chart_appversion_pattern" "$chart")
  if [ "$cur_appversion" != "$want_appversion" ]; then
    echo "Chart.yaml: appVersion is '$cur_appversion', want '$want_appversion'" >&2
    fail=1
  fi
  cur_helper=$(grep -E -- "$helper_pattern" "$helpers")
  if [ "$cur_helper" != "$want_helper" ]; then
    echo "_helpers.tpl: nospy.appVersion is '$cur_helper', want '$want_helper'" >&2
    fail=1
  fi
  cur_example=$(grep -E -- "$example_pattern" "$example")
  if [ "$cur_example" != "$want_example" ]; then
    echo "examples/sidecar-deployment.yaml: image is '$cur_example', want '$want_example'" >&2
    fail=1
  fi
  exit "$fail"
fi

sed -i -E "s/$chart_version_pattern/$want_version/" "$chart"
sed -i -E "s/$chart_appversion_pattern/$want_appversion/" "$chart"
sed -i -E "s/$helper_pattern/$want_helper/" "$helpers"
sed -i -E "s/$example_pattern/$want_example/" "$example"
