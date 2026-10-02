#!/usr/bin/env bash
# Build the GitHub Pages site into ./site.
#
# README.md and docs/ stay as written so they keep working on GitHub. This stages
# copies of them (plus images/) into build/docs-src and fixes the links that only
# differ on the site, then runs mkdocs. Needs mkdocs-material; the version CI uses
# is pinned in .github/workflows/pages.yml.
set -euo pipefail
cd "$(dirname "$0")/.."

src=build/docs-src
if [ -d "$src" ]; then
  rm -r "$src"
fi
mkdir -p "$src"
cp -R images "$src/images"

# The README is the home page, so docs/x.md becomes x.md.
sed 's#](docs/#](#g' README.md > "$src/index.md"

# Each doc's "Back to the README" link goes to the home page.
for f in docs/*.md; do
  sed 's#](\.\./README\.md)#](index.md)#g' "$f" > "$src/$(basename "$f")"
done

mkdocs build --strict
