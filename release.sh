#!/bin/bash
# =============================================================================
# hajimu_web — ローカルビルド + GitHub Release スクリプト
# =============================================================================
# 使い方:
#   ./release.sh              hajimu.json のバージョンでリリース
#   ./release.sh v5.4.2       指定バージョンでリリース
#   ./release.sh --push       ビルドなし、push + Release のみ
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")"

PLUGIN_NAME="hajimu_web"
HJP_FILE="${PLUGIN_NAME}.hjp"

# ---------- 引数解析 ----------
VERSION=""
PUSH_ONLY=false

for arg in "$@"; do
  case "$arg" in
    --push)  PUSH_ONLY=true ;;
    v*|[0-9]*) VERSION="$arg" ;;
  esac
done

# hajimu.json からバージョン自動取得
if [[ -z "$VERSION" ]]; then
  VERSION=$(jq -r '.バージョン // .version // empty' hajimu.json 2>/dev/null || true)
fi

if [[ -z "$VERSION" ]]; then
  echo "使い方: ./release.sh [バージョン] [--push]"
  exit 1
fi

[[ "$VERSION" == v* ]] || VERSION="v$VERSION"

echo "=== $PLUGIN_NAME $VERSION リリース ==="

# ---------- ビルド ----------
if [[ "$PUSH_ONLY" == false ]]; then
  echo "--- macOS ビルド ---"
  make clean && make
  echo "  → $HJP_FILE"
fi

# ---------- Git push ----------
echo "--- Git push ---"
git add -A
git diff --cached --quiet || git commit -m "release: $PLUGIN_NAME $VERSION"
git push origin HEAD

if git rev-parse "$VERSION" >/dev/null 2>&1; then
  echo "  タグ $VERSION は既に存在します"
else
  git tag -a "$VERSION" -m "$PLUGIN_NAME $VERSION"
  echo "  タグ作成: $VERSION"
fi
git push origin "$VERSION"

# ---------- GitHub Release ----------
if command -v gh >/dev/null 2>&1; then
  echo "--- GitHub Release 作成 ---"
  mkdir -p dist
  cp "$HJP_FILE" "dist/${PLUGIN_NAME}-macos.hjp"

  gh release create "$VERSION" "dist/${PLUGIN_NAME}-macos.hjp" \
    --title "$PLUGIN_NAME $VERSION" \
    --generate-notes 2>/dev/null || \
  gh release upload "$VERSION" "dist/${PLUGIN_NAME}-macos.hjp" --clobber 2>/dev/null || \
  echo "⚠ Release 作成/アップロードに失敗"
fi

echo ""
echo "=== リリース完了: $PLUGIN_NAME $VERSION ==="
