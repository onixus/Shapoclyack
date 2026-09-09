#!/usr/bin/env bash
#
# publish-wiki.sh: Publish docs/wiki/ to the GitHub Wiki repository
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WIKI_SRC="$REPO_DIR/docs/wiki"
TMP_DIR="$(mktemp -d /tmp/shapoclyack-wiki.XXXXXX)"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Derive remote URL (replace .git with .wiki.git)
ORIGIN_URL="$(git -C "$REPO_DIR" config --get remote.origin.url || true)"
if [[ -z "$ORIGIN_URL" ]]; then
    echo "[-] Error: git remote.origin.url is not set." >&2
    exit 1
fi

WIKI_URL="${ORIGIN_URL%.git}.wiki.git"

echo "[*] GitHub Wiki repository: $WIKI_URL"
echo "[*] Cloning wiki repository to temporary directory..."

if ! git clone "$WIKI_URL" "$TMP_DIR" 2>/dev/null; then
    echo "[-] Could not clone $WIKI_URL."
    echo "[!] Make sure that:"
    echo "    1. GitHub Wiki is enabled in Repo Settings -> Features -> Wikis"
    echo "    2. You have created at least one initial page in the GitHub Wiki web interface"
    echo "    3. You have push access to the repository"
    exit 1
fi

echo "[*] Preparing Wiki files..."

# In GitHub Wiki, the main page is Home.md
cp "$WIKI_SRC/README.md" "$TMP_DIR/Home.md"
cp "$WIKI_SRC/scenarios-security-engineer.md" "$TMP_DIR/scenarios-security-engineer.md"
cp "$WIKI_SRC/scenarios-architect.md" "$TMP_DIR/scenarios-architect.md"
cp "$WIKI_SRC/scenarios-ciso.md" "$TMP_DIR/scenarios-ciso.md"
cp "$WIKI_SRC/security-processes.md" "$TMP_DIR/security-processes.md"
cp "$WIKI_SRC/implementation-plan.md" "$TMP_DIR/implementation-plan.md"

# Create standard GitHub Wiki Sidebar (_Sidebar.md)
cat > "$TMP_DIR/_Sidebar.md" << 'EOF'
### [Главная (Home)](Home)

#### Ролевые сценарии
* [Инженер ИБ](scenarios-security-engineer)
* [Архитектор ИБ](scenarios-architect)
* [CISO / Руководство](scenarios-ciso)

#### Процессы и регламенты
* [Операционные процессы ИБ](security-processes)
* [Регламент SLA и VM](security-processes#12-матрица-sla-по-устранению-уязвимостей)
* [Экстренное реагирование (0-day)](security-processes#-процесс-3-экстренное-реагирование-на-0-day-и-kev-emergency-response)

#### Развертывание
* [План внедрения (12 недель)](implementation-plan)
* [Матрица RACI](implementation-plan#-матрица-ответственности-raci)
* [Критерии успеха (KPI)](implementation-plan#-критерии-успеха-внедрения-kpi-проекта)
EOF

# In GitHub Wiki, internal links should point to page names without .md extension
# and without docs/wiki/ prefixes:
for f in "$TMP_DIR"/*.md; do
    # Replace relative links like (scenarios-security-engineer.md) with (scenarios-security-engineer)
    # and (README.md) with (Home)
    perl -pi -e 's/\(README\.md\)/(Home)/g;' "$f"
    perl -pi -e 's/\(([a-z0-9-]+)\.md(#?[^)]*)\)/(\1\2)/g;' "$f"
    perl -pi -e 's/\.\.\/([a-z0-9-]+)\.md/https:\/\/github.com\/onixus\/Shapoclyack\/blob\/main\/docs\/\1.md/g;' "$f"
done

echo "[*] Committing and pushing to GitHub Wiki..."
cd "$TMP_DIR"
git add .
if git diff --staged --quiet; then
    echo "[+] No changes to publish: Wiki is already up-to-date."
else
    git commit -m "docs(wiki): update corporate wiki and role guides"
    git push origin master || git push origin main
    echo "[+] Wiki successfully published to GitHub!"
fi
