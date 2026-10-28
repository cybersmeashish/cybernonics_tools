#!/usr/bin/env bash
# Push agent-honeypot into a GitHub repository as its own folder.
#
#   bash scripts/push-to-github.sh [options]
#
#   --repo URL        target repository   (default https://github.com/cybersmeashish/cybernonics_tools)
#   --dir NAME        folder in the repo  (default agent-honeypot)
#   --branch NAME     push to a new branch and open a pull request instead of the default branch
#   --release         also push the tag agent-honeypot-v<version> (publishes image + Helm chart)
#   --skip-tests      don't run the test suite and demo first
#   --force           replace the folder if it already exists in the repo
#
# What it does: checks access, runs the tests in a throwaway .venv, clones the
# repo into a temp dir, copies this project into <dir>/ (without local state,
# caches or virtualenvs), installs the CI + release workflows at the repo root
# (.github/workflows/agent-honeypot-*.yml), refuses to commit decoy or
# Terraform state, then commits and pushes. Your local folder is not modified.
set -euo pipefail

REPO_URL="https://github.com/cybersmeashish/cybernonics_tools"
SUBDIR="agent-honeypot"; BRANCH=""; RELEASE=false; TESTS=true; FORCE=false
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO_URL="$2"; shift 2 ;;
    --dir) SUBDIR="$2"; shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    --release) RELEASE=true; shift ;;
    --skip-tests) TESTS=false; shift ;;
    --force) FORCE=true; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done
REPO_URL=${REPO_URL%/}; REPO_URL=${REPO_URL%.git}
REPO_SLUG=${REPO_URL#https://github.com/}
REPO_NAME=${REPO_SLUG##*/}
SRC="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$SRC/pyproject.toml" | head -n 1)
TAG="agent-honeypot-v$VERSION"

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
die() { echo "error: $*" >&2; exit 1; }

if [ -n "$BRANCH" ] && $RELEASE; then
  die "--release tags the default branch; merge the pull request first, then re-run with --release"
fi

step "Checking tools and access to $REPO_URL"
for t in git python3 rsync; do
  command -v "$t" >/dev/null || die "missing $t (macOS: brew install git python)"
done
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  gh auth setup-git >/dev/null 2>&1 || true          # let git use your gh login
fi
[ -n "$(git config user.name || true)" ] && [ -n "$(git config user.email || true)" ] || \
  die "set your git identity: git config --global user.name \"Your Name\"; git config --global user.email you@example.com"
git ls-remote "$REPO_URL.git" >/dev/null 2>&1 || \
  die "can't access $REPO_URL. Sign in with 'gh auth login' (or use a personal access token with repo + workflow scopes) and check the URL"

if $TESTS; then
  step "Running tests and demo (throwaway .venv)"
  # call everything through "python -m": venv launcher scripts break on paths with spaces
  (cd "$SRC" && python3 -m venv .venv \
     && .venv/bin/python -m pip install -q --upgrade pip \
     && .venv/bin/python -m pip install -q -e ".[dev]" \
     && .venv/bin/python -m pytest -q \
     && .venv/bin/python examples/demo_compromised_agent.py >/dev/null)
  echo "tests and demo OK"
fi

step "Cloning $REPO_SLUG"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
git clone -q "$REPO_URL.git" "$WORK/repo"
cd "$WORK/repo"
if git rev-parse -q --verify HEAD >/dev/null 2>&1; then
  EMPTY=false
  DEFAULT=$(git rev-parse --abbrev-ref HEAD)
else
  EMPTY=true
  DEFAULT=main
  git checkout -q -b main
  echo "repository is empty - creating '$DEFAULT'"
fi
if [ -n "$BRANCH" ]; then
  $EMPTY && die "the repository is empty, so there is nothing to open a pull request against; run without --branch"
  git checkout -q -b "$BRANCH"
fi
TARGET=${BRANCH:-$DEFAULT}

if [ -e "$SUBDIR" ] && ! $FORCE; then
  die "$SUBDIR/ already exists in $REPO_SLUG - re-run with --force to replace it"
fi

step "Copying project into $SUBDIR/"
rm -rf "$SUBDIR"
mkdir -p "$SUBDIR"
rsync -a \
  --exclude '.git' --exclude '.github' --exclude '.venv' --exclude '.DS_Store' \
  --exclude '.honeypot-state' --exclude 'planted' --exclude '__pycache__' \
  --exclude '*.egg-info' --exclude '.pytest_cache' --exclude '.terraform' \
  --exclude '.terraform.lock.hcl' --exclude '*.tfstate' --exclude '*.tfstate.*' \
  --exclude 'terraform.tfvars' --exclude '.build' --exclude '.versions' \
  --exclude '/build' --exclude '/dist' \
  "$SRC/" "$SUBDIR/"
mkdir -p .github/workflows
cp "$SRC/ci/monorepo/agent-honeypot-ci.yml" "$SRC/ci/monorepo/agent-honeypot-release.yml" .github/workflows/
if [ "$SUBDIR" != "agent-honeypot" ]; then   # workflows assume the default folder name
  sed -i.bak "s#agent-honeypot/\*\*#$SUBDIR/**#; s#working-directory: agent-honeypot#working-directory: $SUBDIR#; s#context: agent-honeypot\$#context: $SUBDIR#" \
    .github/workflows/agent-honeypot-*.yml && rm -f .github/workflows/*.bak
fi
if [ ! -e README.md ]; then
  cat > README.md <<EOF
# $REPO_NAME

| Tool | What it does |
|---|---|
| [agent-honeypot]($SUBDIR/) | Deployable honeypots for AI agents: plant decoys, catch and attribute misbehaving agents, keep tamper-evident evidence and halt them. Python, AWS Terraform, Helm + Tetragon. |
EOF
  echo "created a root README.md listing the tool"
elif ! grep -q "$SUBDIR" README.md; then
  echo "note: the existing root README.md doesn't mention $SUBDIR/ - add a link when convenient"
fi

step "Checking what will be committed"
git add -A
if git diff --cached --name-only | grep -E '(^|/)(\.honeypot-state|planted)/|registry\.json$|evidence\.jsonl$|guard-registry\.json$|terraform\.tfvars$|\.tfstate' ; then
  die "refusing to commit the files above (decoy state or Terraform state)"
fi
if git diff --cached --quiet; then
  echo "nothing changed - $REPO_SLUG already has this version of $SUBDIR/"
  exit 0
fi
echo "$(git diff --cached --name-only | wc -l | tr -d ' ') files to commit"
git commit -q -m "Add agent-honeypot v$VERSION" \
  -m "Deployable honeypots for AI agents: decoy planter, AgentGuard, decoy services, hash-chained evidence, incrimination verdicts, AWS Terraform module and Helm chart with Tetragon."

step "Pushing to $TARGET"
if ! out=$(git push -u origin "$TARGET" 2>&1); then
  echo "$out" >&2
  if echo "$out" | grep -qi 'workflow'; then
    echo "hint: your login can't push workflow files. Run: gh auth refresh -h github.com -s workflow   then retry" >&2
  fi
  if echo "$out" | grep -qiE 'protected|GH006|non-fast-forward|fetch first'; then
    echo "hint: the branch is protected or changed meanwhile - retry with --branch add-agent-honeypot to open a pull request" >&2
  fi
  exit 1
fi

if [ -n "$BRANCH" ]; then
  if command -v gh >/dev/null 2>&1; then
    gh pr create --repo "$REPO_SLUG" --base "$DEFAULT" --head "$BRANCH" \
      --title "Add agent-honeypot v$VERSION" \
      --body "Adds \`$SUBDIR/\` (deployable honeypots for AI agents) and its CI/release workflows. CI runs the Python tests, Docker build, terraform validate and Helm lint/kubeconform." \
      || echo "open the pull request at $REPO_URL/compare/$DEFAULT...$BRANCH"
  else
    echo "open the pull request at $REPO_URL/compare/$DEFAULT...$BRANCH"
  fi
fi

if $RELEASE; then
  step "Tagging $TAG (publishes image + Helm chart)"
  if git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; then
    echo "tag $TAG already exists on GitHub - bump version in pyproject.toml and Chart.yaml to release again"
  else
    git tag -a "$TAG" -m "agent-honeypot v$VERSION"
    git push -q origin "$TAG"
  fi
fi

step "Done"
echo "code:     $REPO_URL/tree/$TARGET/$SUBDIR"
echo "CI runs:  $REPO_URL/actions"
if $RELEASE; then
  OWNER_LC=$(printf '%s' "${REPO_SLUG%%/*}" | tr '[:upper:]' '[:lower:]')
  echo "image:    ghcr.io/$OWNER_LC/agent-honeypot:$VERSION   chart: oci://ghcr.io/$OWNER_LC/charts/agent-honeypot"
  echo "note: new ghcr.io packages start private - make them public in each package's settings so others can pull them"
fi
