#!/usr/bin/env bash
# Point git at the in-repo, versioned hooks so the local gate matches CI. Run
# once after cloning: `./scripts/install-hooks.sh`.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

git config core.hooksPath .githooks
chmod +x .githooks/* 2>/dev/null || true
echo "git hooks -> .githooks (pre-commit auto-formats; pre-push runs CI-parity fmt+clippy+test)"
