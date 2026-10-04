#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
cat gitea-full.tar.xz.part-* > gitea-full.tar.xz
sha256sum -c gitea-full.tar.xz.sha256
tar -xJf gitea-full.tar.xz
rm -f gitea-full.tar.xz
echo 'Gitea restored.'
