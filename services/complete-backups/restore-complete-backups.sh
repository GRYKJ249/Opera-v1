#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
cat nextcloud-full.tar.xz.part-* > nextcloud-full.tar.xz
sha256sum -c nextcloud-full.tar.xz.sha256
sha256sum -c opera-unified.pgcustom.sha256
tar -xJf nextcloud-full.tar.xz
printf '%s\n' 'Nextcloud source/data restored. PostgreSQL dump is opera-unified.pgcustom.'
