#!/bin/bash
# Refresh test vectors from transparency-dev/merkle
# Usage: ./update.sh

set -e
cd "$(dirname "$0")"

echo "Fetching latest test vectors from transparency-dev/merkle..."
rm -rf merkle
mkdir merkle
curl -sL https://github.com/transparency-dev/merkle/archive/main.tar.gz | \
    tar -xz --strip-components=1 -C merkle merkle-main/testdata

echo "Done. Test vectors updated:"
find merkle/testdata -name "*.json" | wc -l | xargs echo "  JSON files:"
