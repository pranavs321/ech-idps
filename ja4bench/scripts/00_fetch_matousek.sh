#!/usr/bin/env bash
# Fetch the public Matousek JA4+ corpus (BUT, CNSM 2024).
#   default      : only datasets/*.csv + README (~25 MB) via sparse checkout
#   --with-pcaps : full repo incl. ~1,900 pcaps (~5 GB) so ja4lab can re-extract JA4T/TTL/flow features
# Writes data/external/matousek/MANIFEST.sha256 so every later number is tied to exact input bytes.
set -euo pipefail
DEST="data/external/matousek"
URL="https://github.com/matousp/malware-analysis.git"
mkdir -p data/external
if [ -d "$DEST/.git" ]; then echo "already present: $DEST"; else
  if [ "${1:-}" = "--with-pcaps" ]; then
    git clone --depth 1 "$URL" "$DEST"
  else
    git clone --depth 1 --filter=blob:none --sparse "$URL" "$DEST"
    (cd "$DEST" && git sparse-checkout set --no-cone 'datasets/*.csv' 'datasets/README.md')
  fi
fi
(cd "$DEST" && git rev-parse HEAD > UPSTREAM_COMMIT && sha256sum datasets/*.csv > MANIFEST.sha256)
echo "upstream commit: $(cat $DEST/UPSTREAM_COMMIT)"
cat "$DEST/MANIFEST.sha256"
