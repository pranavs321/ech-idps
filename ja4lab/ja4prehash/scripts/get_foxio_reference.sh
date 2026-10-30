#!/usr/bin/env bash
# Downloads FoxIO's JA4+ repo (reference implementation + test pcaps) into third_party/
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p third_party && cd third_party
curl -sL -o ja4.zip https://codeload.github.com/FoxIO-LLC/ja4/zip/refs/heads/main
unzip -q -o ja4.zip && rm ja4.zip
echo "OK -> third_party/ja4-main  (needs tshark >= 4.0.6 for the reference tool)"
