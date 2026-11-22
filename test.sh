#!/usr/bin/env bash
# 테스트 전체 실행 (리눅스). 결과: results/before_after.md, results/env.txt, results/logs/
#   ./test.sh            # 전체
#   ./test.sh -k D       # 고정 사례만
set -euo pipefail
cd "$(dirname "$0")"
python3 -m pytest -v "$@"
