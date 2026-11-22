#!/usr/bin/env bash
# 현재 (리눅스) 환경에서 전체 데모 실행.
#   취약 바이너리 컴파일 → ELFParser → BitCover → VRewriter → 보호 전/후 판정표
set -euo pipefail
cd "$(dirname "$0")"
python3 tools/vtint.py demo --build "$@"
