#!/usr/bin/env bash
# 취약(보호 전) 바이너리 컴파일.
#  -no-pie / -fno-pie          : 정적 주소(재작성 용이)
#  -O0 / -fno-devirtualize*    : 가상 호출을 vtable 경유로 유지(탈가상화 방지)
#  -fno-stack-protector        : 스택 카나리 제거(오버플로 재현)
#  -U_FORTIFY_SOURCE           : fortify 로 인한 복사 중단 방지
#  -z relro -z now             : 정상 vtable 이 읽기 전용이 되도록(논문 관찰 전제)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$ROOT/out"
mkdir -p "$OUT"

g++ -std=c++17 -O0 -g -no-pie -fno-pie \
    -fno-stack-protector -U_FORTIFY_SOURCE \
    -fno-devirtualize -fno-devirtualize-speculatively \
    -Wl,-z,relro,-z,now \
    -o "$OUT/victim_vuln" \
    "$HERE/factory.cpp" "$HERE/victim.cpp"

echo "built: $OUT/victim_vuln"
