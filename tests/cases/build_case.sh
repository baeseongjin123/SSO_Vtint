#!/usr/bin/env bash
# 테스트케이스 하나를 빌드하고 VTint 를 적용한다.
#
# 사용법:  bash tests/cases/build_case.sh tc1
#
# 하는 일:
#   1) tests/cases/<이름>_factory.cpp + <이름>_main.cpp 를 컴파일 → out/<이름>_vuln      (보호 전)
#   2) 팀원 VTint(tools/vtint.py pipeline) 적용            → out/<이름>_hardened  (보호 후)
#
# 그다음 직접 판정해 보기:
#   python3 tools/vtint.py judge out/<이름>_hardened inject
#
# 컴파일 옵션은 팀원 tests/build.sh 와 똑같다. build.sh 가 바뀌면 아래 FLAGS 도 같이 바꾼다.
set -euo pipefail

if [ $# -ne 1 ]; then
    echo "사용법: bash tests/cases/build_case.sh <테스트케이스 이름>   (예: tc1)" >&2
    exit 2
fi

NAME="$1"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$ROOT/out"

FACTORY="$HERE/${NAME}_factory.cpp"
MAIN="$HERE/${NAME}_main.cpp"
for f in "$FACTORY" "$MAIN" "$HERE/${NAME}.h"; do
    if [ ! -f "$f" ]; then
        echo "파일이 없음: $f" >&2
        echo "테스트케이스는 ${NAME}.h, ${NAME}_factory.cpp, ${NAME}_main.cpp 세 파일이 있어야 한다." >&2
        exit 1
    fi
done

FLAGS=(
    -std=c++17 -O0 -g -no-pie -fno-pie
    -fno-stack-protector -U_FORTIFY_SOURCE
    -fno-devirtualize -fno-devirtualize-speculatively
    -Wl,-z,relro,-z,now
)

mkdir -p "$OUT"
echo "[1/2] 컴파일: $NAME → out/${NAME}_vuln"
g++ "${FLAGS[@]}" -I"$HERE" -o "$OUT/${NAME}_vuln" "$FACTORY" "$MAIN"

echo "[2/2] VTint 적용: out/${NAME}_vuln → out/${NAME}_hardened"
python3 "$ROOT/tools/vtint.py" pipeline "$OUT/${NAME}_vuln" "$OUT/${NAME}_hardened"

echo
echo "완료. 직접 판정해 보기:"
echo "  python3 tools/vtint.py judge out/${NAME}_vuln     inject     # 보호 전"
echo "  python3 tools/vtint.py judge out/${NAME}_hardened inject     # 보호 후"
echo "  (모드: normal / inject / rodata)"
