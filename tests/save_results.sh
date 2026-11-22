#!/usr/bin/env bash
# 제출·보고서용으로 테스트 결과를 docs/results/<이름>/ 에 저장한다.
#
# 사용법:  bash tests/save_results.sh week12
#
# 하는 일:
#   1) 테스트 전체를 한 번 실행하고, 화면 출력(요약 포함)을 pytest_output.txt 로 저장
#   2) 그때 만들어진 results/before_after.md, results/env.txt 를 같이 복사
#
# results/ 는 실행할 때마다 바뀌어서 git 에서 제외(.gitignore)하고,
# 이 스크립트로 저장한 docs/results/ 만 일부러 커밋한다.
set -uo pipefail
cd "$(dirname "$0")/.."

if [ $# -ne 1 ]; then
    echo "사용법: bash tests/save_results.sh <저장 이름>   (예: week12)" >&2
    exit 2
fi

DEST="docs/results/$1"
mkdir -p "$DEST"

echo "[1/2] 테스트 실행 중..."
python3 -m pytest -q -rfE 2>&1 | tee "$DEST/pytest_output.txt"
STATUS=${PIPESTATUS[0]}

echo "[2/2] 결과 복사 → $DEST"
cp results/before_after.md "$DEST/"
cp results/env.txt "$DEST/"
date '+%Y-%m-%d %H:%M:%S %Z' > "$DEST/saved_at.txt"

echo
echo "저장 완료: $DEST"
ls "$DEST"
exit $STATUS
