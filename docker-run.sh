#!/usr/bin/env bash
# Docker 로 전체 데모 실행 (어느 PC 에서도 동일 재현).
#   1) 이미지 빌드(vtint-env)   2) 프로젝트 마운트 후 데모 실행
#
# 사용:  ./docker-run.sh            # 전체 데모(비교표)
#        ./docker-run.sh bash       # 컨테이너 셸 진입
set -euo pipefail
cd "$(dirname "$0")"

IMAGE=vtint-env
echo "# [1/2] Docker 이미지 빌드: $IMAGE"
docker build -t "$IMAGE" .

echo
echo "# [2/2] 컨테이너에서 데모 실행"
if [ "${1:-}" = "bash" ]; then
    docker run --rm -it -v "$PWD":/work "$IMAGE" bash
else
    docker run --rm -v "$PWD":/work "$IMAGE" bash -lc "python3 tools/vtint.py demo --build"
fi
