#!/usr/bin/env bash
# Docker(Ubuntu 22.04) 안에서 테스트 전체 실행. gdb 테스트용으로 ptrace 권한을 준다.
#   ./docker-test.sh             # 전체
#   ./docker-test.sh -k D        # 고정 사례만
set -euo pipefail
cd "$(dirname "$0")"
IMAGE=vtint-env
docker build -t "$IMAGE" .
docker run --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v "$PWD":/work "$IMAGE" bash -lc "./test.sh $*"
