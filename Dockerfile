# VTint(ELF 적응) 구현 · 재현 환경
# 어느 PC에서도 동일하게 동작하도록 Ubuntu 22.04 고정
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ \
        gcc \
        binutils \
        python3 \
        python3-pip \
        xxd \
        file \
        less \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 분석/재작성용 파이썬 라이브러리
#  - pyelftools : ELF 파싱(ELFParser)
#  - capstone   : 디스어셈블(BitCover)
#  - lief       : 바이너리 재작성(VRewriter)
RUN pip3 install --no-cache-dir \
        pyelftools==0.31 \
        capstone==5.0.1 \
        lief==0.15.1

WORKDIR /work
# 소스는 docker run 시 -v 로 마운트 (코드 수정이 바로 반영되도록)
CMD ["/bin/bash"]
