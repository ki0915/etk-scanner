# PoC 실행 샌드박스
# run.py가 docker run --network none --read-only --cap-drop ALL 로 실행
FROM python:3.12-slim

# 비루트 사용자 생성
RUN useradd -m -u 1000 sandbox && \
    mkdir -p /sandbox /home/sandbox/.cache && \
    chown sandbox:sandbox /sandbox /home/sandbox/.cache

# pip 캐시 경로를 sandbox 홈으로
ENV PIP_CACHE_DIR=/home/sandbox/.cache/pip
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /sandbox
USER sandbox

CMD ["python", "/sandbox/poc.py"]
