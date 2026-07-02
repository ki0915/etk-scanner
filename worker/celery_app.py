import os
from celery import Celery

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "ai_pentester",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["worker.tasks.analyze"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_time_limit=600,      # 태스크 최대 10분
    worker_prefetch_multiplier=1,  # 병렬 분석 시 공정 분배
)
