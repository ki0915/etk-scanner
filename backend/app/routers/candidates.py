from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from worker.tasks.analyze import analyze_candidate

router = APIRouter(prefix="/candidates", tags=["candidates"])


class AddCandidateRequest(BaseModel):
    package: str
    ecosystem: str          # pypi / npm
    github_url: str
    weekly_downloads: int = 0
    stars: int = 0
    reason: str = ""


class AnalyzeRequest(BaseModel):
    etk_id: str
    github_url: str


@router.post("/")
def add_candidate(req: AddCandidateRequest):
    """후보 패키지 등록 (DB 연동 전 skeleton)."""
    return {"status": "ok", "package": req.package}


@router.post("/analyze")
def trigger_analysis(req: AnalyzeRequest):
    """분석 태스크 큐에 등록."""
    task = analyze_candidate.delay(req.etk_id, req.github_url)
    return {"task_id": task.id, "etk_id": req.etk_id, "status": "queued"}


@router.get("/{task_id}/status")
def get_task_status(task_id: str):
    """Celery 태스크 상태 조회."""
    from worker.celery_app import celery_app
    result = celery_app.AsyncResult(task_id)
    return {
        "task_id": task_id,
        "state": result.state,
        "result": result.result if result.ready() else None,
    }
