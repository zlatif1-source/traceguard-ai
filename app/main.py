import logging
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.models import AnalyzeRequest, AnalyzeResponse, HealthResponse
from app.service import SecurityAnalystService

settings = get_settings()
logging.basicConfig(level=settings.log_level)

app = FastAPI(
    title="TraceGuard AI",
    description="An explainable SOC copilot by Zain Latif.",
    version="0.1.0",
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@lru_cache
def get_service() -> SecurityAnalystService:
    return SecurityAnalystService(settings)


@app.get("/", include_in_schema=False)
def home() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    service = get_service()
    return HealthResponse(
        status="ok",
        mode=settings.app_mode,
        knowledge_documents=service.store.count(),
    )


@app.get("/api/sample", response_model=dict[str, str])
def sample_logs() -> dict[str, str]:
    path = PROJECT_ROOT / "data" / "sample_logs" / "brute_force.jsonl"
    return {"logs": path.read_text(encoding="utf-8")}


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    try:
        return get_service().analyze(request)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except Exception as error:
        logging.exception("Analysis failed")
        raise HTTPException(status_code=500, detail="Analysis failed safely.") from error
