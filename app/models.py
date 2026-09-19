from typing import Literal

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    question: str = Field(
        default="What happened, how serious is it, and what should the analyst do next?",
        min_length=5,
        max_length=500,
    )
    logs: str = Field(min_length=2, max_length=100_000)
    mode: Literal["demo", "live"] = "demo"
    explanation_mode: Literal["analyst", "teach_me"] = "teach_me"


class Finding(BaseModel):
    title: str
    evidence: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    source_ip: str | None = None
    count: int = 1
    mitre_technique: str | None = None
    mitre_name: str | None = None


class TimelineEvent(BaseModel):
    order: int
    timestamp: str
    label: str
    detail: str
    suspicious: bool


class RiskFactor(BaseModel):
    reason: str
    points: int


class Citation(BaseModel):
    number: int
    title: str
    url: str
    excerpt: str
    score: float


class AnalyzeResponse(BaseModel):
    answer: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)
    risk_score: int = Field(ge=0, le=100)
    risk_factors: list[RiskFactor]
    findings: list[Finding]
    timeline: list[TimelineEvent]
    recommended_actions: list[str]
    citations: list[Citation]
    metadata: dict[str, str | int | float | bool]


class HealthResponse(BaseModel):
    status: str
    mode: str
    knowledge_documents: int
