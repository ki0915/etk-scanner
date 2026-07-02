from datetime import datetime
from sqlalchemy import String, Integer, DateTime, Text, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum

from backend.app.database import Base


class CandidateStatus(str, enum.Enum):
    pending = "pending"
    analyzing = "analyzing"
    go = "go"
    stop = "stop"
    verifying = "verifying"
    submitted = "submitted"
    rejected = "rejected"


class Candidate(Base):
    __tablename__ = "candidates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    etk_id: Mapped[str] = mapped_column(String(20), unique=True, index=True)  # ETK-CAND-0001
    package: Mapped[str] = mapped_column(String(100))
    ecosystem: Mapped[str] = mapped_column(String(10))   # pypi / npm
    github_url: Mapped[str] = mapped_column(String(500))
    weekly_downloads: Mapped[int] = mapped_column(Integer, default=0)
    stars: Mapped[int] = mapped_column(Integer, default=0)
    reason: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[CandidateStatus] = mapped_column(
        SAEnum(CandidateStatus), default=CandidateStatus.pending
    )
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="candidate")


class VulnSeverity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class VulnStatus(str, enum.Enum):
    found = "found"
    poc_pending = "poc_pending"
    poc_confirmed = "poc_confirmed"
    da_passed = "da_passed"
    da_failed = "da_failed"
    reported = "reported"


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    candidate_id: Mapped[int] = mapped_column(Integer, index=True)
    vuln_index: Mapped[int] = mapped_column(Integer, default=1)  # vuln-001, vuln-002
    vuln_type: Mapped[str] = mapped_column(String(100))          # SQL Injection, RCE, ...
    cwe: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(nullable=True)
    severity: Mapped[VulnSeverity | None] = mapped_column(SAEnum(VulnSeverity), nullable=True)
    description: Mapped[str] = mapped_column(Text)
    affected_file: Mapped[str | None] = mapped_column(String(500), nullable=True)
    affected_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    poc_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    poc_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_md: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[VulnStatus] = mapped_column(SAEnum(VulnStatus), default=VulnStatus.found)
    analysis_raw: Mapped[str | None] = mapped_column(Text, nullable=True)  # Claude 원문
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    candidate: Mapped["Candidate"] = relationship(
        back_populates="vulnerabilities",
        foreign_keys=[candidate_id],
        primaryjoin="Vulnerability.candidate_id == Candidate.id"
    )
