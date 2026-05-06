"""SQLAlchemy database models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from sqlalchemy import ForeignKey, Integer, String, DateTime, Float, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, Session


class Base(DeclarativeBase):
    pass


class Server(Base):
    __tablename__ = "servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repo_url: Mapped[str] = mapped_column(String(500), unique=True, index=True)
    owner: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    stars: Mapped[int] = mapped_column(Integer, default=0)
    registered_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    scans: Mapped[List["Scan"]] = relationship(
        back_populates="server", cascade="all, delete-orphan", lazy="selectin"
    )

    @property
    def latest_scan(self) -> "Scan | None":
        if not self.scans:
            return None
        return max(self.scans, key=lambda s: s.scanned_at)

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id"))
    score: Mapped[int] = mapped_column(Integer)
    grade: Mapped[str] = mapped_column(String(1))
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )

    server: Mapped["Server"] = relationship(back_populates="scans")
    findings: Mapped[List["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )
    artifacts: Mapped[List["Artifact"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    rule_id: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(10))
    message: Mapped[str] = mapped_column(String(1000))
    file: Mapped[str | None] = mapped_column(String(500), nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="findings")


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    artifact_type: Mapped[str] = mapped_column(String(20))  # mitre, sigma, atomic, gap
    filename: Mapped[str | None] = mapped_column(String(200), nullable=True)
    content: Mapped[str] = mapped_column(String(100000))  # Large text storage
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )

    scan: Mapped["Scan"] = relationship(back_populates="artifacts")
