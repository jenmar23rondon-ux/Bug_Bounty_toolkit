from __future__ import annotations

import sqlite3
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class ProgramPaths:
    root: Path
    program: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", self.program):
            raise ValueError("Program must be a name with letters, digits, underscores or hyphens.")

    @property
    def program_dir(self) -> Path:
        return self.root / self.program

    @property
    def db_path(self) -> Path:
        return self.program_dir / "toolkit.sqlite3"

    @property
    def scope_file(self) -> Path:
        return self.program_dir / "scope.txt"

    @property
    def evidence_dir(self) -> Path:
        return self.program_dir / "evidence"

    @property
    def raw_dir(self) -> Path:
        return self.program_dir / "raw"

    @property
    def reports_dir(self) -> Path:
        return self.program_dir / "reports"

    @property
    def reviewed_dir(self) -> Path:
        return self.program_dir / "reviewed"

    def ensure(self) -> None:
        for path in [self.program_dir, self.evidence_dir, self.raw_dir, self.reports_dir, self.reviewed_dir]:
            path.mkdir(parents=True, exist_ok=True)


class RecordStore:
    def __init__(self, paths: ProgramPaths):
        self.paths = paths
        self.paths.ensure()
        self.connection = sqlite3.connect(self.paths.db_path)
        self.connection.row_factory = sqlite3.Row
        self.migrate()

    def migrate(self) -> None:
        self.connection.executescript(
            """
            create table if not exists program (
              key text primary key,
              value text not null
            );
            create table if not exists runs (
              id integer primary key autoincrement,
              started_at text not null,
              command_name text not null,
              target text,
              command text not null,
              return_code integer,
              output_path text
            );
            create table if not exists reviewed (
              id integer primary key autoincrement,
              reviewed_at text not null,
              kind text not null,
              value text not null,
              note text,
              unique(kind, value)
            );
            create table if not exists findings (
              id text primary key,
              created_at text not null,
              title text not null,
              category text not null,
              severity text not null,
              status text not null,
              target text not null,
              summary text not null,
              evidence_path text
            );
            """
        )
        self.connection.commit()

    def set_program_meta(self, **items: str) -> None:
        self.connection.executemany(
            "insert into program(key, value) values(?, ?) on conflict(key) do update set value = excluded.value",
            items.items(),
        )
        self.connection.commit()

    def add_run(
        self, command_name: str, target: str | None, command: Iterable[str], return_code: int, output_path: Path | None
    ) -> None:
        self.connection.execute(
            "insert into runs(started_at, command_name, target, command, return_code, output_path) values(?, ?, ?, ?, ?, ?)",
            (
                utc_now(),
                command_name,
                target,
                " ".join(command),
                return_code,
                str(output_path) if output_path else None,
            ),
        )
        self.connection.commit()

    def mark_reviewed(self, kind: str, value: str, note: str | None = None) -> None:
        self.connection.execute(
            """
            insert into reviewed(reviewed_at, kind, value, note) values(?, ?, ?, ?)
            on conflict(kind, value) do update set reviewed_at = excluded.reviewed_at, note = excluded.note
            """,
            (utc_now(), kind, value, note),
        )
        self.connection.commit()

    def add_finding(
        self,
        finding_id: str,
        title: str,
        category: str,
        severity: str,
        target: str,
        summary: str,
        evidence_path: str | None = None,
    ) -> None:
        self.connection.execute(
            """
            insert into findings(id, created_at, title, category, severity, status, target, summary, evidence_path)
            values(?, ?, ?, ?, ?, 'new', ?, ?, ?)
            on conflict(id) do update set title = excluded.title, category = excluded.category,
              severity = excluded.severity, target = excluded.target, summary = excluded.summary, evidence_path = excluded.evidence_path
            """,
            (finding_id, utc_now(), title, category, severity, target, summary, evidence_path),
        )
        self.connection.commit()

    def finding(self, finding_id: str) -> sqlite3.Row | None:
        return self.connection.execute("select * from findings where id = ?", (finding_id,)).fetchone()

    def metadata(self) -> dict[str, str]:
        return dict(self.connection.execute("select key, value from program").fetchall())

    def require_authorization(self) -> None:
        if not self.metadata().get("authorization", "").strip():
            raise ValueError("Initialize this program with --authorization before sending requests.")

    def runs(self) -> list[dict[str, object]]:
        return [dict(row) for row in self.connection.execute("select * from runs order by id desc")]

    def reviewed(self) -> list[dict[str, object]]:
        return [dict(row) for row in self.connection.execute("select * from reviewed order by id desc")]

    def findings(self) -> list[dict[str, object]]:
        return [dict(row) for row in self.connection.execute("select * from findings order by created_at desc")]

    def close(self) -> None:
        self.connection.close()

    def counts(self) -> dict[str, int]:
        return {
            "runs": self.connection.execute("select count(*) from runs").fetchone()[0],
            "reviewed": self.connection.execute("select count(*) from reviewed").fetchone()[0],
            "findings": self.connection.execute("select count(*) from findings").fetchone()[0],
        }
