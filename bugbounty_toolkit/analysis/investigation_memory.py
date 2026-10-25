"""Lifecycle metadata for saved local investigations."""

from __future__ import annotations

import json
import re
from pathlib import PurePosixPath, PureWindowsPath
from typing import Mapping

from ..core.records import RecordStore, utc_now

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_BUNDLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_STAGE_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,39}$")


class InvestigationMemory:
    """Store a small lifecycle index in the program's existing SQLite database."""

    def __init__(self, records: RecordStore) -> None:
        self.connection = records.connection
        self.connection.executescript(
            """
            create table if not exists investigation_memory (
              investigation_id text primary key,
              status text not null check(status in ('active','closed')),
              bundle_id text not null,
              snapshot_ref text not null,
              stages_json text not null,
              created_at text not null,
              updated_at text not null,
              closed_at text,
              resume_count integer not null default 0
            );
            create table if not exists investigation_memory_events (
              event_id integer primary key autoincrement,
              investigation_id text not null references investigation_memory(investigation_id) on delete cascade,
              event_type text not null check(event_type in ('saved','closed','resumed')),
              occurred_at text not null,
              snapshot_ref text not null
            );
            create index if not exists investigation_memory_events_idx
              on investigation_memory_events(investigation_id, event_id);
            """
        )
        self.connection.commit()

    @staticmethod
    def _validate_id(value: str) -> str:
        if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
            raise ValueError("Investigation ID must be 1-80 safe letters, digits, dots, underscores or hyphens.")
        return value

    @staticmethod
    def _validate_bundle_id(value: str) -> str:
        if not isinstance(value, str) or not _BUNDLE_ID.fullmatch(value):
            raise ValueError("Evidence bundle ID is missing or invalid.")
        return value

    @staticmethod
    def _validate_snapshot_ref(value: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 240 or "\\" in value:
            raise ValueError("Investigation snapshot reference must be a short program-relative path.")
        path = PurePosixPath(value)
        if path.is_absolute() or PureWindowsPath(value).drive or any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("Investigation snapshot reference must stay inside the program directory.")
        return path.as_posix()

    @staticmethod
    def _stage_summary(value: Mapping[str, object]) -> str:
        if len(value) > 20:
            raise ValueError("Investigation memory accepts at most 20 stage summaries.")
        summary: dict[str, str] = {}
        for name, row in value.items():
            if not isinstance(name, str) or not _STAGE_NAME.fullmatch(name):
                raise ValueError("Investigation stage names must use safe lowercase identifiers.")
            status = row.get("status") if isinstance(row, dict) else None
            if not isinstance(status, str) or not status or len(status) > 80:
                raise ValueError("Each investigation stage must include a short status.")
            summary[name] = status
        return json.dumps(summary, sort_keys=True, separators=(",", ":"))

    def save_snapshot(
        self,
        investigation_id: str,
        bundle_id: str,
        snapshot_ref: str,
        stages: Mapping[str, object],
        *,
        resume: bool = False,
    ) -> dict[str, object]:
        """Create a memory entry or resume a closed entry with the same evidence bundle."""
        identifier = self._validate_id(investigation_id)
        evidence_id = self._validate_bundle_id(bundle_id)
        snapshot = self._validate_snapshot_ref(snapshot_ref)
        stage_json = self._stage_summary(stages)
        now = utc_now()
        existing = self.connection.execute(
            "select status,bundle_id,resume_count from investigation_memory where investigation_id=?",
            (identifier,),
        ).fetchone()
        if existing is None:
            if resume:
                raise ValueError("Cannot resume an unknown investigation; save it once first.")
            self.connection.execute(
                """insert into investigation_memory(
                     investigation_id,status,bundle_id,snapshot_ref,stages_json,created_at,updated_at,closed_at,resume_count
                   ) values(?,'active',?,?,?,?,?,null,0)""",
                (identifier, evidence_id, snapshot, stage_json, now, now),
            )
            event = "saved"
        else:
            if not resume:
                raise ValueError("Investigation already exists; close it before using --resume-session.")
            if existing["status"] != "closed":
                raise ValueError("Only a closed investigation can be resumed.")
            if existing["bundle_id"] != evidence_id:
                raise ValueError(
                    "Resuming requires the same evidence bundle; start a new investigation for new evidence."
                )
            self.connection.execute(
                """update investigation_memory set status='active',snapshot_ref=?,stages_json=?,updated_at=?,
                   closed_at=null,resume_count=resume_count+1 where investigation_id=?""",
                (snapshot, stage_json, now, identifier),
            )
            event = "resumed"
        self.connection.execute(
            "insert into investigation_memory_events(investigation_id,event_type,occurred_at,snapshot_ref) values(?,?,?,?)",
            (identifier, event, now, snapshot),
        )
        self.connection.commit()
        result = self.get(identifier)
        if result is None:
            raise RuntimeError("Saved investigation memory could not be read back.")
        return result

    def close(self, investigation_id: str) -> dict[str, object]:
        """Close an active investigation without deleting its saved history."""
        identifier = self._validate_id(investigation_id)
        row = self.connection.execute(
            "select status,snapshot_ref from investigation_memory where investigation_id=?", (identifier,)
        ).fetchone()
        if row is None:
            raise ValueError("Investigation does not exist in this program's local memory.")
        if row["status"] != "active":
            raise ValueError("Investigation is already closed.")
        now = utc_now()
        self.connection.execute(
            "update investigation_memory set status='closed',updated_at=?,closed_at=? where investigation_id=?",
            (now, now, identifier),
        )
        self.connection.execute(
            "insert into investigation_memory_events(investigation_id,event_type,occurred_at,snapshot_ref) values(?,?,?,?)",
            (identifier, "closed", now, row["snapshot_ref"]),
        )
        self.connection.commit()
        result = self.get(identifier)
        if result is None:
            raise RuntimeError("Closed investigation memory could not be read back.")
        return result

    def get(self, investigation_id: str) -> dict[str, object] | None:
        """Return lifecycle metadata and event history for one investigation."""
        identifier = self._validate_id(investigation_id)
        row = self.connection.execute(
            "select * from investigation_memory where investigation_id=?", (identifier,)
        ).fetchone()
        if row is None:
            return None
        events = self.connection.execute(
            "select event_type,occurred_at,snapshot_ref from investigation_memory_events "
            "where investigation_id=? order by event_id",
            (identifier,),
        ).fetchall()
        stages_value = json.loads(row["stages_json"])
        stages = stages_value if isinstance(stages_value, dict) else {}
        return {
            "investigation_id": row["investigation_id"],
            "status": row["status"],
            "bundle_id": row["bundle_id"],
            "snapshot_ref": row["snapshot_ref"],
            "stages": stages,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "closed_at": row["closed_at"],
            "resume_count": row["resume_count"],
            "events": [dict(event) for event in events],
        }

    def list_recent(self, limit: int = 50) -> list[dict[str, object]]:
        """Return a bounded list of investigation summaries without loading event histories."""
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Investigation list limit must be from 1 to 100.")
        rows = self.connection.execute(
            "select investigation_id,status,bundle_id,snapshot_ref,updated_at,resume_count from investigation_memory "
            "order by updated_at desc, investigation_id limit ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]
