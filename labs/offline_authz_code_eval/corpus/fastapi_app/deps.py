"""Synthetic FastAPI dependencies (never executed by the audit)."""

from fastapi import Depends, Header, HTTPException

DOCS: dict[int, dict[str, int]] = {}
PROJECTS: dict[int, dict[str, int]] = {}


def get_current_user(authorization: str = Header(default="")) -> dict[str, int]:
    if not authorization:
        raise HTTPException(status_code=401)
    return {"id": 1}


def get_owned_project(project_id: int, user: dict[str, int] = Depends(get_current_user)) -> dict[str, int]:
    project = PROJECTS[project_id]
    if project["owner_id"] != user["id"]:
        raise HTTPException(status_code=404)
    return project


def ensure_owner(record: dict[str, int], user: dict[str, int]) -> None:
    if record["owner_id"] != user["id"]:
        raise HTTPException(status_code=403)


def check_permission(user: dict[str, int], record: dict[str, int]) -> bool:
    # Distraction: a "permission" helper that checks nothing.
    return True


def authorize(user: dict[str, int], record: dict[str, int]) -> None:
    pass
