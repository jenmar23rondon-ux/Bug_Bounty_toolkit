"""Synthetic FastAPI app for the offline authorization audit lab."""

from fastapi import APIRouter, Depends, FastAPI, HTTPException

from company_sec import external_authz, verify_access  # unresolved on purpose

from .deps import (
    DOCS,
    authorize,
    check_permission,
    ensure_owner,
    get_current_user,
    get_owned_project,
)
from .services import get_order_for_user

app = FastAPI()
notes_router = APIRouter(dependencies=[Depends(get_current_user)])


@app.get("/health")
def health() -> dict[str, str]:
    return {"ok": "yes"}


@app.get("/docs/{doc_id}")
def read_doc(doc_id: int, user: dict[str, int] = Depends(get_current_user)) -> dict[str, int]:
    doc = DOCS[doc_id]
    if doc["owner_id"] != user["id"]:
        raise HTTPException(status_code=404)
    return doc


@app.get("/invoices/{invoice_id}")
def read_invoice(invoice_id: int, user: dict[str, int] = Depends(get_current_user)) -> dict[str, int]:
    return DOCS[invoice_id]


@app.get("/orders/{order_id}")
def read_order(order_id: int, user: dict[str, int] = Depends(get_current_user)) -> dict[str, int]:
    return get_order_for_user(order_id, user)


@notes_router.get("/notes/{note_id}")
def read_note(note_id: int) -> dict[str, int]:
    return DOCS[note_id]


@app.get("/projects/{project_id}")
def read_project(project: dict[str, int] = Depends(get_owned_project)) -> dict[str, int]:
    return project


@app.get("/reports/{report_id}", dependencies=[Depends(external_authz)])
def read_report(report_id: int) -> dict[str, int]:
    return DOCS[report_id]


@app.get("/files/{file_id}")
def read_file(file_id: int, user: dict[str, int] = Depends(get_current_user)) -> dict[str, int]:
    record = DOCS[file_id]
    ensure_owner(record, user)
    return record


@app.get("/records/{record_id}")
def read_record(record_id: int, user: dict[str, int] = Depends(get_current_user)) -> dict[str, int]:
    rec = DOCS[record_id]
    if not (user.get("is_admin") or rec["owner_id"] == user["id"]):
        raise HTTPException(status_code=403)
    return rec


@app.get("/tickets/{ticket_id}")
def read_ticket(ticket_id: int, user: dict[str, int] = Depends(get_current_user)) -> dict[str, int]:
    rec = DOCS[ticket_id]
    check_permission(user, rec)
    authorize(user, rec)
    return rec


@app.get("/drafts/{draft_id}")
def read_draft(draft_id: int, user: dict[str, int] = Depends(get_current_user)) -> dict[str, int]:
    rec = DOCS[draft_id]
    if False:
        if rec["owner_id"] != user["id"]:
            raise HTTPException(status_code=403)
    return rec


@app.get("/archives/{archive_id}")
def read_archive(archive_id: int, user: dict[str, int] = Depends(get_current_user)) -> dict[str, int]:
    rec = DOCS[archive_id]
    return rec
    if rec["owner_id"] != user["id"]:
        raise HTTPException(status_code=403)


@app.get("/shares/{share_id}")
def read_share(share_id: int, user: dict[str, int] = Depends(get_current_user)) -> dict[str, int]:
    rec = DOCS[share_id]
    verify_access(user, rec)
    return rec


app.include_router(notes_router)
