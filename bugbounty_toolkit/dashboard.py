"""Loopback-only, read-oriented local investigation dashboard."""

from __future__ import annotations

import ipaddress
import json
import re
import tempfile
from collections.abc import Awaitable, Callable
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse

from .authorization_workbench import build_workbench
from .authorization_workbench_ui import WORKBENCH_HTML
from .analysis.evidence_engine import MAX_INPUT_BYTES, import_evidence
from .analysis.evidence_graph import EvidenceGraphStore
from .analysis.investigation_memory import InvestigationMemory
from .core.records import ProgramPaths, RecordStore
from .fuzzing.wordlist_manager import default_registry_path, list_wordlists, load_collections
from .dashboard_triage import (
    ai_review_differences,
    build_triage,
    candidate_detail,
    compare_prioritization_runs,
    mask_display_secrets,
    review_queue_reports,
)
from .analysis.unified_security_triage import build_unified_security_triage
from .reporting.evidence import write_evidence_json

_PROGRAM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
_UPLOAD_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REPORT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_UPLOAD_SUFFIXES = {".csv", ".har", ".html", ".htm", ".json", ".jsonl", ".md", ".txt", ".xml"}
_REPORT_SUFFIXES = {".html", ".json", ".md", ".pdf"}
_MAX_REPORT_BYTES = 8 * 1024 * 1024
_RESOURCE_ID_SEGMENT = re.compile(r"^(?:\d{1,20}|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,35})$")
_DISCOVERY_CLASSIFICATIONS = {
    "generic_response",
    "endpoint_candidate",
    "not_found",
    "rate_limited",
    "authentication_required",
    "access_denied",
    "server_error",
    "redirect",
    "authentication_redirect",
    "authentication_route",
    "inconclusive",
}
_ACCESS_CLASSIFICATIONS = {
    "candidate",
    "rejected_in_this_test",
    "inconclusive",
    "public_endpoint",
    "control_valid",
    "insufficient_evidence",
    "denied",
}

_DASHBOARD_HTML = """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bug Bounty Toolkit · Triage local</title>
<style>
:root{--bg:#101827;--panel:#172235;--line:#39465b;--fg:#e6edf3;--muted:#a9b6c8;--warn:#ffd479;--bad:#ff8f8f;--ok:#8fe3a8}
*{box-sizing:border-box}body{font:16px system-ui,sans-serif;max-width:1280px;margin:0 auto;padding:1rem;background:var(--bg);color:var(--fg)}
section{border:1px solid var(--line);border-radius:8px;padding:1rem;margin:1rem 0;background:var(--panel)}
button,input,select{font:inherit;padding:.45rem;margin:.2rem;min-height:2.5rem}button{cursor:pointer}
:focus-visible{outline:3px solid #8bc5ff;outline-offset:2px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:28rem;overflow:auto}
a{color:#8bc5ff}.notice{color:var(--warn)}.muted{color:var(--muted)}.bad{color:var(--bad)}.ok{color:var(--ok)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr));gap:1rem}
.cards{display:flex;flex-wrap:wrap;gap:.5rem}.card{border:1px solid var(--line);border-radius:6px;padding:.5rem .75rem;min-width:8rem}
.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid var(--line);padding:.4rem;text-align:left;vertical-align:top}
.badge{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:0 .5rem;font-size:.85rem}
.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
</style></head><body>
<header><h1>Bug Bounty Toolkit · Triage</h1>
<p class="notice" role="note">Panel local de solo lectura: muestra artefactos ya guardados. No ejecuta escáneres, no aprueba pruebas, no confirma vulnerabilidades, no cambia el scope, no ejecuta comandos y no envía evidencia a ningún servicio.</p></header>
<main>
<section aria-labelledby="h-overview"><h2 id="h-overview">Vista general</h2><button id="refresh" type="button">Actualizar</button>
<div id="summary" class="cards" aria-live="polite"></div><div id="status-msg" role="status"></div></section>
<section aria-labelledby="h-queue"><h2 id="h-queue">Candidatos priorizados</h2>
<form id="filters"><label>Categoría <select id="f-category"><option value="">todas</option></select></label>
<label>Estado <select id="f-state"><option value="">todos</option></select></label>
<label>Evidencia <select id="f-evidence"><option value="">cualquiera</option></select></label>
<button type="submit">Filtrar</button></form>
<details><summary>Cómo se ordena y sus límites</summary><ul id="ranking"></ul></details>
<div class="table-wrap"><table><caption class="sr-only">Cola de triage</caption><thead><tr><th scope="col">#</th><th scope="col">Candidato</th><th scope="col">Categoría</th><th scope="col">Estado</th><th scope="col">Evidencia</th><th scope="col">Flujo IDOR/BOLA</th><th scope="col">Avisos</th></tr></thead><tbody id="queue"></tbody></table></div>
<p id="queue-empty" class="muted"></p></section>
<div class="grid">
<section aria-labelledby="h-detail"><h2 id="h-detail">Detalle y procedencia</h2><div id="detail" aria-live="polite"><p class="muted">Selecciona un candidato.</p></div></section>
<section aria-labelledby="h-coverage"><h2 id="h-coverage">Cobertura</h2><div id="coverage"></div></section>
<section aria-labelledby="h-issues"><h2 id="h-issues">Referencias rotas y evidencias inválidas</h2><ul id="issues"></ul></section>
<section aria-labelledby="h-ai"><h2 id="h-ai">Diferencias entre revisores IA</h2><div id="ai"></div></section>
<section aria-labelledby="h-runs"><h2 id="h-runs">Progreso y comparación de ejecuciones</h2><div id="runs"></div></section>
<section aria-labelledby="h-queue-reports"><h2 id="h-queue-reports">Reportes para revisión humana</h2><div id="security-research" class="panel"></div><div id="review-queue"></div><div id="reports"></div><pre id="report-content"></pre></section>
</div>
<details><summary>Datos de investigación (vistas anteriores)</summary><div class="grid">
<section><h2>Investigaciones</h2><pre id="overview"></pre></section>
<section><h2>Importar evidencia</h2><label for="artifact">Archivo local</label><input id="artifact" type="file"><button id="upload" type="button">Importar offline</button><pre id="import-result"></pre></section>
<section><h2>Grafo</h2><form id="graph-form"><label>Endpoint <input id="endpoint" placeholder="/api/orders/{id}"></label><button>Buscar</button></form><pre id="graph"></pre></section>
<section><h2>Hipótesis y controles pendientes</h2><pre id="hypotheses"></pre></section>
<section><h2>Benchmark</h2><pre id="benchmark"></pre></section>
<section><h2>Wordlists locales</h2><pre id="wordlists"></pre></section>
<section><h2>Descubrimiento y presupuesto</h2><pre id="discovery"></pre></section>
<section><h2>Matriz de autorización</h2><pre id="access-matrix"></pre></section>
</div></details>
</main>
<script>
const $=id=>document.getElementById(id);
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined&&text!==null)n.textContent=String(text);if(cls)n.className=cls;return n;};
const show=(id,value)=>{$(id).textContent=JSON.stringify(value,null,2)};
async function getJSON(url){const r=await fetch(url,{credentials:'same-origin'});const body=await r.json().catch(()=>({detail:'Respuesta no válida'}));if(!r.ok)throw new Error(body.detail||('HTTP '+r.status));return body;}
function fillSelect(id,values,current){const s=$(id);const keep=s.options[0];s.replaceChildren(keep);for(const v of values){const o=el('option',v);o.value=v;if(v===current)o.selected=true;s.append(o);}}
function card(label,value,cls){const c=el('div',null,'card');c.append(el('div',label,'muted'),el('strong',value,cls));return c;}
function list(id,items){const u=$(id);u.replaceChildren();for(const i of items)u.append(el('li',i));}
async function loadTriage(){
  const q=new URLSearchParams();for(const [k,id] of [['category','f-category'],['state','f-state'],['evidence','f-evidence']]){if($(id).value)q.set(k,$(id).value);}
  const t=await getJSON('/api/triage?'+q);
  const st=t.candidate_states||{};
  $('summary').replaceChildren(card('Candidatos',t.counts.total),card('Requieren validación',st.requires_validation||0,'notice'),card('Confirmados (revisión humana)',st.confirmed||0,'ok'),card('Rechazados',st.rejected||0),card('Referencias rotas',t.broken_references||0,(t.broken_references?'bad':'')),card('Cobertura',Math.round((t.coverage.coverage_ratio||0)*100)+'%'));
  $('status-msg').textContent=t.message||(t.ledger_valid===false?'El ledger tiene errores de validación; revisa la sección de referencias rotas.':'');
  if(t.filters.categories){fillSelect('f-category',t.filters.categories,t.filters.applied.category);fillSelect('f-state',t.filters.states,t.filters.applied.state);fillSelect('f-evidence',t.filters.evidence,t.filters.applied.evidence);}
  list('ranking',[...t.ranking.order,...t.ranking.limits]);
  const body=$('queue');body.replaceChildren();
  for(const c of t.candidates){const tr=el('tr');const link=el('button',c.candidate_id);link.type='button';link.setAttribute('aria-label','Ver detalle de '+c.candidate_id);link.addEventListener('click',()=>loadDetail(c.candidate_id).catch(e=>{$('detail').textContent='Error: '+e.message;}));
    const name=el('td');name.append(link,el('div',c.title||'','muted'));
    const flow=c.idor_flow.applicable?c.idor_flow.stage:'n/a';
    tr.append(el('td',c.rank),name,el('td',c.category),el('td',c.displayed_state,'badge'),el('td',c.evidence_status+' ('+c.evidence_counts.usable+'/'+c.evidence_counts.referenced+')',c.evidence_status==='present'?'ok':'bad'),el('td',flow),el('td',c.warnings.join(' ')||'—',c.warnings.length?'notice':''));body.append(tr);}
  $('queue-empty').textContent=t.candidates.length?'':(t.counts.total?'Ningún candidato coincide con los filtros.':(t.message||'Sin candidatos.'));
  const cov=$('coverage');cov.replaceChildren();const ss=t.coverage.surface_status||{};
  const cards=el('div',null,'cards');for(const [k,v] of Object.entries(ss))cards.append(card(k,v));cov.append(cards);
  const pend=el('ul');for(const p of t.coverage.pending_or_blocked||[])pend.append(el('li',(p.ref||p.surface_id)+' — '+(p.blocker||'sin bloqueo declarado')));cov.append(el('h3','Pendiente / bloqueado'),pend);
  list('issues',(t.issues||[]).map(i=>'['+i.severity+'] '+i.code+' · '+(i.ref||'')+' · '+(i.message||'')));if(!(t.issues||[]).length)list('issues',['Sin incidencias en el ledger.']);
}
async function loadDetail(id){
  const d=await getJSON('/api/triage/candidates/'+encodeURIComponent(id));const box=$('detail');box.replaceChildren();const c=d.candidate;
  box.append(el('h3',c.candidate_id),el('p','Estado mostrado: '+c.displayed_state+' (ledger: '+c.ledger_state+')'),el('p','Banda de impacto potencial (heurística): '+c.potential_impact_band));
  box.append(el('h4','Controles que faltan para validar'));const mc=el('ul');for(const m of c.missing_controls)mc.append(el('li',m));if(!c.missing_controls.length)mc.append(el('li','Ninguno registrado.'));box.append(mc);
  if(c.idor_flow.applicable){box.append(el('h4','Flujo IDOR/BOLA'));const f=el('ol');for(const s of c.idor_flow.stages)f.append(el('li',s.name+': '+(s.done?'hecho':'pendiente')));box.append(f);}
  box.append(el('h4','Procedencia (minimizada)'),el('p',d.provenance_notice,'muted'));const pv=el('ul');for(const p of d.evidence_provenance)pv.append(el('li',[p.evidence_id,p.status,p.tool,p.captured_at,p.sha256_prefix&&('sha256:'+p.sha256_prefix+'…')].filter(Boolean).join(' · ')));box.append(pv);
  if(d.issues.length){box.append(el('h4','Incidencias'));const iu=el('ul');for(const i of d.issues)iu.append(el('li',i.code+': '+(i.message||''),'bad'));box.append(iu);}
}
async function loadSide(){
  const ai=await getJSON('/api/triage/ai-reviews');const a=$('ai');a.replaceChildren();
  if(!ai.latest){a.append(el('p',ai.message,'muted'));}else{a.append(el('p','Coincidencia de decisión: '+(ai.decision_agreement?'sí':'no')+' · independientes: '+(ai.independent?'sí':'no')+' · el consenso no es prueba.'));for(const [k,label] of [['disputed_evidence','Evidencia disputada'],['cited_by_first_only','Solo revisor A'],['cited_by_second_only','Solo revisor B'],['missing_controls_union','Controles faltantes']]){a.append(el('h4',label));const u=el('ul');for(const v of ai[k])u.append(el('li',v));if(!ai[k].length)u.append(el('li','—'));a.append(u);}}
  const runs=await getJSON('/api/triage/runs');const r=$('runs');r.replaceChildren();const p=runs.progress;
  r.append(el('div',null,'cards'));r.firstChild.append(card('Ejecuciones',p.runs_total),card('Errores técnicos',p.technical_errors,p.technical_errors?'bad':''),card('Sin terminar',p.unfinished||0));
  const cmp=runs.comparison;if(!cmp.available){r.append(el('p',cmp.message,'muted'));}else{r.append(el('p','Comparando '+cmp.older+' → '+cmp.newer),el('p','Nuevos: '+(cmp.added.join(', ')||'—')),el('p','Retirados: '+(cmp.removed.join(', ')||'—')));const u=el('ul');for(const s of cmp.score_changes)u.append(el('li',s.group_id+': '+s.before+' → '+s.after));r.append(u);}
  const sr=await getJSON('/api/triage/security-research');const sbox=$('security-research');if(sbox){sbox.replaceChildren();sbox.append(el('p','Investigación unificada (solo lectura; IA no aprueba):','muted'));const ul=el('ul');for(const [k,v] of Object.entries(sr.security_state_counts||{})){if(v)ul.append(el('li',k+': '+v));}sbox.append(ul);sbox.append(el('p','Total: '+(sr.counts&&sr.counts.total||0)+' · AI may confirm findings: '+String(sr.ai_may_confirm_findings),'muted'));}
  const rq=await getJSON('/api/triage/review-queue');const q=$('review-queue');q.replaceChildren(el('p',rq.notice,'muted'),el('p','Candidatos esperando revisión humana: '+(rq.candidates_awaiting_human_review.join(', ')||'ninguno')));
  const data=await getJSON('/api/reports');const box=$('reports');box.replaceChildren();if(!data.reports.length)box.append(el('p','No hay reportes guardados.','muted'));
  for(const item of data.reports){const link=el('a',item.name);link.href='#';link.addEventListener('click',async e=>{e.preventDefault();const x=await fetch('/api/reports/'+encodeURIComponent(item.name)+'/content');$('report-content').textContent=await x.text();});box.append(link,el('br'));}
}
async function loadLegacy(){
  for(const [url,id] of [['/api/overview','overview'],['/api/hypotheses','hypotheses'],['/api/benchmark','benchmark'],['/api/wordlists','wordlists'],['/api/discovery','discovery'],['/api/access-matrix','access-matrix']]){
    try{show(id,await getJSON(url));}catch(e){show(id,{error:e.message});}
  }
}
async function load(){for(const f of [loadTriage,loadSide,loadLegacy]){try{await f();}catch(e){$('status-msg').textContent='Error: '+e.message;}}}
$('refresh').addEventListener('click',()=>load());
$('filters').addEventListener('submit',e=>{e.preventDefault();loadTriage().catch(err=>{$('status-msg').textContent='Error: '+err.message;});});
$('graph-form').addEventListener('submit',async e=>{e.preventDefault();const q=new URLSearchParams({endpoint:$('endpoint').value});const r=await fetch('/api/graph/search?'+q);show('graph',await r.json());});
$('upload').addEventListener('click',async()=>{const f=$('artifact').files[0];if(!f){show('import-result',{error:'Selecciona un archivo.'});return;}if(f.size>33554432){show('import-result',{error:'El límite de importación es 32 MiB.'});return;}const r=await fetch('/api/evidence/import?filename='+encodeURIComponent(f.name),{method:'POST',headers:{'content-type':'application/octet-stream'},body:f});show('import-result',await r.json());await load();});
load();
</script></body></html>"""


def _is_loopback(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def require_loopback_host(value: str) -> str:
    """Validate a bind address so the dashboard cannot listen on a public interface."""
    if not _is_loopback(value):
        raise ValueError("The local dashboard may bind only to a loopback IP address (127.0.0.1 or ::1).")
    return value


def _host_is_local(value: str | None) -> bool:
    if not value:
        return False
    try:
        parsed = urlsplit(f"//{value}")
        hostname = parsed.hostname
    except ValueError:
        return False
    return not parsed.username and not parsed.password and (hostname == "localhost" or _is_loopback(hostname))


def _origin_is_local(value: str | None) -> bool:
    """Absent Origin is allowed (same-origin GET); a present Origin must be loopback http(s)."""
    if value is None:
        return True
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and _host_is_local(parsed.netloc)


def _public_row(row: dict[str, object]) -> dict[str, object]:
    """Withhold local file paths and redact secrets in run/finding rows shown by /api/overview."""
    safe: dict[str, object] = {}
    for key, value in row.items():
        if key in {"output_path", "evidence_path"}:
            safe[key] = Path(value).name[:180] if isinstance(value, str) and value else None
        elif isinstance(value, str):
            safe[key] = mask_display_secrets(value)
        else:
            safe[key] = value
    return safe


def _read_json_file(path: Path, maximum: int = _MAX_REPORT_BYTES) -> object:
    with path.open("rb") as source:
        raw = source.read(maximum + 1)
    if len(raw) > maximum:
        raise HTTPException(status_code=413, detail="Saved artifact exceeds the dashboard read limit.")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise HTTPException(status_code=422, detail="Saved JSON artifact is malformed.") from exc


def _safe_label(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return "".join(character for character in value if character.isprintable())[:120]


def _dashboard_route_template(value: str) -> str | None:
    try:
        path = urlsplit(value).path
    except ValueError:
        return None
    parts = ["{id}" if _RESOURCE_ID_SEGMENT.fullmatch(part) else part for part in path.split("/")]
    return "/".join(parts)[:2048]


def _contained_report_path(paths: ProgramPaths, name: str) -> Path:
    if (
        not _REPORT_NAME_RE.fullmatch(name)
        or Path(name).name != name
        or Path(name).suffix.lower() not in _REPORT_SUFFIXES
    ):
        raise HTTPException(status_code=404, detail="Report not found.")
    reports_root = paths.reports_dir.resolve()
    candidate = paths.reports_dir / name
    if candidate.is_symlink() or not candidate.is_file():
        raise HTTPException(status_code=404, detail="Report not found.")
    resolved = candidate.resolve()
    if resolved.parent != reports_root:
        raise HTTPException(status_code=404, detail="Report not found.")
    return resolved


def create_app(records_root: Path, program: str) -> FastAPI:
    """Create a local dashboard app for one validated program; it exposes no active-check route."""
    if not _PROGRAM_RE.fullmatch(program):
        raise ValueError("Program must be a name with letters, digits, underscores or hyphens.")
    paths = ProgramPaths(records_root, program)
    app = FastAPI(title="Bug Bounty Toolkit local dashboard", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def local_only(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        client_host = request.client.host if request.client is not None else None
        if not _is_loopback(client_host) or not _host_is_local(request.headers.get("host")):
            return JSONResponse(status_code=403, content={"detail": "Dashboard accepts loopback requests only."})
        if not _origin_is_local(request.headers.get("origin")) or request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse(status_code=403, content={"detail": "Cross-origin dashboard requests are rejected."})
        if request.method not in {"GET", "HEAD"} and request.url.path != "/api/evidence/import":
            return JSONResponse(status_code=405, content={"detail": "The dashboard is read-only."})
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        )
        return response

    @app.get("/", response_class=HTMLResponse)
    async def home() -> HTMLResponse:
        return HTMLResponse(
            _DASHBOARD_HTML.replace(
                "</body>", '<p><a href="/authorization-workbench">Authorization comparison workbench</a></p></body>'
            )
        )

    @app.get("/authorization-workbench", response_class=HTMLResponse)
    async def authorization_workbench_page() -> HTMLResponse:
        return HTMLResponse(WORKBENCH_HTML)

    @app.get("/api/authorization-workbench")
    async def authorization_workbench(
        a: str | None = None, b: str | None = None, c: str | None = None
    ) -> dict[str, object]:
        if (a is None) != (b is None) or (c is not None and a is None):
            raise HTTPException(status_code=400, detail="Choose A and B; C is optional.")
        try:
            return build_workbench(paths, [v for v in (a, b, c) if v is not None])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Choose distinct existing captures.") from exc

    @app.get("/api/overview")
    async def overview() -> dict[str, object]:
        if not paths.db_path.is_file():
            return {"program": program, "investigations": [], "findings": [], "runs": [], "database_present": False}
        store = RecordStore(paths)
        try:
            memory = InvestigationMemory(store)
            return {
                "program": program,
                "investigations": memory.list_recent(),
                "findings": [
                    _public_row(dict(row))
                    for row in store.connection.execute("select * from findings order by created_at desc limit 100")
                ],
                "runs": [
                    _public_row(dict(row))
                    for row in store.connection.execute("select * from runs order by id desc limit 50")
                ],
                "database_present": True,
            }
        finally:
            store.close()

    @app.get("/api/investigations/{investigation_id}")
    async def investigation_detail(investigation_id: str) -> dict[str, object]:
        if not paths.db_path.is_file():
            raise HTTPException(status_code=404, detail="Investigation not found.")
        store = RecordStore(paths)
        try:
            result = InvestigationMemory(store).get(investigation_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            store.close()
        if result is None:
            raise HTTPException(status_code=404, detail="Investigation not found.")
        return result

    @app.get("/api/hypotheses")
    async def hypotheses() -> dict[str, object]:
        if not paths.db_path.is_file():
            return {
                "latest": None,
                "hypotheses": [],
                "controls_pending": [],
                "notice": "Las hipótesis del modelo son una segunda opinión, nunca una confirmación.",
            }
        store = RecordStore(paths)
        try:
            rows = InvestigationMemory(store).list_recent(1)
        finally:
            store.close()
        if not rows:
            return {
                "latest": None,
                "hypotheses": [],
                "controls_pending": [],
                "notice": "Las hipótesis del modelo son una segunda opinión, nunca una confirmación.",
            }
        snapshot_ref = rows[0].get("snapshot_ref")
        if not isinstance(snapshot_ref, str):
            return {
                "latest": rows[0],
                "hypotheses": [],
                "controls_pending": [],
                "notice": "Las hipótesis del modelo son una segunda opinión, nunca una confirmación.",
            }
        candidate = (paths.program_dir / Path(*Path(snapshot_ref).parts)).resolve()
        if paths.program_dir.resolve() not in candidate.parents or not candidate.is_file():
            return {
                "latest": rows[0],
                "hypotheses": [],
                "controls_pending": [],
                "notice": "Las hipótesis del modelo son una segunda opinión, nunca una confirmación.",
            }
        snapshot = _read_json_file(candidate)
        if not isinstance(snapshot, dict):
            return {"latest": rows[0], "hypotheses": [], "controls_pending": []}
        hypotheses_value = snapshot.get("hypotheses")
        groups = hypotheses_value.get("groups") if isinstance(hypotheses_value, dict) else None
        safe_groups = []
        if isinstance(groups, list):
            for group in groups[:500]:
                if not isinstance(group, dict):
                    continue
                hypothesis = group.get("hypothesis")
                safe_groups.append(
                    {
                        "group_id": group.get("group_id"),
                        "status": group.get("status"),
                        "hypothesis": hypothesis if isinstance(hypothesis, dict) else None,
                    }
                )
        prioritization = snapshot.get("prioritization")
        steps = prioritization.get("steps") if isinstance(prioritization, dict) else None
        pending = [step for step in steps[:200] if isinstance(step, dict)] if isinstance(steps, list) else []
        access_assessment = snapshot.get("access_control_assessment")
        return {
            "latest": rows[0],
            "hypotheses": safe_groups,
            "controls_pending": pending,
            "access_control_assessment": access_assessment if isinstance(access_assessment, dict) else None,
            "notice": "Las hipótesis del modelo son una segunda opinión, nunca una confirmación.",
        }

    @app.get("/api/graph/search")
    async def graph_search(
        endpoint: str | None = None,
        category: str | None = None,
        account: str | None = None,
        resource: str | None = None,
        finding_id: str | None = None,
    ) -> dict[str, object]:
        if not any((endpoint, category, account, resource, finding_id)):
            raise HTTPException(
                status_code=400, detail="Provide an endpoint, category, account, resource or finding ID."
            )
        if not paths.db_path.is_file():
            return {"type": "evidence-graph-search", "matches": [], "neighbors": [], "relations": []}
        store = RecordStore(paths)
        try:
            return EvidenceGraphStore(store).search(
                endpoint=endpoint, category=category, account=account, resource=resource, finding_id=finding_id
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            store.close()

    @app.get("/api/benchmark")
    async def benchmark() -> dict[str, object]:
        if not paths.reports_dir.is_dir():
            return {"latest": None, "reports": []}
        candidates = sorted(
            (path for path in paths.reports_dir.iterdir() if path.is_file() and not path.is_symlink()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for path in candidates[:50]:
            if path.suffix.lower() != ".json":
                continue
            try:
                data = _read_json_file(path)
            except HTTPException:
                continue
            if isinstance(data, dict) and data.get("type") == "bbtk-benchmark":
                return {"latest": data, "reports": [path.name]}
        return {"latest": None, "reports": []}

    @app.get("/api/wordlists")
    async def wordlists() -> dict[str, object]:
        """Summarize registered local lists without opening or exposing their contents."""
        registry = default_registry_path()
        try:
            collections = load_collections(registry)
            entries = list_wordlists(collections)
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="Local wordlist registry is unavailable or malformed.") from exc
        category_counts: dict[str, int] = {}
        collection_counts: dict[str, int] = {}
        total_size = 0
        for item in entries:
            category_counts[item.category] = category_counts.get(item.category, 0) + 1
            collection_counts[item.collection] = collection_counts.get(item.collection, 0) + 1
            total_size += item.size_bytes
        return {
            "registry_present": registry.is_file(),
            "collections": [
                {
                    "name": collection.name,
                    "category": collection.category,
                    "lists": collection_counts.get(collection.name, 0),
                }
                for collection in collections[:100]
            ],
            "wordlist_count": len(entries),
            "total_size_bytes": total_size,
            "counts_by_category": dict(sorted(category_counts.items())),
            "sample": [
                {
                    "collection": item.collection,
                    "name": item.path.name,
                    "category": item.category,
                    "size_bytes": item.size_bytes,
                }
                for item in entries[:100]
            ],
            "contents_read": False,
            "network_requests_sent": 0,
        }

    @app.get("/api/discovery")
    async def discovery() -> dict[str, object]:
        """Return the latest bounded ffuf summary without exposing raw output paths."""
        directory = paths.evidence_dir / "fuzzing"
        candidates = sorted(
            (path for path in directory.glob("*-ffuf.json") if path.is_file() and not path.is_symlink()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )[:100]
        for path in candidates:
            try:
                data = _read_json_file(path)
            except (OSError, HTTPException):
                continue
            if not isinstance(data, dict) or data.get("type") != "ffuf":
                continue
            results = data.get("results")
            safe_results: list[dict[str, object]] = []
            counts: dict[str, int] = {}
            if isinstance(results, list):
                for result in results[:500]:
                    if not isinstance(result, dict):
                        continue
                    classification = result.get("classification")
                    if isinstance(classification, str) and classification in _DISCOVERY_CLASSIFICATIONS:
                        counts[classification] = counts.get(classification, 0) + 1
                    else:
                        classification = "inconclusive"
                    url = result.get("url")
                    status = result.get("status")
                    endpoint = _dashboard_route_template(url) if isinstance(url, str) else None
                    safe_results.append(
                        {
                            "endpoint": endpoint,
                            "status": status if type(status) is int else None,
                            "classification": classification,
                            "response_group": result.get("response_group")
                            if isinstance(result.get("response_group"), str)
                            else None,
                        }
                    )
            followups = data.get("followup_candidates")
            safe_followups = []
            if isinstance(followups, list):
                for item in followups[:100]:
                    if not isinstance(item, dict) or not isinstance(item.get("route_template"), str):
                        continue
                    route_template = _dashboard_route_template(item["route_template"])
                    if route_template is None or not route_template.startswith("/"):
                        continue
                    safe_followups.append(
                        {
                            "route_template": route_template,
                            "classification": "candidate_for_authorization_review",
                            "resource_privacy": "unknown",
                            "vulnerability_confirmed": False,
                        }
                    )
            limits = data.get("limits")
            safe_limits = {
                key: limits.get(key)
                for key in (
                    "max_entries",
                    "max_seconds",
                    "rate_per_second",
                    "concurrency",
                    "planned_requests_upper_bound",
                    "ffuf_requests_observed",
                )
                if isinstance(limits, dict) and key in limits
            }
            return {
                "latest": {
                    "status": "stopped_rate_limited_baseline"
                    if data.get("status") == "stopped_rate_limited_baseline"
                    else "completed",
                    "limits": safe_limits,
                },
                "result_count": len(results) if isinstance(results, list) else 0,
                "counts_by_classification": dict(sorted(counts.items())),
                "results": safe_results,
                "authorization_followups": safe_followups,
                "notice": "Discovery signals only; HTTP status does not confirm an endpoint or vulnerability.",
            }
        return {
            "latest": None,
            "result_count": 0,
            "counts_by_classification": {},
            "results": [],
            "authorization_followups": [],
            "notice": "No saved ffuf discovery evidence.",
        }

    @app.get("/api/access-matrix")
    async def access_matrix() -> dict[str, object]:
        """Expose predicate-only access matrix summaries, never IDs, markers or bodies."""
        directory = paths.evidence_dir / "access-control"
        candidates = sorted(
            (path for path in directory.glob("*.json") if path.is_file() and not path.is_symlink()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )[:100]
        for path in candidates:
            try:
                data = _read_json_file(path)
            except (OSError, HTTPException):
                continue
            if not isinstance(data, dict) or data.get("type") != "access-control":
                continue
            matrix = data.get("matrix")
            safe_matrix = []
            if isinstance(matrix, list):
                for cell in matrix[:500]:
                    if not isinstance(cell, dict):
                        continue
                    access_type = cell.get("access_type")
                    classification = cell.get("classification")
                    safe_matrix.append(
                        {
                            "session_account": _safe_label(cell.get("session_account")),
                            "resource_owner": _safe_label(cell.get("resource_owner")),
                            "access_type": access_type
                            if isinstance(access_type, str) and access_type in {"control", "cross"}
                            else "unknown",
                            "classification": classification
                            if isinstance(classification, str) and classification in _ACCESS_CLASSIFICATIONS
                            else "inconclusive",
                            "private_resource_match": cell.get("private_resource_match") is True,
                            "confirmed": False,
                        }
                    )
            steps = data.get("steps")
            safe_steps = []
            if isinstance(steps, list):
                for step in steps[:100]:
                    if not isinstance(step, dict):
                        continue
                    safe_steps.append(
                        {
                            "step": _safe_label(step.get("step")),
                            "application_success": step.get("application_success")
                            if type(step.get("application_success")) is bool
                            else None,
                            "resource_match": step.get("resource_match")
                            if type(step.get("resource_match")) is bool
                            else None,
                            "private_match": step.get("private_match")
                            if type(step.get("private_match")) is bool
                            else None,
                            "owner_resource_match": step.get("owner_resource_match")
                            if type(step.get("owner_resource_match")) is bool
                            else None,
                            "owner_private_match": step.get("owner_private_match")
                            if type(step.get("owner_private_match")) is bool
                            else None,
                        }
                    )
            mode = data.get("mode")
            classification = data.get("classification")
            stop_reason = data.get("stop_reason")
            return {
                "mode": mode
                if isinstance(mode, str)
                and mode in {"read", "account-matrix", "write", "write-range", "function-matrix"}
                else "unknown",
                "classification": classification
                if isinstance(classification, str) and classification in _ACCESS_CLASSIFICATIONS
                else "insufficient_evidence",
                "controls_valid": data.get("controls_valid") is True,
                "matrix_accounts": [_safe_label(value) for value in data.get("matrix_accounts", [])[:100]]
                if isinstance(data.get("matrix_accounts"), list)
                else [],
                "matrix": safe_matrix,
                "steps": safe_steps,
                "stop_reason": stop_reason
                if isinstance(stop_reason, str)
                and stop_reason
                in {
                    "private_evidence_observed",
                    "cross_read_rejected",
                    "cross_matrix_rejected",
                    "public_endpoint",
                    "cross_read_not_proven",
                    "partial_private_evidence",
                    "rate_limited",
                    "truncated_response",
                    "redirect_not_followed",
                    "transport_error",
                    "invalid_owner_control",
                    "invalid_actor_control",
                }
                else None,
                "confirmed": False,
                "network_requests_sent": 0,
            }
        return {
            "latest": None,
            "mode": None,
            "classification": "insufficient_evidence",
            "matrix": [],
            "steps": [],
            "confirmed": False,
        }

    @app.get("/api/reports")
    async def list_reports() -> dict[str, object]:
        if not paths.reports_dir.is_dir():
            return {"reports": []}
        reports = [
            {"name": path.name, "format": path.suffix.lower().lstrip(".")}
            for path in sorted(paths.reports_dir.iterdir(), key=lambda item: item.name.casefold())
            if path.is_file()
            and not path.is_symlink()
            and path.suffix.lower() in _REPORT_SUFFIXES
            and _REPORT_NAME_RE.fullmatch(path.name)
        ]
        return {"reports": reports[:500]}

    @app.get("/api/reports/{name}/content", response_class=PlainTextResponse)
    async def report_content(name: str) -> PlainTextResponse:
        path = _contained_report_path(paths, name)
        if path.stat().st_size > _MAX_REPORT_BYTES:
            raise HTTPException(status_code=413, detail="Report exceeds the dashboard read limit.")
        if path.suffix.lower() == ".pdf":
            raise HTTPException(status_code=415, detail="PDF reports can be downloaded but not rendered as text.")
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=422, detail="Report is not readable UTF-8 text.") from exc
        return PlainTextResponse(content)

    @app.get("/api/reports/{name}")
    async def download_report(name: str) -> FileResponse:
        path = _contained_report_path(paths, name)
        return FileResponse(path, filename=path.name, media_type="application/octet-stream")

    @app.get("/api/triage")
    async def triage(
        category: str | None = None, state: str | None = None, evidence: str | None = None
    ) -> dict[str, object]:
        try:
            return build_triage(paths, category=category, state=state, evidence=evidence)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/triage/candidates/{candidate_id}")
    async def triage_candidate(candidate_id: str) -> dict[str, object]:
        try:
            result = candidate_detail(paths, candidate_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if result is None:
            raise HTTPException(status_code=404, detail="Candidate not found.")
        return result

    @app.get("/api/triage/ai-reviews")
    async def triage_ai_reviews() -> dict[str, object]:
        return ai_review_differences(paths)

    @app.get("/api/triage/runs")
    async def triage_runs() -> dict[str, object]:
        progress: dict[str, object] = {"runs_total": 0, "technical_errors": 0, "by_command": {}}
        if paths.db_path.is_file():
            store = RecordStore(paths)
            try:
                rows = list(
                    store.connection.execute("select command_name, return_code from runs order by id desc limit 1000")
                )
            finally:
                store.close()
            by_command: dict[str, dict[str, int]] = {}
            for row in rows:
                name = _safe_label(row["command_name"]) or "unknown"
                bucket = by_command.setdefault(name[:60], {"runs": 0, "errors": 0, "unfinished": 0})
                bucket["runs"] += 1
                if row["return_code"] is None:
                    bucket["unfinished"] += 1
                elif row["return_code"] != 0:
                    bucket["errors"] += 1
            progress = {
                "runs_total": len(rows),
                "technical_errors": sum(b["errors"] for b in by_command.values()),
                "unfinished": sum(b["unfinished"] for b in by_command.values()),
                "by_command": by_command,
            }
        return {"progress": progress, "comparison": compare_prioritization_runs(paths)}

    @app.get("/api/triage/security-research")
    async def triage_security_research(
        category: str | None = None,
        family: str | None = None,
    ) -> dict[str, object]:
        """Unified read-only IDOR/XSS/disclosure triage; AI cannot approve."""
        try:
            return build_unified_security_triage(paths, category=category, family=family)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/triage/review-queue")
    async def triage_review_queue() -> dict[str, object]:
        reports = (await list_reports())["reports"]
        names = [str(item["name"]) for item in reports if isinstance(item, dict)] if isinstance(reports, list) else []
        return review_queue_reports(paths, names)

    @app.post("/api/evidence/import")
    async def import_artifact(request: Request, filename: str) -> dict[str, object]:
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/octet-stream":
            raise HTTPException(status_code=415, detail="Evidence uploads require application/octet-stream.")
        origin = request.headers.get("origin")
        if origin:
            try:
                parsed_origin = urlsplit(origin)
            except ValueError as exc:
                raise HTTPException(status_code=403, detail="Upload Origin must be local.") from exc
            if parsed_origin.scheme not in {"http", "https"} or not _host_is_local(parsed_origin.netloc):
                raise HTTPException(status_code=403, detail="Upload Origin must be local.")
        if not _UPLOAD_NAME_RE.fullmatch(filename) or Path(filename).name != filename:
            raise HTTPException(status_code=400, detail="Filename must be a plain safe artifact name.")
        suffix = Path(filename).suffix.lower()
        if suffix not in _UPLOAD_SUFFIXES:
            raise HTTPException(status_code=415, detail="Unsupported evidence file extension.")
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > MAX_INPUT_BYTES:
            raise HTTPException(status_code=413, detail="Evidence upload exceeds the 32 MiB limit.")
        with tempfile.TemporaryDirectory(prefix="bbtk-dashboard-") as temporary:
            artifact_path = Path(temporary) / f"upload{suffix}"
            total = 0
            try:
                with artifact_path.open("xb") as artifact:
                    async for chunk in request.stream():
                        total += len(chunk)
                        if total > MAX_INPUT_BYTES:
                            raise HTTPException(status_code=413, detail="Evidence upload exceeds the 32 MiB limit.")
                        artifact.write(chunk)
                if total == 0:
                    raise HTTPException(status_code=400, detail="Evidence upload is empty.")
                bundle = import_evidence([artifact_path])
            except HTTPException:
                raise
            except (OSError, ValueError) as exc:
                raise HTTPException(
                    status_code=422, detail="Evidence import failed; inspect the local input format."
                ) from exc
        inputs = bundle.get("inputs")
        if isinstance(inputs, list):
            for item in inputs:
                if isinstance(item, dict):
                    item["source_path"] = filename
        destination_dir = paths.evidence_dir / "imports"
        bundle_path = write_evidence_json(destination_dir, bundle, prefix="dashboard-import")
        store = RecordStore(paths)
        try:
            graph_result = EvidenceGraphStore(store).ingest(bundle_path)
        except (ValueError, RuntimeError) as exc:
            graph_result = {"status": "error", "detail": str(exc)}
        finally:
            store.close()
        summary = bundle.get("summary", {})
        return {
            "bundle_id": bundle.get("bundle_id"),
            "summary": summary,
            "bundle_path": bundle_path.relative_to(paths.program_dir).as_posix(),
            "graph_ingestion": graph_result,
            "network_requests_sent": 0,
            "ollama_calls": 0,
            "active_checks_executed": False,
        }

    return app
