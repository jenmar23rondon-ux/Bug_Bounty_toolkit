"""Evaluation harness: deterministic engine vs local single models vs dual review (both orders).

All model traffic goes through the existing ``AIProvider`` adapters (``review_evidence_multi``
for single reviews, ``dual_review`` for analyst/critic review). Nothing here adds a backend,
enables tools, executes model output, writes to the Evidence Ledger or confirms a finding.

Mock mode uses ``MockLocalAIServer`` with two *simulated* profiles fixed a priori from the
bundle predicate contract (not from labels). Their scores measure the harness, never a real
Qwen or DeepSeek model, and mock latency is not model latency.
"""

from __future__ import annotations

import json
import math
import shutil
import statistics
import subprocess
import tracemalloc
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from time import perf_counter
from typing import Any

from bugbounty_toolkit import ai_mock_server as mocks
from bugbounty_toolkit.analysis.ai_backend import AISelection
from bugbounty_toolkit.analysis.ai_providers import (
    PROVIDER_REGISTRY,
    AIProviderError,
    GenerationLimits,
    _request_json,
    normalize_model_identity,
    resolve_provider,
)
from bugbounty_toolkit.analysis.dual_review import dual_review
from bugbounty_toolkit.analysis.multi_review import build_evidence_bundle, review_evidence_multi

from . import corpus

RESULT_SCHEMA = "bbtk.local-llm-quality-result.v1"
CONTROL_KEYWORDS: dict[str, tuple[str, ...]] = {
    "ownership": ("owner", "ownership", "belongs", "shared"),
    "negative_control": ("negative", "baseline", "unauthori", "denial", "control"),
    "second_session": ("second session", "another session", "second account", "other user", "actor", "cross read"),
    "execution_proof": ("execut", "browser", "dom", "script ran"),
    "exploitability": ("exploit", "differential", "boolean", "time-based", "credential"),
    "complete_response": ("truncat", "complete response", "full response", "untruncated"),
    "valid_evidence": ("valid", "integrity", "corrupt", "transport", "missing response", "status"),
}


def controls_matched(texts: list[str]) -> set[str]:
    """Map free-text missing-control suggestions onto the fixed control vocabulary."""
    found: set[str] = set()
    for text in texts:
        low = text.lower().replace("_", " ")
        for control, keys in CONTROL_KEYWORDS.items():
            if any(key in low for key in keys):
                found.add(control)
    return found


# --------------------------------------------------------------------------- engine A
def deterministic_engine(data: dict[str, Any]) -> dict[str, Any]:
    """Configuration A: the existing faithful predicate reference over the minimized bundle (no model)."""
    bundle = build_evidence_bundle(data)
    content = mocks.rule_based(bundle)["content"]
    return {
        "decision": content["decision"],
        "status": "valid",
        "missing_controls": list(content["missing_controls"]),
        "contradiction_detected": False,
        "invented_refs": 0,
        "duration_ms": 0.0,
        "prompt_chars": 0,
        "model_calls": 0,
    }


# --------------------------------------------------------------------------- simulated profiles
def _obs(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = bundle.get("observations", [])
    return {str(row["field"]): row for row in rows if isinstance(row, dict) and "field" in row}


def _cautious_decision(bundle: dict[str, Any]) -> tuple[str, list[str], list[str]]:
    o = _obs(bundle)
    base = mocks.rule_based(bundle)["content"]
    flags = [o[k] for k in ("truncated_rows", "transport_error_rows") if k in o and o[k]["value"]]
    stop = o.get("stop_reason", {}).get("value")
    if flags or stop not in (None, "cross_read_rejected"):
        return "inconclusive", [], [str(flags[0]["ref"]) if flags else str(o["stop_reason"]["ref"])]
    return (
        str(base["decision"]),
        [str(i["ref"]) for i in base["evidence_for"]],
        [str(i["ref"]) for i in base["evidence_against"]],
    )


def _eager_decision(bundle: dict[str, Any]) -> tuple[str, list[str], list[str]]:
    o = _obs(bundle)
    if o.get("topic", {}).get("value") == "cors" or bundle.get("topic") == "cors":
        return "candidate", ["E99"], []  # invents a reference: must be rejected by the validator
    ok = o.get("status_codes.200")
    if ok is not None:
        return "candidate", [str(ok["ref"])], []
    first = next(iter(o.values()), None)
    return "not_observed", [], [str(first["ref"])] if first else []


Profile = Callable[[dict[str, Any]], tuple[str, list[str], list[str]]]
PROFILES: dict[str, tuple[Profile, list[str]]] = {
    "cautious-sim": (_cautious_decision, ["ownership control", "negative control baseline"]),
    "eager-sim": (_eager_decision, []),
}


def single_behavior(name: str) -> mocks.Behavior:
    decide, controls = PROFILES[name]

    def behavior(bundle: dict[str, Any]) -> mocks.Reply:
        decision, cite_for, cite_against = decide(bundle)
        return {"content": mocks.assessment(decision, cite_for, cite_against, missing_controls=list(controls))}

    return behavior


def analyst_behavior(name: str) -> mocks.Behavior:
    decide, controls = PROFILES[name]

    def behavior(bundle: dict[str, Any]) -> mocks.Reply:
        decision, cite_for, cite_against = decide(bundle)
        claims = [{"statement": f"Supports {decision}.", "kind": "evidence", "refs": cite_for or cite_against}]
        return {"content": {"decision": decision, "claims": claims, "missing_controls": list(controls)}}

    return behavior


def critic_behavior(name: str) -> mocks.Behavior:
    decide, controls = PROFILES[name]

    def behavior(review: dict[str, Any]) -> mocks.Reply:
        inner = review.get("bundle", {})
        decision, cite_for, cite_against = decide(inner if isinstance(inner, dict) else {})
        claims = [c for c in review.get("analyst_claims_untrusted", []) if isinstance(c, dict)]
        contradictions = [
            {"claim": int(c["index"]), "refs": cite_against[:1], "note": "Observation disagrees."}
            for c in claims
            if isinstance(c.get("statement"), str) and not c["statement"].endswith(f"{decision}.")
        ]
        unsupported = [int(c["index"]) for c in claims if c.get("kind") == "evidence" and not c.get("refs")]
        return {
            "content": {
                "decision": decision,
                "contradictions": contradictions[:8],
                "unsupported_claims": unsupported,
                "missing_controls": list(controls),
            }
        }

    return behavior


# --------------------------------------------------------------------------- runners
@dataclass(frozen=True)
class Reviewer:
    label: str
    selection: AISelection


def run_single(data: dict[str, Any], reviewer: Reviewer, limits: GenerationLimits) -> dict[str, Any]:
    sel = reviewer.selection
    result = review_evidence_multi(data, [(sel.build(), sel.model)], limits)
    status = result["validation_status"]
    telemetry = result["telemetry"]
    return {
        "decision": result["decision"],
        "status": "error" if result["status"] == "unavailable" else status,
        "error_code": telemetry["error_code"],
        "missing_controls": list(result["missing_controls"]),
        "contradiction_detected": status == "valid"
        and result["decision"] != "candidate"
        and bool(result["evidence_against"])
        and bool(result["evidence_for"]),
        "invented_refs": int(status == "invalid_reference"),
        "duration_ms": float(telemetry["duration_ms"]),
        "prompt_chars": int(telemetry["prompt_chars"]),
        "response_bytes": int(telemetry["response_bytes"]),
        "reported_model": telemetry["reported_model"],
        "model_calls": 1,
        "finding_confirmed": bool(result["finding_confirmed"]),
    }


def consensus_decision(result: dict[str, Any]) -> str:
    """Evaluation-only rule: keep the shared decision only if both valid, agree and nothing is flagged."""
    comp = result["comparison"]
    clean = not (comp["contradicted_claims"] or comp["unsupported_evidence_claims"] or result["invented_citations"])
    if comp["both_reviews_valid"] and comp["decision_agreement"] and clean:
        return str(comp["decisions"]["analyst"])
    return "inconclusive"


def run_dual(data: dict[str, Any], analyst: Reviewer, critic: Reviewer) -> dict[str, Any]:
    result = dual_review(data, analyst.selection, critic.selection)
    comp = result["comparison"]
    roles = (result["analyst"], result["critic"])
    errors = [r["telemetry"]["errors"] for r in roles if r["status"] == "unavailable"]
    rejected = [r for r in roles if r["status"] == "rejected"]
    return {
        "decision": comp["advisory_decision"],
        "consensus_decision": consensus_decision(result),
        "analyst_decision": comp["decisions"]["analyst"],
        "critic_decision": comp["decisions"]["critic"],
        "status": "error" if errors else "rejected" if rejected else "valid",
        "error_code": ",".join(sorted({k for e in errors for k in e})) or None,
        "missing_controls": list(comp["missing_controls_union"]),
        "contradiction_detected": bool(comp["contradicted_claims"]),
        "invented_refs": int(result["invented_citations"]),
        "unsupported_claims": len(comp["unsupported_evidence_claims"]),
        "duration_ms": float(sum(float(r["telemetry"]["duration_ms_total"]) for r in roles)),
        "prompt_chars": 0,
        "model_calls": int(sum(int(r["telemetry"]["calls"]) for r in roles)),
        "independent_models": bool(result["independence"]["independent_models"]),
        "finding_confirmed": bool(result["finding_confirmed"] or comp["finding_confirmed"]),
    }


# --------------------------------------------------------------------------- metrics
def wilson(successes: int, total: int) -> list[float] | None:
    if total < 5:
        return None
    z = 1.96
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, max(0, math.ceil(q * len(ordered)) - 1))], 3)


def quality(records: list[dict[str, Any]], labels: dict[str, dict[str, Any]], key: str = "decision") -> dict[str, Any]:
    tp = fp = fn = tn = abst = errors = rejected = 0
    correct = 0
    control_hits = control_total = 0
    contra_hit = contra_total = 0
    invented = 0
    unsupported_candidates = 0
    for rec in records:
        label = labels[rec["id"]]
        pred = rec[key]
        truth = label["expected_decision"]
        correct += pred == truth
        if rec["status"] == "error":
            errors += 1
        elif rec["status"] != "valid":
            rejected += 1
        if pred == "inconclusive":
            abst += 1
        if pred == "candidate":
            if truth == "candidate":
                tp += 1
            else:
                fp += 1
                unsupported_candidates += 1
        elif truth == "candidate":
            fn += 1
        else:
            tn += 1
        required = set(label["required_controls"])
        control_total += len(required)
        control_hits += len(required & controls_matched(rec["missing_controls"]))
        if label["contradiction_expected"]:
            contra_total += 1
            contra_hit += bool(rec["contradiction_detected"]) or pred == "inconclusive"
        invented += int(rec["invented_refs"])
    n = len(records)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision and recall else 0.0
    return {
        "runs": n,
        "accuracy": _ratio(correct, n),
        "accuracy_ci95": wilson(correct, n),
        "precision": precision,
        "precision_ci95": wilson(tp, tp + fp),
        "recall": recall,
        "recall_ci95": wilson(tp, tp + fn),
        "f1": f1,
        "false_positive_rate": _ratio(fp, fp + tn),
        "false_negative_rate": _ratio(fn, fn + tp),
        "abstention_rate": _ratio(abst, n),
        "valid_structured_output_rate": _ratio(n - errors - rejected, n),
        "rejected_outputs": rejected,
        "provider_errors": errors,
        "invented_citations": invented,
        "missing_control_recall": _ratio(control_hits, control_total),
        "contradictions_handled": f"{contra_hit}/{contra_total}",
        "candidates_without_support": unsupported_candidates,
        "automatic_confirmations": sum(1 for r in records if r.get("finding_confirmed")),
    }


def by_family(
    records: list[dict[str, Any]], labels: dict[str, dict[str, Any]], key: str = "decision"
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for fam in sorted({labels[r["id"]]["family"] for r in records}):
        rows = [r for r in records if labels[r["id"]]["family"] == fam]
        expected = labels[rows[0]["id"]]["expected_decision"]
        out[fam] = {
            "expected": expected,
            "correct": f"{sum(1 for r in rows if r[key] == expected)}/{len(rows)}",
            "predicted": dict(sorted(statistics_counter(r[key] for r in rows).items())),
            "held_out_family": labels[rows[0]["id"]]["held_out_family"],
        }
    return out


def statistics_counter(values: Iterator[str] | Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[str(value)] = counts.get(str(value), 0) + 1
    return counts


def stability(records: list[dict[str, Any]], key: str = "decision") -> float | None:
    groups: dict[str, set[str]] = {}
    for rec in records:
        groups.setdefault(rec["id"], set()).add(str(rec[key]))
    return _ratio(sum(1 for v in groups.values() if len(v) == 1), len(groups))


def performance(records: list[dict[str, Any]], live: bool) -> dict[str, Any]:
    durations = [float(r["duration_ms"]) for r in records if r.get("model_calls")]
    chars = sum(int(r.get("prompt_chars", 0)) for r in records)
    out_bytes = sum(int(r.get("response_bytes", 0)) for r in records)
    return {
        "latency_kind": "real_model_wall_clock" if live else "mock_latency_NOT_model_latency",
        "latency_ms_median": round(statistics.median(durations), 3) if durations else None,
        "latency_ms_p95": _pct(durations, 0.95),
        "model_calls": sum(int(r.get("model_calls", 0)) for r in records),
        "estimated_input_tokens": chars // 4 if chars else "not_measured",
        "estimated_output_tokens": out_bytes // 4 if out_bytes else "not_measured",
        "token_method": "chars/4 estimate, not tokenizer counts",
        "tokens_per_second": "not_measured",
        "timeouts": sum(1 for r in records if r.get("error_code") and "timeout" in str(r["error_code"])),
    }


def dual_delta(
    single: list[dict[str, Any]], dual: list[dict[str, Any]], labels: dict[str, dict[str, Any]], key: str
) -> dict[str, Any]:
    """Compare dual-review runs with the analyst's own single review on the same scenario and repeat."""
    base = {(r["id"], r["repeat"]): r for r in single}
    out = {"correct_agreements": 0, "incorrect_agreements": 0, "improved": 0, "worsened": 0}
    out.update({"disagreements": 0, "correctly_converted_to_inconclusive": 0})
    for rec in dual:
        truth = labels[rec["id"]]["expected_decision"]
        before = base[(rec["id"], rec["repeat"])]["decision"]
        after = rec[key]
        analyst, critic = rec["analyst_decision"], rec["critic_decision"]
        if analyst is not None and analyst == critic:
            out["correct_agreements" if analyst == truth else "incorrect_agreements"] += 1
        else:
            out["disagreements"] += 1
        out["correctly_converted_to_inconclusive"] += before != truth and after == "inconclusive" == truth
        out["improved"] += before != truth and after == truth
        out["worsened"] += before == truth and after != truth
    extra_calls = sum(r["model_calls"] for r in dual) - sum(r["model_calls"] for r in single)
    net = out["improved"] - out["worsened"]
    return {
        **out,
        "extra_model_calls": extra_calls,
        "extra_calls_per_net_improvement": round(extra_calls / net, 2) if net > 0 else None,
    }


# --------------------------------------------------------------------------- orchestration
def evaluate(
    split: str,
    first: Reviewer,
    second: Reviewer,
    single_first: Reviewer,
    single_second: Reviewer,
    repeats: int,
    limits: GenerationLimits,
    live: bool,
    critics: dict[str, AISelection] | None = None,
) -> dict[str, Any]:
    """Run A-E. ``critics`` maps a reviewer label to its critic-role selection (mock servers only)."""
    roles = critics or {}

    def critic(r: Reviewer) -> Reviewer:
        return Reviewer(r.label, roles.get(r.label, r.selection))

    if not 1 <= repeats <= 20:
        raise ValueError("repeats must be between 1 and 20")
    scenarios, labels = corpus.load(split)
    raw: dict[str, list[dict[str, Any]]] = {k: [] for k in ("A", "B", "C", "D", "E")}
    stage_ms: dict[str, float] = {}
    steps: tuple[tuple[str, Callable[[dict[str, Any]], dict[str, Any]]], ...] = (
        ("A", deterministic_engine),
        ("B", lambda d: run_single(d, single_first, limits)),
        ("C", lambda d: run_single(d, single_second, limits)),
        ("D", lambda d: run_dual(d, first, critic(second))),
        ("E", lambda d: run_dual(d, second, critic(first))),
    )
    for key, fn in steps:
        started = perf_counter()
        for repeat in range(1 if key == "A" else repeats):
            for sc in scenarios:
                raw[key].append({"id": sc["id"], "repeat": repeat, **fn(sc["data"])})
        stage_ms[key] = round((perf_counter() - started) * 1000, 3)
    names = {
        "A": "deterministic (no AI)",
        "B": first.label,
        "C": second.label,
        "D": f"dual {first.label} -> {second.label}",
        "E": f"dual {second.label} -> {first.label}",
    }
    configs: dict[str, Any] = {}
    for key, recs in raw.items():
        entry: dict[str, Any] = {
            "name": names[key],
            "quality": quality(recs, labels),
            "per_family": by_family(recs, labels),
            "decision_stability_across_repeats": stability(recs),
            "performance": performance(recs, live),
            "stage_wall_ms": stage_ms[key],
        }
        if key in {"D", "E"}:
            entry["quality_consensus_rule"] = quality(recs, labels, "consensus_decision")
            entry["dual_vs_analyst_single_production_rule"] = dual_delta(
                raw["B" if key == "D" else "C"], recs, labels, "decision"
            )
            entry["dual_vs_analyst_single_consensus_rule"] = dual_delta(
                raw["B" if key == "D" else "C"], recs, labels, "consensus_decision"
            )
            entry["independent_models"] = all(r["independent_models"] for r in recs)
        configs[key] = entry
    order = [r["consensus_decision"] for r in raw["D"]]
    reverse = [r["consensus_decision"] for r in raw["E"]]
    return {
        "configs": configs,
        "order_effect": {"scenario_runs_with_different_consensus": sum(a != b for a, b in zip(order, reverse))},
        "scenarios": len(scenarios),
        "held_out_families": sorted({v["family"] for v in labels.values() if v["held_out_family"]}),
    }


def _spec(provider: str, port: int) -> Any:
    return replace(PROVIDER_REGISTRY[provider], port=port, allowed_ports=(port,))


@contextmanager
def _servers(behaviors: dict[str, tuple[mocks.Behavior, str]]) -> Iterator[dict[str, mocks.MockLocalAIServer]]:
    started: dict[str, mocks.MockLocalAIServer] = {}
    try:
        for key, (behavior, model) in behaviors.items():
            started[key] = mocks.MockLocalAIServer(behavior, models=(model,)).__enter__()
        yield started
    finally:
        for server in started.values():
            server.__exit__(None, None, None)


def label_strings(split: str) -> list[str]:
    _, labels = corpus.load(split)
    out = {"expected_decision", "required_controls", "contradiction_expected", "label_source"}
    for row in labels.values():
        out.update({row["family"], row["spec"][:40]})
    return sorted(out)


def run_mock(split: str = "final", repeats: int = 2) -> dict[str, Any]:
    """CI path: every configuration over the frozen split via the real adapters against loopback mocks."""
    tracemalloc.start()
    q, d = "cautious-sim", "eager-sim"
    plan = {
        "q_single": (single_behavior(q), q),
        "d_single": (single_behavior(d), d),
        "q_analyst": (analyst_behavior(q), q),
        "d_analyst": (analyst_behavior(d), d),
        "q_critic": (critic_behavior(q), q),
        "d_critic": (critic_behavior(d), d),
    }
    with _servers(plan) as s:
        sel = {k: AISelection("ollama", plan[k][1], None, 10.0, _spec("ollama", v.port)) for k, v in s.items()}
        # Mock servers are role-specific because a canned behavior cannot see which schema was sent.
        result = _evaluate_mock(split, sel, repeats)
        requests = [req for server in s.values() for req in server.requests]
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    result.update(_privacy(requests, split))
    result.update(
        {
            "schema_version": RESULT_SCHEMA,
            "mode": "mock",
            "split": split,
            "repeats": repeats,
            "notice": "SIMULATED profiles (cautious-sim, eager-sim). These are NOT Qwen or DeepSeek scores.",
            "models": {"B": {"model": q, "simulated": True}, "C": {"model": d, "simulated": True}},
            "harness_python_peak_bytes": peak,
            "vram": "not_measured",
            "corpus_manifest": (corpus.CORPUS_DIR / corpus.MANIFEST).read_text(encoding="utf-8").splitlines(),
        }
    )
    return result


def _evaluate_mock(split: str, sel: dict[str, AISelection], repeats: int) -> dict[str, Any]:
    limits = GenerationLimits(timeout=10.0, max_output_tokens=768)
    q, d = "cautious-sim", "eager-sim"
    return evaluate(
        split,
        Reviewer(q, sel["q_analyst"]),
        Reviewer(d, sel["d_analyst"]),
        Reviewer(q, sel["q_single"]),
        Reviewer(d, sel["d_single"]),
        repeats,
        limits,
        live=False,
        critics={q: sel["q_critic"], d: sel["d_critic"]},
    )


def _privacy(requests: list[dict[str, Any]], split: str) -> dict[str, Any]:
    raws = [bytes(req.get("raw", b"")).decode("utf-8", "replace") for req in requests]
    hosts = {str(req["headers"].get("Host", "")) for req in requests}
    leaks = label_strings(split)
    return {
        "privacy": {
            "requests_observed": len(requests),
            "secrets_or_canaries_sent": sum(1 for raw in raws for c in corpus.CANARIES if c in raw),
            "prompt_injection_text_sent": sum(1 for raw in raws if "SYSTEM OVERRIDE" in raw),
            "ground_truth_strings_in_prompts": sum(1 for raw in raws for s in leaks if s in raw),
            "unauthorized_destinations": sum(1 for h in hosts if not h.startswith("127.0.0.1:")),
            "payloads_with_tools": sum(1 for req in requests if "tools" in req.get("body", {})),
            "tool_calls_accepted": 0,
            "commands_executed": 0,
        }
    }


# --------------------------------------------------------------------------- live (opt-in, user hardware)
def model_metadata(provider: str, model: str) -> dict[str, Any]:
    """Read-only model listing through the existing allowlisted transport; never pulls a model."""
    spec = resolve_provider(provider)
    meta: dict[str, Any] = {"provider": provider, "model": model, "identity": normalize_model_identity(model)}
    try:
        payload, _ = _request_json(spec, "GET", spec.models_path, None, 10.0, 1_048_576)
    except AIProviderError as exc:
        return {**meta, "present": False, "error_code": exc.code}
    if provider == "ollama":
        rows = [r for r in payload.get("models", []) if isinstance(r, dict) and r.get("name") == model]
        if not rows:
            return {**meta, "present": False}
        raw_details = rows[0].get("details")
        details: dict[str, Any] = raw_details if isinstance(raw_details, dict) else {}
        return {
            **meta,
            "present": True,
            "digest": rows[0].get("digest", "not_exposed"),
            "size_bytes": rows[0].get("size", "not_exposed"),
            "quantization": details.get("quantization_level", "not_exposed"),
            "parameter_size": details.get("parameter_size", "not_exposed"),
            "family": details.get("family", "not_exposed"),
            "format": details.get("format", "not_exposed"),
            "context_length": "provider_default (num_ctx not overridden)",
            "backend_version": "not_exposed_via_allowlisted_paths",
        }
    ids = [r.get("id") for r in payload.get("data", []) if isinstance(r, dict)]
    present = model in ids
    return {
        **meta,
        "present": present,
        "digest": "not_exposed",
        "quantization": "not_exposed (read it from the LM Studio UI)",
        "context_length": "server_setting",
        "backend_version": "not_exposed_via_allowlisted_paths",
    }


def vram_mb() -> int | str:
    exe = shutil.which("nvidia-smi")
    if exe is None:
        return "not_measured"
    try:
        out = subprocess.run(  # noqa: S603 - fixed local binary and args, opt-in live mode only
            [exe, "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout
        return int(out.strip().splitlines()[0])
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        return "not_measured"


def parse_reviewer(value: str) -> tuple[str, str]:
    provider, sep, model = value.partition("=")
    if not sep or provider not in PROVIDER_REGISTRY or not model:
        raise ValueError("reviewer must be provider=model with provider ollama or lmstudio")
    return provider, model


def run_live(qwen: str, deepseek: str, split: str, repeats: int, timeout: float) -> dict[str, Any]:
    """Opt-in run on the user's own machine. Refuses absent models; never downloads anything."""
    (qp, qm), (dp, dm) = parse_reviewer(qwen), parse_reviewer(deepseek)
    meta = {"B": model_metadata(qp, qm), "C": model_metadata(dp, dm)}
    missing = [m["model"] for m in meta.values() if not m.get("present")]
    if missing:
        raise RuntimeError(
            "Model(s) not installed or provider not running: " + ", ".join(missing) + ". Nothing was downloaded."
        )
    if (
        meta["B"]["identity"] == meta["C"]["identity"]
        or meta["B"].get("digest") not in (None, "not_exposed")
        and meta["B"].get("digest") == meta["C"].get("digest")
    ):
        raise RuntimeError("Both reviewers resolve to the same model; they are not independent reviewers.")
    limits = GenerationLimits(timeout=float(timeout), max_output_tokens=768)
    sq = AISelection(qp, qm, None, float(timeout)).validate()
    sd = AISelection(dp, dm, None, float(timeout)).validate()
    rq, rd = Reviewer(f"qwen:{qm}", sq), Reviewer(f"deepseek:{dm}", sd)
    tracemalloc.start()
    before = vram_mb()
    started = perf_counter()
    result = evaluate(split, rq, rd, rq, rd, repeats, limits, live=True)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    result.update(
        {
            "schema_version": RESULT_SCHEMA,
            "mode": "live",
            "split": split,
            "repeats": repeats,
            "models": meta,
            "generation_limits": limits.as_dict(),
            "vram_used_mb_before": before,
            "vram_used_mb_after": vram_mb(),
            "harness_python_peak_bytes": peak,
            "elapsed_seconds": round(perf_counter() - started, 3),
            "privacy": {
                "note": "Live mode cannot observe the wire; bundles are pre-scanned instead.",
                "secrets_or_canaries_in_bundles": prescan_bundles(split),
                "unauthorized_destinations": 0,
                "payloads_with_tools": 0,
            },
        }
    )
    return result


def prescan_bundles(split: str) -> int:
    scenarios, _ = corpus.load(split)
    texts = [json.dumps(build_evidence_bundle(sc["data"])["observations"]) for sc in scenarios]
    return sum(1 for t in texts for c in corpus.CANARIES if c in t)
