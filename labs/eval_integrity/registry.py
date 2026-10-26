"""Registered frozen corpora, their builders and pinned manifest digests.

Historical pins were taken from origin/main 86c9a868 (those corpora must not change);
the e2e-contract pin was taken when that synthetic fixture was authored in this PR.
"""

from __future__ import annotations

from pathlib import Path

from labs.adversarial_idor_eval import build_corpus as adv10
from labs.adversarial_idor_eval import build_corpus_adv11 as adv11
from labs.eval_integrity import build_fixture as e2e
from labs.eval_integrity.corpus_integrity import CorpusSpec
from labs.object_ranking_eval.build_corpus import build_dev, build_eval

LABS = Path(__file__).resolve().parents[1]


def _rk_eval(out: Path) -> None:
    build_eval().write(out)


def _rk_dev(out: Path) -> None:
    build_dev().write(out)


def specs(base: Path = LABS) -> list[CorpusSpec]:
    return [
        CorpusSpec("adv-ranking-1.0", base / "object_ranking_eval" / "frozen", _rk_eval),
        CorpusSpec("adv-ranking-dev", base / "object_ranking_eval" / "dev", _rk_dev),
        CorpusSpec("adv-1.0", base / "adversarial_idor_eval" / "frozen", adv10.build),
        CorpusSpec("adv-1.1", base / "adversarial_idor_eval" / "frozen_adv11", adv11.build),
        CorpusSpec("e2e-contract-1.0", base / "eval_integrity" / "frozen_e2e", e2e.build),
    ]


PINS: dict[str, str] = {
    "adv-ranking-1.0": "b96d654643b056a74236cf0e63b2629b5dd9070ff53ed4311f298b4514901138",
    "adv-ranking-dev": "00e9193dd4f7bfc7acfc109e6f3bf94314be648c4de9f561ceed27ba3ff040c2",
    "adv-1.0": "80da22a92287cf9f838a5ccd088b2b9a30d2fb4328fbaddfc5a3cd868162a88a",
    "adv-1.1": "54f71ad1bbf7772d2147709b1016d0aca0646f647ed1428ed9b59ea6d3a89599",
    "e2e-contract-1.0": "9f0c7aa67b5b95bdb2f52330748f29a8b9c4ef764d626a51829313dcf79a6a54",
}

INDEPENDENT_PAIRS: tuple[tuple[str, str], ...] = (
    ("adv-ranking-1.0", "adv-ranking-dev"),
    ("adv-ranking-1.0", "adv-1.0"),
    ("adv-ranking-1.0", "adv-1.1"),
    ("adv-ranking-dev", "adv-1.0"),
    ("adv-ranking-dev", "adv-1.1"),
    ("adv-1.0", "adv-1.1"),
    ("e2e-contract-1.0", "adv-ranking-1.0"),
    ("e2e-contract-1.0", "adv-1.0"),
)
