from __future__ import annotations

import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

# CVSS v3.x metric weights (FIRST.org CVSS 3.1 spec).
_CVSS3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS3_AC = {"L": 0.77, "H": 0.44}
_CVSS3_UI = {"N": 0.85, "R": 0.62}
_CVSS3_C = {"H": 0.56, "L": 0.22, "N": 0.0}
_CVSS3_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}


def normalize_name(name: str) -> str:
    """PEP 503 normalized name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def severity_rank(s: str) -> int:
    return SEVERITY_ORDER.get((s or "UNKNOWN").upper(), 0)


def max_severity(a: str, b: str) -> str:
    return a if severity_rank(a) >= severity_rank(b) else b


def _roundup_cvss(value: float) -> float:
    """CVSS 3.x roundup: smallest number, specified to 1 decimal, >= value."""
    return math.ceil(value * 10) / 10.0 if value > 0 else 0.0


def _as_number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def cvss_vector_base_score(vector: str) -> Optional[float]:
    """Compute CVSS 3.0/3.1 base score from a vector string, or None if unparseable."""
    if not isinstance(vector, str):
        return None
    text = vector.strip()
    if not text.upper().startswith("CVSS:3"):
        return None
    parts: dict[str, str] = {}
    for chunk in text.split("/"):
        if ":" not in chunk:
            continue
        key, _, val = chunk.partition(":")
        parts[key.upper()] = val.upper()
    try:
        scope = parts["S"]
        av = _CVSS3_AV[parts["AV"]]
        ac = _CVSS3_AC[parts["AC"]]
        pr = _CVSS3_PR[scope][parts["PR"]]
        ui = _CVSS3_UI[parts["UI"]]
        c = _CVSS3_C[parts["C"]]
        i = _CVSS3_C[parts["I"]]
        a = _CVSS3_C[parts["A"]]
    except KeyError:
        return None

    iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    base = impact + exploitability
    if scope != "U":
        base *= 1.08
    return _roundup_cvss(min(base, 10.0))


def _severity_from_label(text: str) -> str:
    upper = text.strip().upper()
    if upper in SEVERITY_ORDER:
        return upper
    if upper == "MODERATE":
        return "MEDIUM"
    return "UNKNOWN"


def _severity_from_text(text: str) -> str:
    labeled = _severity_from_label(text)
    if labeled != "UNKNOWN":
        return labeled
    vec = cvss_vector_base_score(text)
    return cvss_to_severity(vec) if vec is not None else "UNKNOWN"


def parse_severity(value: Any) -> str:
    if value is None:
        return "UNKNOWN"
    if isinstance(value, list):
        best = "UNKNOWN"
        for item in value:
            best = max_severity(best, parse_severity(item))
        return best
    if isinstance(value, dict):
        score = value.get("score")
        num = _as_number(score)
        if num is not None:
            return cvss_to_severity(num)
        if isinstance(score, str):
            from_score = _severity_from_text(score)
            if from_score != "UNKNOWN":
                return from_score
        if value.get("severity") is not None:
            return parse_severity(value.get("severity"))
        return "UNKNOWN"
    num = _as_number(value)
    if num is not None:
        return cvss_to_severity(num)
    return _severity_from_text(str(value).strip())


def extract_cvss_score(value: Any) -> Optional[float]:
    """Best numeric CVSS base score found in an OSV-style severity payload."""
    if value is None:
        return None
    if isinstance(value, list):
        best: Optional[float] = None
        for item in value:
            score = extract_cvss_score(item)
            if score is not None and (best is None or score > best):
                best = score
        return best
    if isinstance(value, dict):
        score = value.get("score")
        num = _as_number(score)
        if num is not None:
            return num
        return cvss_vector_base_score(score) if isinstance(score, str) else None
    num = _as_number(value)
    if num is not None:
        return num
    return cvss_vector_base_score(value) if isinstance(value, str) else None


def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def is_malware(*ids: str) -> bool:
    return any(i.upper().startswith("MAL-") for i in ids if i)


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def first_cve(ids: Iterable[str]) -> Optional[str]:
    for vid in ids:
        if vid.startswith("CVE-"):
            return vid
    return None
