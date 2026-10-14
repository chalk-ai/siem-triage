"""Enrich a raw signal into a record, ask the decision model about it, and explain the answer.

Features come from three places, the way they would in a real triage service:
- the identity and asset directories (static context),
- windowed counts over the signal stream itself (recent alerts per principal and per asset),
- analyst feedback on similar signals (rule + principal), which expires.

Contributions are counterfactual: each feature is removed from the record in turn, and the change
in P(malicious) is that feature's contribution. All variants run in one batched forward pass.
"""

from __future__ import annotations

import copy
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from signals import ASSETS, SOURCE_ALLOWLIST, USERS, Draft

QUESTIONS: dict[str, dict[str, Any]] = {
    "disposition": {
        "type": "choice",
        "instructions": "How should this security alert be dispositioned?",
        "criteria": {
            "close_benign": "Expected, explainable activity; close without analyst time.",
            "monitor": "Not clearly malicious, but worth watching for recurrence.",
            "investigate": "Warrants an analyst opening an investigation.",
            "contain": "Contain the host or account immediately; do not wait for triage.",
        },
    },
    "true_positive": {
        "type": "noul",
        "instructions": "This alert reflects genuinely malicious or unauthorised activity.",
        "criteria": {
            "false": "Benign activity, a misconfiguration, or a known false positive.",
            "true": "The underlying behaviour is malicious or unauthorised.",
        },
    },
    "severity": {
        "type": "score",
        "instructions": "How severe is the potential impact if this alert is real?",
        "criteria": [
            "Negligible: no access to anything sensitive.",
            "Low: limited access, easily reversed.",
            "Moderate: access to internal systems or non-public data.",
            "High: access to production, secrets or customer data.",
            "Critical: active compromise of crown-jewel systems.",
        ],
    },
}

# Counterfactuals for the structured fields: (path, label, neutral value). A feature's
# contribution is P(malicious) with the real value minus P(malicious) with the neutral one.
FIELD_COUNTERFACTUALS: list[tuple[tuple[str, str], str, Any]] = [
    (("context", "asset_criticality"), "Asset criticality", "medium"),
    (("context", "source_on_allowlist"), "Source on allowlist", None),
    (("context", "change_window_active"), "Change window open", None),
    (("principal", "mfa_enrolled"), "MFA enrolled", None),
    (("principal", "privileges"), "Principal privileges", ["repo:read"]),
    (("history", "distinct_countries_30d"), "Countries in 30 days", 1),
    (("history", "prior_alerts_90d"), "Prior alerts, 90 days", 1),
    (("history", "credential_rotation_days_ago"), "Days since credential rotation", 30),
]

# Logistic calibration of P(malicious), fitted on the typed-decisions security-incident train
# split (300 cases, soft labels; log loss 0.590 -> 0.563, test-split Brier 0.0160 -> 0.0133).
# The raw model ranks well but compresses probabilities toward 0.5.
CALIBRATION_SCALE = 1.95
CALIBRATION_BIAS = -0.02


def calibrate(p: float) -> float:
    p = min(max(p, 1e-6), 1 - 1e-6)
    return 1 / (
        1 + math.exp(-(CALIBRATION_SCALE * math.log(p / (1 - p)) + CALIBRATION_BIAS))
    )


WINDOW_S = 3600.0
FEEDBACK_TTL_S = 15 * 60.0


@dataclass
class StreamState:
    """Windowed counters over the signal stream, plus analyst feedback with a TTL."""

    by_principal: dict[str, deque[float]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    by_asset: dict[str, deque[float]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    # (rule, principal) -> expiry times of "confirmed malicious" verdicts
    confirmed: dict[tuple[str, str], list[float]] = field(
        default_factory=lambda: defaultdict(list)
    )
    # source -> expiry time of an analyst-added allowlist entry
    allowlisted: dict[str, float] = field(default_factory=dict)

    def observe(self, draft: Draft, now: float) -> None:
        self.by_principal[draft.principal].append(now)
        self.by_asset[draft.asset].append(now)

    def recent(self, window: deque[float], now: float) -> int:
        while window and now - window[0] > WINDOW_S:
            window.popleft()
        return len(window)

    def confirm_malicious(self, rule: str, principal: str, now: float) -> None:
        entries = self.confirmed[(rule, principal)]
        entries.append(now + FEEDBACK_TTL_S)
        # Bound the influence any burst of clicks can have on one rule + principal.
        del entries[:-3]

    def allowlist_source(self, source: str, now: float) -> None:
        self.allowlisted[source] = now + FEEDBACK_TTL_S

    def confirmed_count(self, rule: str, principal: str, now: float) -> int:
        return sum(
            1 for expires in self.confirmed.get((rule, principal), []) if expires > now
        )

    def on_allowlist(self, source: str, now: float) -> tuple[bool, bool]:
        """(on the allowlist, added by an analyst rather than the static directory)."""
        if source in SOURCE_ALLOWLIST:
            return True, False
        expires = self.allowlisted.get(source)
        return (expires is not None and expires > now), True


def enrichment(draft: Draft, stream: StreamState, now: float) -> list[tuple[str, str]]:
    """Context the triage service knows and the detection rule does not, as (label, sentence)."""
    user = USERS[draft.principal]
    notes: list[tuple[str, str]] = []
    if user["travel_flag"]:
        notes.append(("Approved travel", user["travel_flag"]))
    if user["employment_status"]:
        notes.append(("HR status", user["employment_status"]))
    # The current signal is already observed, so subtract it: these count *other* alerts.
    same_principal = stream.recent(stream.by_principal[draft.principal], now) - 1
    if same_principal > 0:
        notes.append(
            (
                "Alerts on this principal, last hour",
                f"{same_principal} other alert{'s' if same_principal != 1 else ''} fired for "
                + f"{draft.principal} in the last hour.",
            )
        )
    same_asset = stream.recent(stream.by_asset[draft.asset], now) - 1
    if same_asset > 0:
        notes.append(
            (
                "Alerts on this asset, last hour",
                f"{same_asset} other alert{'s' if same_asset != 1 else ''} fired on {draft.asset} in the last hour.",
            )
        )
    confirmed = stream.confirmed_count(draft.rule, draft.principal, now)
    if confirmed:
        notes.append(
            (
                "Analyst-confirmed similar alerts",
                f"Analysts confirmed {confirmed} recent {draft.rule} alert{'s' if confirmed != 1 else ''} for "
                + f"{draft.principal} as malicious.",
            )
        )
    return notes


def _fact_sentences(record: dict[str, Any], source: str) -> list[str]:
    """Facts rendered from the record's fields, so flipping a field flips its sentence too."""
    ctx, principal = record["context"], record["principal"]
    facts = [
        f"Source {source} is on the allowlist."
        if ctx["source_on_allowlist"]
        else f"Source {source} is not a recognised address.",
        "A change window was open."
        if ctx["change_window_active"]
        else "No change window was active.",
    ]
    if principal["type"] not in ("service_account", "ci_runner"):
        facts.append(
            "The account authenticates with MFA."
            if principal["mfa_enrolled"]
            else "The account has no MFA."
        )
    return facts


def render_evidence(
    record: dict[str, Any], draft: Draft, notes: list[tuple[str, str]]
) -> dict[str, Any]:
    """Write the evidence text from the core detection plus facts and context notes."""
    out = copy.deepcopy(record)
    context = " ".join(
        _fact_sentences(out, draft.source) + [sentence for _, sentence in notes]
    )
    out["alert"]["evidence"] = f"{draft.evidence} {context}"
    return out


def build_record(
    draft: Draft, stream: StreamState, now: float, drop_note: str | None = None
) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    """The record in the decision model's security-incident schema, and its enrichment notes."""
    user = USERS[draft.principal]
    asset = ASSETS[draft.asset]
    notes = [n for n in enrichment(draft, stream, now) if n[0] != drop_note]
    record = {
        "alert": {
            "description": draft.description,
            "evidence": draft.evidence,
            "rule": draft.rule,
        },
        "context": {
            "asset_criticality": asset["criticality"],
            "change_window_active": draft.change_window_active,
            "source_on_allowlist": stream.on_allowlist(draft.source, now)[0],
        },
        "history": {
            "credential_rotation_days_ago": user["credential_rotation_days_ago"],
            "distinct_countries_30d": user["distinct_countries_30d"],
            "logins_30d": user["logins_30d"],
            "prior_alerts_90d": user["prior_alerts_90d"],
        },
        "principal": {
            "mfa_enrolled": user["mfa_enrolled"],
            "name": draft.principal,
            "privileges": user["privileges"],
            "type": user["type"],
        },
    }
    return render_evidence(record, draft, notes), notes


def _with(record: dict[str, Any], path: tuple[str, str], value: Any) -> dict[str, Any]:
    out = copy.deepcopy(record)
    out[path[0]][path[1]] = value
    return out


def summarize(answers: dict[str, Any]) -> dict[str, Any]:
    disp = answers["disposition"]
    sev = answers["severity"]
    return {
        "disposition": disp["choice"],
        "disposition_probs": {k: round(v, 4) for k, v in disp["probabilities"].items()},
        "p_malicious": round(calibrate(answers["true_positive"]["noul"]), 4),
        "severity": sev["score"],
        "severity_label": sev.get("legend", {}).get(str(sev["score"])),
        "severity_probs": {k: round(v, 4) for k, v in sev["probabilities"].items()},
    }


def triage(
    agent: Any, draft: Draft, stream: StreamState, now: float
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], float]:
    """Decision for one signal plus a contribution per feature, in one batched pass.

    Returns (record, decision, contributions, infer_ms).
    """
    record, notes = build_record(draft, stream, now)
    variants: list[tuple[str, str, Any, dict[str, Any]]] = []
    for path, label, neutral in FIELD_COUNTERFACTUALS:
        value = record[path[0]][path[1]]
        # Booleans have no neutral value: their counterfactual is the opposite fact.
        if neutral is None:
            neutral = not value
        if value != neutral:
            flipped = _with(record, path, neutral)
            variants.append(
                (".".join(path), label, value, render_evidence(flipped, draft, notes))
            )
    for label, sentence in notes:
        variants.append(
            (
                "context_note",
                label,
                sentence,
                build_record(draft, stream, now, drop_note=label)[0],
            )
        )
    t0 = time.perf_counter()
    results = agent.predict_batch([record] + [v[3] for v in variants], QUESTIONS)
    infer_ms = (time.perf_counter() - t0) * 1000
    decision = summarize(results[0]["answers"])
    base = decision["p_malicious"]
    contributions = [
        {
            "feature": feature,
            "label": label,
            "value": value,
            # Positive: this feature's real value pushed the model toward malicious.
            "delta": round(
                base - calibrate(res["answers"]["true_positive"]["noul"]), 4
            ),
        }
        for (feature, label, value, _), res in zip(variants, results[1:], strict=True)
    ]
    contributions.sort(key=lambda c: abs(c["delta"]), reverse=True)
    return record, decision, contributions, infer_ms
