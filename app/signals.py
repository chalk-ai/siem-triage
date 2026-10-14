"""Fictional SIEM signals for Halcyon Freight, plus the context a triage service joins onto them.

Every rule has risky and benign variants that differ only in context (who, which asset, whether
the source is allowlisted, whether a change window is open). The decision model has to read
that context to tell them apart; the rule name alone never decides it.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any

USERS: dict[str, dict[str, Any]] = {
    "m.okafor": {
        "type": "employee",
        "role": "Finance controller",
        "privileges": ["finance:ledger", "payments:approve"],
        "mfa_enrolled": True,
        "employment_status": None,
        "travel_flag": None,
        "home_country": "US",
        "logins_30d": 71,
        "distinct_countries_30d": 1,
        "prior_alerts_90d": 0,
        "credential_rotation_days_ago": 45,
    },
    "s.lindqvist": {
        "type": "employee",
        "role": "Sales director",
        "privileges": ["crm:export"],
        "mfa_enrolled": True,
        "employment_status": None,
        "travel_flag": "Travel to Stockholm and Singapore this week is approved in the travel system.",
        "home_country": "US",
        "logins_30d": 88,
        "distinct_countries_30d": 3,
        "prior_alerts_90d": 2,
        "credential_rotation_days_ago": 30,
    },
    "r.batra": {
        "type": "admin",
        "role": "Platform engineer",
        "privileges": ["prod:deploy", "iam:admin"],
        "mfa_enrolled": True,
        "employment_status": None,
        "travel_flag": None,
        "home_country": "US",
        "logins_30d": 140,
        "distinct_countries_30d": 1,
        "prior_alerts_90d": 1,
        "credential_rotation_days_ago": 20,
    },
    "d.mercer": {
        "type": "employee",
        "role": "Accounts payable analyst",
        "privileges": ["finance:share", "vendors:edit"],
        "mfa_enrolled": True,
        "employment_status": "HR records show this employee resigned and is serving a notice period ending Friday.",
        "travel_flag": None,
        "home_country": "US",
        "logins_30d": 54,
        "distinct_countries_30d": 1,
        "prior_alerts_90d": 0,
        "credential_rotation_days_ago": 60,
    },
    "k.huang": {
        "type": "admin",
        "role": "IT administrator",
        "privileges": ["iam:admin", "endpoints:manage"],
        "mfa_enrolled": True,
        "employment_status": None,
        "travel_flag": None,
        "home_country": "US",
        "logins_30d": 162,
        "distinct_countries_30d": 1,
        "prior_alerts_90d": 4,
        "credential_rotation_days_ago": 15,
    },
    "a.ferreira": {
        "type": "contractor",
        "role": "Dispatcher",
        "privileges": ["routing:edit"],
        "mfa_enrolled": False,
        "employment_status": None,
        "travel_flag": None,
        "home_country": "US",
        "logins_30d": 38,
        "distinct_countries_30d": 1,
        "prior_alerts_90d": 0,
        "credential_rotation_days_ago": 120,
    },
    "svc-backup": {
        "type": "service_account",
        "role": "Nightly backup job",
        "privileges": ["finance:share:read", "storage:write"],
        "mfa_enrolled": False,
        "employment_status": None,
        "travel_flag": None,
        "home_country": None,
        "logins_30d": 30,
        "distinct_countries_30d": 1,
        "prior_alerts_90d": 0,
        "credential_rotation_days_ago": 90,
    },
    "svc-ci-deployer": {
        "type": "ci_runner",
        "role": "CI deploy pipeline",
        "privileges": ["prod:deploy", "iam:keys:create"],
        "mfa_enrolled": False,
        "employment_status": None,
        "travel_flag": None,
        "home_country": None,
        "logins_30d": 410,
        "distinct_countries_30d": 1,
        "prior_alerts_90d": 1,
        "credential_rotation_days_ago": 7,
    },
}

ASSETS: dict[str, dict[str, Any]] = {
    "ledger-db-prod": {
        "criticality": "crown_jewel",
        "environment": "production",
        "owner": "finance-eng",
    },
    "fin-share-01": {
        "criticality": "high",
        "environment": "production",
        "owner": "finance",
    },
    "build-runner-07": {
        "criticality": "high",
        "environment": "ci",
        "owner": "platform",
    },
    "dispatch-web": {
        "criticality": "medium",
        "environment": "production",
        "owner": "ops",
    },
    "laptop-fin-114": {
        "criticality": "medium",
        "environment": "corporate",
        "owner": "m.okafor",
    },
    "laptop-ops-022": {
        "criticality": "low",
        "environment": "corporate",
        "owner": "a.ferreira",
    },
    "idp-tenant": {
        "criticality": "crown_jewel",
        "environment": "production",
        "owner": "it",
    },
    "crm-saas": {"criticality": "high", "environment": "saas", "owner": "sales"},
}

# Known infrastructure sources. Alerts from these still fire, but the triage record says so.
SOURCE_ALLOWLIST = {
    "10.40.0.15 (vuln-scanner-01)",
    "10.50.0.4 (backup-01)",
    "10.60.3.7 (build-runner-07)",
    "10.10.1.5 (it-admin-ws)",
    "10.20.0.31 (dispatch-web)",
    "10.0.0.8 (corp-vpn-gateway)",
}


@dataclass(frozen=True)
class Draft:
    """A raw signal before enrichment: what the detection rule emits."""

    rule: str
    title: str
    description: str
    evidence: str
    principal: str
    asset: str
    source: str
    change_window_active: bool
    source_reputation: str
    # What a careful analyst would conclude; used only to report agreement, never sent to the model.
    expected: str


DESCRIPTIONS = {
    "impossible_travel": "two successful logins from distant locations too close together",
    "privilege_escalation": "an account granted itself or received elevated permissions",
    "brute_force": "many failed authentications followed by a success",
    "mass_download": "an unusual volume of files read in a short window",
    "token_reuse": "a session token was presented from a second address",
    "data_egress": "a large transfer to an external destination",
    "suspicious_process": "an unrecognised binary executed on a server",
    "disabled_logging": "audit logging was turned off on a host",
    "dormant_account_use": "a long-unused account became active",
}

TITLES = {
    "impossible_travel": "Impossible travel",
    "privilege_escalation": "Privilege escalation",
    "brute_force": "Failed logins, then a success",
    "mass_download": "Bulk file reads",
    "token_reuse": "Session token reused",
    "data_egress": "Large outbound transfer",
    "suspicious_process": "Unrecognised binary on a server",
    "disabled_logging": "Audit logging disabled",
    "dormant_account_use": "Dormant account active",
}


def _d(
    rule: str,
    evidence: str,
    principal: str,
    asset: str,
    source: str,
    change_window: bool,
    expected: str,
) -> Draft:
    return Draft(
        rule=rule,
        title=TITLES[rule],
        description=DESCRIPTIONS[rule],
        evidence=evidence,
        principal=principal,
        asset=asset,
        source=source,
        change_window_active=change_window,
        source_reputation="allowlisted"
        if source in SOURCE_ALLOWLIST
        else "unrecognised",
        expected=expected,
    )


# Each pair: (risky, benign). The benign twin differs in context, not in the rule that fired.
# Evidence holds only what the detection saw; allowlist, change-window and MFA facts are rendered
# from features by the triage service, so a counterfactual can flip them consistently.
PAIRS: list[tuple[Draft, Draft]] = [
    (
        _d(
            "impossible_travel",
            "m.okafor signed in from Chicago, US at 08:02 UTC and from Bucharest, RO at 08:19 UTC. The "
            "second session disabled MFA, added a new payee and approved a $48,200 payment.",
            "m.okafor",
            "idp-tenant",
            "185.220.101.44 (hosting provider, RO)",
            False,
            "malicious",
        ),
        _d(
            "impossible_travel",
            "s.lindqvist signed in from Stockholm, SE at 07:40 UTC and from Singapore, SG at 19:05 UTC. "
            "Both sessions came through the corporate VPN and only opened the CRM; no data was exported.",
            "s.lindqvist",
            "crm-saas",
            "10.0.0.8 (corp-vpn-gateway)",
            False,
            "benign",
        ),
    ),
    (
        _d(
            "privilege_escalation",
            "At 02:47 UTC the contractor account a.ferreira added itself to the Org Admins group on the "
            "identity provider, then listed all users. No ticket references the change.",
            "a.ferreira",
            "idp-tenant",
            "98.51.7.200 (residential ISP)",
            False,
            "malicious",
        ),
        _d(
            "privilege_escalation",
            "Admin k.huang granted r.batra the Org Admins role for 4 hours, referencing approved change "
            "ticket CHG-2291.",
            "k.huang",
            "idp-tenant",
            "10.10.1.5 (it-admin-ws)",
            True,
            "benign",
        ),
    ),
    (
        _d(
            "brute_force",
            "Between 03:02 and 03:09 UTC, 46 failed logins for admin r.batra came from Lagos, NG, followed "
            "by a successful login after an MFA push was approved. The new session created an IAM access key.",
            "r.batra",
            "idp-tenant",
            "102.89.32.10 (mobile carrier, NG)",
            False,
            "malicious",
        ),
        _d(
            "brute_force",
            "Between 09:12 and 09:14 UTC, 6 failed logins for k.huang were followed by a successful login. "
            "The help desk notes a password reset at 09:10.",
            "k.huang",
            "idp-tenant",
            "10.10.1.5 (it-admin-ws)",
            True,
            "benign",
        ),
    ),
    (
        _d(
            "mass_download",
            "Between 23:40 and 00:15 UTC, d.mercer read 3,412 files (2.1 GB) on fin-share-01, including "
            "every vendor bank-details sheet, over a personal VPN.",
            "d.mercer",
            "fin-share-01",
            "73.12.40.9 (personal VPN)",
            False,
            "malicious",
        ),
        _d(
            "mass_download",
            "Between 01:00 and 01:42 UTC, the service account svc-backup read 41,880 files on fin-share-01 "
            "and wrote them to the backup vault, as the nightly backup does.",
            "svc-backup",
            "fin-share-01",
            "10.50.0.4 (backup-01)",
            True,
            "benign",
        ),
    ),
    (
        _d(
            "token_reuse",
            "A session token for admin r.batra, issued at 10:03 UTC, was presented again at 10:04 UTC from "
            "a second address in another country, which then called the secrets API 212 times.",
            "r.batra",
            "build-runner-07",
            "198.51.100.77 (hosting provider)",
            False,
            "malicious",
        ),
        _d(
            "token_reuse",
            "A session token for the CI runner svc-ci-deployer was presented from two runner addresses "
            "within one pipeline run, after the job migrated between runner hosts.",
            "svc-ci-deployer",
            "build-runner-07",
            "10.60.3.7 (build-runner-07)",
            True,
            "benign",
        ),
    ),
    (
        _d(
            "data_egress",
            "At 02:20 UTC, ledger-db-prod sent 38 GB over 40 minutes to external IP 45.143.200.12 using a "
            "renamed rclone binary.",
            "svc-backup",
            "ledger-db-prod",
            "45.143.200.12 (hosting provider)",
            False,
            "malicious",
        ),
        _d(
            "data_egress",
            "At 01:05 UTC, svc-backup sent 18 GB to the company's offsite backup bucket, which is on the "
            "outbound allowlist.",
            "svc-backup",
            "fin-share-01",
            "10.50.0.4 (backup-01)",
            True,
            "benign",
        ),
    ),
    (
        _d(
            "suspicious_process",
            "On build-runner-07 an unrecognised, unsigned binary in /tmp started at 03:31 UTC, opened a "
            "reverse shell, and read the deploy credentials.",
            "svc-ci-deployer",
            "build-runner-07",
            "185.100.87.3 (hosting provider)",
            False,
            "malicious",
        ),
        _d(
            "suspicious_process",
            "On dispatch-web a new binary from the signed release pipeline started as part of release 4.18.",
            "svc-ci-deployer",
            "dispatch-web",
            "10.60.3.7 (build-runner-07)",
            True,
            "benign",
        ),
    ),
    (
        _d(
            "disabled_logging",
            "At 02:58 UTC audit logging was turned off on ledger-db-prod by the contractor account "
            "a.ferreira, and 14 minutes of queries against the payments tables followed.",
            "a.ferreira",
            "ledger-db-prod",
            "98.51.7.200 (residential ISP)",
            False,
            "malicious",
        ),
        _d(
            "disabled_logging",
            "Admin k.huang paused audit logging on dispatch-web for 5 minutes to rotate the log agent, "
            "under ticket CHG-2304.",
            "k.huang",
            "dispatch-web",
            "10.10.1.5 (it-admin-ws)",
            True,
            "benign",
        ),
    ),
    (
        _d(
            "dormant_account_use",
            "The contractor account a.ferreira, inactive for 210 days, signed in and immediately "
            "enumerated the routing database.",
            "a.ferreira",
            "dispatch-web",
            "185.220.101.44 (hosting provider, RO)",
            False,
            "malicious",
        ),
        _d(
            "dormant_account_use",
            "The service account svc-backup, unused for 95 days, became active when the quarterly archive "
            "job ran.",
            "svc-backup",
            "fin-share-01",
            "10.50.0.4 (backup-01)",
            True,
            "benign",
        ),
    ),
]


def draw(rng: random.Random) -> Draft:
    """One raw signal. Real SIEM queues are mostly noise, so about two in three are benign."""
    risky, benign = rng.choice(PAIRS)
    return risky if rng.random() < 0.35 else benign
