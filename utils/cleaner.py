"""Normalization and extraction helpers."""

from __future__ import annotations

import re
from typing import Iterable, Set

EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
BLOCKED_EMAIL_PREFIXES = {"example", "test", "testing", "sample", "demo", "noreply"}


def normalize_subdomains(subdomains: Iterable[str], domain: str) -> Set[str]:
    cleaned: Set[str] = set()
    for item in subdomains:
        value = item.strip().lower().lstrip("*.").rstrip(".")
        if not value or value == domain:
            continue
        if value.endswith(domain):
            cleaned.add(value)
    return cleaned


def extract_emails(text: str, domain: str) -> Set[str]:
    emails = set()
    for match in EMAIL_RE.findall(text):
        email = match.lower().strip()
        if email.endswith(f"@{domain}"):
            emails.add(email)
    return emails


def clean_emails(emails: Iterable[str], domain: str) -> Set[str]:
    cleaned: Set[str] = set()
    for email in emails:
        candidate = email.lower().strip()
        if "@" not in candidate:
            continue
        local_part, _, email_domain = candidate.partition("@")
        if email_domain != domain:
            continue
        if local_part in BLOCKED_EMAIL_PREFIXES:
            continue
        cleaned.add(candidate)
    return cleaned
