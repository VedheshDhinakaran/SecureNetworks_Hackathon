"""Paths and catalog loading."""
from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
PCAPS = DATA / "pcaps"
OUT = ROOT / "out"
RULES_DIR = ROOT / "rules"
ZEEK_DIR = ROOT / "zeek"
PLAYBOOKS = ROOT / "playbooks"
CATALOG_FILE = ROOT / "detections" / "catalog.yml"
LAB_CONF = ROOT / "lab" / "victim" / "conf"
MANIFEST = DATA / "manifest.json"

CLASSES = ["web_fuzz", "scan", "ssh_bruteforce", "smb_admin"]


def load_catalog() -> dict:
    with open(CATALOG_FILE, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def ensure_dirs() -> None:
    for d in (DATA, PCAPS, OUT):
        d.mkdir(parents=True, exist_ok=True)
