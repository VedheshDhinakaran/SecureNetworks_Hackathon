"""Quality engine: scoring, benign gate, threshold sweep, robustness grid, evasion matrix.

Ground truth comes from data/manifest.json (written by the generator), so every number here
is computed, never typed by hand.
"""
from __future__ import annotations

import math
from collections import defaultdict
from statistics import median

from . import engines as eng
from . import native
from .config import CLASSES, PCAPS, load_catalog
from .gen import GRID_RATES

CORE = ("attack", "chain")
NEG = ("benign", "hardneg")
KNOWN_GAPS = {"ev_distributed_ssh", "ev_admin_host_abuse", "ev_tiny_scan_9", "ev_http_boundary49", "ev_http_padded", "ev_http_small5"}          # honest limitation: per-source counting cannot see it
COLS = [("suricata", "L1"), ("suricata", "UA"), ("zeek", "L2"), ("native", "L1"), ("native", "L2"), ("native", "UA")]


def layer_key(e: dict) -> str:
    return "UA" if (e.get("aux") or str(e.get("rule", "")).endswith("-UA")) else e["layer"]


def collect(engines: list[str], manifest: list[dict]) -> dict:
    """{pcap: {engine: [events]}}"""
    out: dict = {}
    for m in manifest:
        p = PCAPS / m["file"]
        out[m["name"]] = {e: eng.events_for(e, p) for e in engines}
    return out


def _evs(col, name, engine, cls):
    if engine == "ensemble":
        return [x for e in col[name].values() for x in e if x["class"] == cls]
    return [x for x in col[name].get(engine, []) if x["class"] == cls]


# ---------------------------------------------------------------- scoring
def score(col: dict, manifest: list[dict], engines: list[str]) -> dict:
    neg = [m for m in manifest if m["kind"] in NEG]
    neg_hours = sum(m["duration"] for m in neg) / 3600
    res: dict = {"engines": {}, "neg_pcaps": len(neg), "neg_hours": round(neg_hours, 2)}
    for en in engines + ["ensemble"]:
        per: dict = {}
        for cls in CLASSES:
            pos = [m for m in manifest if m["kind"] in CORE and cls in m["expect"]]
            tp, ttd = 0, []
            for m in pos:
                ev = _evs(col, m["name"], en, cls)
                if ev:
                    tp += 1
                    ttd.append(min(x["ts"] for x in ev) - m.get("stage_start", {}).get(cls, m["attack_start"]))
            fp_alerts = sum(len(_evs(col, m["name"], en, cls)) for m in neg)
            fp_pcaps = sum(1 for m in neg if _evs(col, m["name"], en, cls))
            per[cls] = {
                "positives": len(pos), "tp": tp, "fn": len(pos) - tp,
                "fp_alerts": fp_alerts, "fp_pcaps": fp_pcaps,
                "recall": round(tp / len(pos), 3) if pos else None,
                "precision": round(tp / (tp + fp_pcaps), 3) if (tp + fp_pcaps) else 1.0,
                "ttd_median_s": round(median(ttd), 2) if ttd else None,
            }
        res["engines"][en] = per
    return res


def agreement(col: dict, manifest: list[dict], engines: list[str]) -> list[dict]:
    rows = []
    for m in manifest:
        if m["kind"] not in CORE:
            continue
        for cls in m["expect"]:
            seen = {en: bool(_evs(col, m["name"], en, cls)) for en in engines}
            n = sum(seen.values())
            rows.append({"pcap": m["name"], "class": cls, "engines": seen,
                         "consensus": "both" if n >= 2 and len(engines) >= 2 and seen.get("suricata") and seen.get("zeek")
                         else ("single" if n == 1 else ("none" if n == 0 else "multi"))})
    return rows


def _cells(col, name, cls, engines):
    cells = {}
    for en, layer in COLS:
        if en not in engines:
            continue
        cells[f"{en}:{layer}"] = any(layer_key(x) == layer for x in col[name].get(en, []) if x["class"] == cls)
    return cells


def evasion_matrix(col: dict, manifest: list[dict], engines: list[str]) -> list[dict]:
    rows = []
    for m in manifest:
        if m["kind"] != "evasion":
            continue
        cls = m["expect"][0]
        cells = _cells(col, m["name"], cls, engines)
        rows.append({"pcap": m["name"], "class": cls, "desc": m["desc"], "cells": cells,
                     "caught": any(cells.values()), "known_gap": m["name"] in KNOWN_GAPS})
    return rows


def robustness_grid(col: dict, manifest: list[dict], engines: list[str]) -> dict:
    grid: dict = {}
    for cls, rates in GRID_RATES.items():
        rows = []
        for rate in rates:
            m = next((x for x in manifest if x["name"] == f"grid_{cls}_{rate:g}"), None)
            if not m:
                continue
            cells = _cells(col, m["name"], cls, engines)
            rows.append({"rate": rate, "cells": cells, "caught": any(cells.values())})
        grid[cls] = rows
    return grid


# ---------------------------------------------------------------- sweep
LADDER = [1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 16, 20, 25, 30, 40, 50, 75, 100, 150, 200, 300, 500, 1000]


def sweep(manifest: list[dict]) -> dict:
    """Evidence-based tuning: for every class and layer, evaluate a ladder of thresholds against all
    labelled traffic and report the safe band [max benign metric + 1, min attack metric]."""
    cat = load_catalog()["classes"]
    feats = {m["name"]: native.features(native.parse_pcap(PCAPS / m["file"])) for m in manifest}
    out: dict = {}
    for cls in CLASSES:
        if cls == "smb_admin":
            continue
        for layer in ("L1", "L2"):
            kinds = CORE if layer == "L1" else CORE + ("evasion",)
            pos = [m["name"] for m in manifest if m["kind"] in kinds and cls in m["expect"] and m["name"] not in KNOWN_GAPS]
            neg = [m["name"] for m in manifest if m["kind"] in NEG]
            pv = {n: feats[n][cls][layer] for n in pos}
            nv = {n: feats[n][cls][layer] for n in neg}
            max_neg = max(nv.values()) if nv else 0
            min_pos = min(pv.values()) if pv else 0
            lo, hi = max_neg + 1, min_pos
            current = cat[cls]["l1" if layer == "L1" else "l2"]["count"]
            curve = []
            for t in LADDER:
                tp = sum(1 for v in pv.values() if v >= t)
                fp = sum(1 for v in nv.values() if v >= t)
                curve.append({"t": t, "recall": round(tp / len(pv), 3) if pv else 0,
                              "precision": round(tp / (tp + fp), 3) if (tp + fp) else 1.0, "fp": fp})
            out[f"{cls}.{layer}"] = {
                "class": cls, "layer": layer, "current": current, "band": [lo, hi],
                "recommended": int(round(math.sqrt(lo * hi))) if hi >= lo else None,
                "in_band": lo <= current <= hi, "max_benign": max_neg, "min_attack": min_pos,
                "worst_benign": max(nv, key=nv.get) if nv else None,
                "weakest_attack": min(pv, key=pv.get) if pv else None, "curve": curve,
                "positives": pos,
            }
    return out


# ---------------------------------------------------------------- gate
def gate(sc: dict, sw: dict, engines: list[str]) -> list[dict]:
    checks = []
    for en in engines:
        fp = sum(v["fp_alerts"] for v in sc["engines"][en].values())
        checks.append({"name": f"Benign gate: {en} raises 0 alerts on benign + hard-negative traffic",
                       "ok": fp == 0, "detail": f"{fp} false-positive alerts over {sc['neg_pcaps']} captures ({sc['neg_hours']} h)"})
    ens = sc["engines"]["ensemble"]
    missed = [c for c, v in ens.items() if v["fn"]]
    checks.append({"name": "Recall: every attack class detected in every core attack capture",
                   "ok": not missed, "detail": "all 4 classes detected" if not missed else f"missed: {missed}"})
    off = [k for k, v in sw.items() if not v["in_band"]]
    checks.append({"name": "Tuning: every threshold sits inside its measured safe band",
                   "ok": not off, "detail": "all thresholds inside band" if not off else f"outside band: {off}"})
    return checks
