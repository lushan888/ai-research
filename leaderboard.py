#!/usr/bin/env python3
"""
leaderboard.py — AI Research Platform 统一排行榜系统

从 BOUNTY_LEDGER.json + honey_ledger.json 读取数据，
输出 Markdown / JSON / SVG 三种格式。

用法:
    python scripts/leaderboard.py                          # stdout Markdown
    python scripts/leaderboard.py --output LEADERBOARD.md
    python scripts/leaderboard.py --json                   # stdout JSON
    python scripts/leaderboard.py --svg docs/leaderboard.svg
    python scripts/leaderboard.py --all                    # 同时输出全部
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any


HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)

BOUNTY_PATH = os.path.join(REPO_ROOT, "BOUNTY_LEDGER.json")
HONEY_PATH = os.path.join(REPO_ROOT, "honey_ledger.json")
SVG_PATH = os.path.join(REPO_ROOT, "docs", "leaderboard.svg")

# ── Load data ─────────────────────────────────────────────────────

def load_bounties() -> dict:
    """Load BOUNTY_LEDGER.json — primary data source."""
    if not os.path.isfile(BOUNTY_PATH):
        return {}
    with open(BOUNTY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def load_honey() -> dict:
    """Load honey_ledger.json — secondary/legacy data."""
    if not os.path.isfile(HONEY_PATH):
        return {}
    with open(HONEY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


# ── Aggregation ────────────────────────────────────────────────────

def build_leaderboard_data() -> dict:
    """Merge both ledgers and compute rankings."""
    bounties = load_bounties()
    honey = load_honey()

    # Start with BOUNTY_LEDGER
    participants = {}
    for name, data in bounties.items():
        participants[name] = {
            "name": name,
            "total_honey": data.get("total", 0),
            "task_count": data.get("task_count", 0),
            "submissions": data.get("submissions", []),
            "honey_legacy": 0,
        }

    # Merge honey_ledger (add to existing or create new)
    for name, data in honey.items():
        if name in participants:
            participants[name]["honey_legacy"] = data.get("HONEY", 0)
        else:
            participants[name] = {
                "name": name,
                "total_honey": data.get("HONEY", 0),
                "task_count": len(data.get("tasks", [])),
                "submissions": [],
                "honey_legacy": data.get("HONEY", 0),
            }

    # Compute extra stats
    for name, p in participants.items():
        subs = p["submissions"]
        p["recent_count"] = sum(1 for s in subs if s.get("date", "")[:7] >= "2026-07")
        p["clean_count"] = sum(1 for s in subs if s.get("clean"))
        # Streak
        dates = sorted(set(s.get("date", "")[:10] for s in subs if s.get("date")))
        p["streak"] = _calc_streak(dates)

    # Sort by total_honey descending
    sorted_p = sorted(participants.values(), key=lambda x: -x["total_honey"])

    # Awards
    medals = []
    if len(sorted_p) >= 1:
        medals.append({"rank": 1, "name": sorted_p[0]["name"], "medal": "🥇", "label": "安全之王"})
    if len(sorted_p) >= 2:
        medals.append({"rank": 2, "name": sorted_p[1]["name"], "medal": "🥈", "label": "漏洞猎手"})
    if len(sorted_p) >= 3:
        medals.append({"rank": 3, "name": sorted_p[2]["name"], "medal": "🥉", "label": "安全新星"})

    # Task leaderboard (who completed most different tasks)
    by_tasks = sorted(participants.values(), key=lambda x: -x["task_count"])

    return {
        "participants": sorted_p,
        "by_tasks": by_tasks,
        "medals": medals,
        "total_participants": len(sorted_p),
        "total_bounties_paid": sum(p["total_honey"] for p in sorted_p),
        "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


def _calc_streak(dates: list[str]) -> int:
    """Calculate consecutive day streak from date strings (allow 2-day gap for weekends)."""
    if not dates:
        return 0
    streak = 1
    from datetime import datetime, timedelta
    try:
        cur = datetime.strptime(dates[-1], "%Y-%m-%d")
        for i in range(len(dates) - 2, -1, -1):
            d = datetime.strptime(dates[i], "%Y-%m-%d")
            if (cur - d).days <= 2:
                streak += 1
                cur = d
            else:
                break
    except ValueError:
        streak = 1
    return streak


def _streak_icon(n: int) -> str:
    if n >= 7: return "🔥"
    if n >= 3: return "✨"
    if n >= 1: return "🌱"
    return ""


def _grade_icon(total: int) -> str:
    if total >= 1000: return "💎"
    if total >= 500: return "🥇"
    if total >= 200: return "🥈"
    if total >= 50: return "🥉"
    return "📋"


# ── Markdown output ────────────────────────────────────────────────

def build_markdown(data: dict) -> str:
    parts = []
    now = data["last_updated"]

    parts.append("# 🏆 AI 安全修复排行榜\n")
    parts.append(f"> _更新于 {now}  ·  {data['total_participants']} 名参与者  ·  总计 {data['total_bounties_paid']} 🪙 HONEY_\n")
    parts.append("---\n")

    # ── Medals ──
    if data["medals"]:
        parts.append("## 🏅 颁奖台\n")
        for m in data["medals"]:
            parts.append(f"| {m['medal']} **{m['label']}** | `{m['name']}` |")
        parts.append("")

    # ── Total leaderboard ──
    parts.append("## 🪙 HONEY 总榜\n")
    parts.append("| 排名 | 参与者 | HONEY 🪙 | 任务数 | 活跃度 | 零作弊 | 徽章 |")
    parts.append("|:---:|:------:|:--------:|:------:|:------:|:------:|:----:|")
    for i, p in enumerate(data["participants"], 1):
        rank_icon = {1: "🥇", 2: "🥈", 3: "🥉"}.get(i, f"{i}")
        parts.append(
            f"| {rank_icon} | `{p['name']}` "
            f"| **{p['total_honey']}** "
            f"| {p['task_count']} "
            f"| {_streak_icon(p['streak'])} {p['streak']}d "
            f"| {'✅' if p['clean_count'] >= p['task_count'] else '—'} "
            f"| {_grade_icon(p['total_honey'])} |"
        )
    parts.append("")

    # ── Task leaderboard ──
    parts.append("## 📋 任务完成榜\n")
    parts.append("| 排名 | 参与者 | 完成任务数 |")
    parts.append("|:---:|:------:|:--------:|")
    for i, p in enumerate(data["by_tasks"], 1):
        parts.append(f"| {i} | `{p['name']}` | {p['task_count']} |")
    parts.append("")

    # ── Recent activity ──
    active = [p for p in data["participants"] if p["recent_count"] > 0]
    if active:
        parts.append("## 🔥 近期活跃\n")
        parts.append("| 参与者 | 近7天提交 | HONEY 🪙 |")
        parts.append("|:------:|:--------:|:--------:|")
        for p in sorted(active, key=lambda x: -x["recent_count"])[:5]:
            parts.append(f"| `{p['name']}` | {p['recent_count']} | {p['total_honey']} |")
        parts.append("")

    # ── Scoring rules ──
    parts.append("---\n")
    parts.append("### 📊 计分规则\n")
    parts.append("| 难度 | 基础分 | 额外奖励 |")
    parts.append("|:----:|:------:|:--------:|")
    parts.append("| 🟢 简单 | 10 分 | 零作弊 +5 分 |")
    parts.append("| 🟡 中等 | 25 分 | 零作弊 +10 分 |")
    parts.append("| 🔴 困难 | 50 分 | 零作弊 +20 分 |")
    parts.append("")
    parts.append("### 🏅 徽章等级\n")
    parts.append("| 徽章 | 门槛 |")
    parts.append("|:----:|:----:|")
    parts.append("| 💎 安全大师 | ≥ 1000 HONEY |")
    parts.append("| 🥇 金牌猎人 | ≥ 500 HONEY |")
    parts.append("| 🥈 银牌猎人 | ≥ 200 HONEY |")
    parts.append("| 🥉 铜牌猎人 | ≥ 50 HONEY |")
    parts.append("| 📋 参与者 | > 0 HONEY |")
    parts.append("")
    parts.append("> 🪙 虚拟代币仅供学习排名使用，不可兑换为现金或加密货币。")

    return "\n".join(parts)


# ── JSON output ───────────────────────────────────────────────────

def build_json(data: dict) -> dict:
    return {
        "meta": {
            "last_updated": data["last_updated"],
            "total_participants": data["total_participants"],
            "total_bounties_paid": data["total_bounties_paid"],
        },
        "medals": data["medals"],
        "leaderboard": [
            {
                "rank": i + 1,
                "name": p["name"],
                "total_honey": p["total_honey"],
                "task_count": p["task_count"],
                "streak_days": p["streak"],
                "clean_count": p["clean_count"],
   
