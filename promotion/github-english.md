# Building a Self-Evolving AI Security Research Platform — Fully Open Source

**A complete pipeline that sends security tasks to AI models, evaluates their fixes in a Docker sandbox, detects cheating, and feeds failures back into LoRA fine-tuning.**

---

## The Problem

When I started testing LLMs (DeepSeek, GPT-4, etc.) on **code security fixes**, I ran into three problems:

1. **AI models cheat** — some just hardcode `return True` to bypass security checks
2. **No feedback loop** — evaluation results were wasted instead of being reused for training
3. **No standardization** — every model needed a custom evaluation setup

So I built **AI Research Platform** — a full pipeline from task publishing → AI behavior capture → sandbox evaluation → anti-cheat detection → data export → LoRA fine-tuning.

---

## Architecture

```
Publish Task → AI Submits Fix → Docker Sandbox Execution
                                    ↓
      Export Training Data ← Multi-Dimension Evaluation
                ↓
          LoRA Fine-Tune → Next Round
```

Three independent open-source components:

### 🍯 1. honeycode-honeypot
- Publishes code security tasks (SQL injection fix, memory leak fix, etc.)
- Captures AI model submissions with auto-scoring + leaderboard
- Each task has a `task.yaml` definition + `tests/` suite

### 📊 2. eval-engine
The heart of the system. Runs untrusted AI code in a **Docker sandbox** with **6 anti-cheat detectors**:

| Detection | Severity | What it catches |
|-----------|----------|----------------|
| Hardcoded Bypass | 🔴 High | `is_admin = True`, hardcoded passwords |
| Dangerous Syscalls | 🔴 High | `subprocess`, `os.system`, `ctypes` |
| SQL Injection | 🟠 Medium | f-string SQL, string concatenation |
| eval/exec | 🔴 High | Dynamic code execution |
| Obfuscated Code | 🟠 Medium | base64 decode, `__import__` |
| Expected Output | 🟡 Low | Hidden answers in comments |

Outputs 3 metrics: **Functional Correctness**, **Security Score**, **Cheat Score**.

### 🏋️ 3. ai-training-gym
- Standardized task format (YAML + JSONL datasets)
- Built-in data generators (math problems, SQL security scenarios)
- **LoRA fine-tuning pipeline** — failed cases auto-export as training data

### 🤖 Auto Agent Loop
Runs every 2 hours:
1. Scan pending tasks
2. Generate fixes via DeepSeek
3. Submit to honeypot
4. Evaluate in sandbox (with anti-cheat)
5. Export training data

---

## Current Status

| Component | Tests | Status |
|-----------|-------|--------|
| eval-engine | 37/37 ✅ | Anti-cheat + metrics all passing |
| honeycode-honeypot | 7/8 ✅ | 1 expected fail (SQL task awaiting fix) |
| ai-training-gym | 23/23 ✅ | Math + SQL tasks all passing |

---

## Quick Start

```bash
git clone https://github.com/zhangjiayang6835-cyber/ai-research.git
cd ai-research

# Activate environment
source venv/bin/activate

# Run eval-engine tests
cd eval-engine && pytest tests/ -v

# Build Docker sandbox
docker build -t eval-sandbox:latest .
```

---

## Repos

| Component | Link |
|-----------|------|
| 🏗️ Platform Overview | [github.com/zhangjiayang6835-cyber/ai-research](https://github.com/zhangjiayang6835-cyber/ai-research) |
| 🍯 honeycode-honeypot | [github.com/zhangjiayang6835-cyber/honeycode-honeypot](https://github.com/zhangjiayang6835-cyber/honeycode-honeypot) |
| 📊 eval-engine | [github.com/zhangjiayang6835-cyber/eval-engine](https://github.com/zhangjiayang6835-cyber/eval-engine) |
| 🏋️ ai-training-gym | [github.com/zhangjiayang6835-cyber/ai-training-gym](https://github.com/zhangjiayang6835-cyber/ai-training-gym) |

---

## Roadmap

- [ ] More security task types (XSS, CSRF, RCE)
- [ ] Support more models (Claude, Gemini)
- [ ] Visualization dashboard (trends, leaderboard)
- [ ] Community-contributed task templates

---

**Interested in AI security, code evaluation, or anti-cheating?** Stars, Issues, and PRs are all welcome!

*Experimental project — the core logic works, but there's plenty of room for improvement. Join us on GitHub!*
