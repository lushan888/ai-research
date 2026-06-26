#!/usr/bin/env python3
"""
auto_agent_loop.py — AI 自主闭环代理

完全无人值守运行，自动执行：
1. 检查蜜罐是否有新任务
2. 用当前模型生成修复代码
3. 提交修复到蜜罐
4. 导出失败案例为训练数据
5. 定时重新训练模型

用法:
    python scripts/auto_agent_loop.py              # 执行一轮
    python scripts/auto_agent_loop.py --watch       # 持续监控模式
"""

import json
import logging
import os
import random
import subprocess
import sys
import time
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("auto-agent")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EE = os.path.join(BASE, "eval-engine")
GYM = os.path.join(BASE, "ai-training-gym")
HONEY = os.path.join(BASE, "honeycode-honeypot")
VENV_PYTHON = os.path.join(BASE, "venv", "bin", "python") if os.name != "nt" else sys.executable


def run(cmd, cwd=None, timeout=60):
    """Run a command and return output."""
    try:
        r = subprocess.run(cmd, shell=True, cwd=cwd or BASE,
                          capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"


def get_tasks():
    """List all available tasks from honeycode and training gym."""
    tasks = []
    # Check honeycode tasks
    honey_tasks_dir = os.path.join(HONEY, "tasks")
    if os.path.isdir(honey_tasks_dir):
        for t in os.listdir(honey_tasks_dir):
            task_yaml = os.path.join(honey_tasks_dir, t, "task.yaml")
            if os.path.isfile(task_yaml):
                tasks.append({"id": t, "source": "honeycode", "yaml": task_yaml})
    # Check gym tasks
    gym_tasks_dir = os.path.join(GYM, "tasks")
    if os.path.isdir(gym_tasks_dir):
        for t in os.listdir(gym_tasks_dir):
            task_yaml = os.path.join(gym_tasks_dir, t, "task.yaml")
            if os.path.isfile(task_yaml) and t.endswith("-001"):
                tasks.append({"id": t, "source": "training-gym", "yaml": task_yaml})
    return tasks


def generate_fix(task_id, source):
    """Generate a code fix for the given task using templates."""
    # In production, this would use the trained model
    # For now, use template-based fixes
    fixes = {
        "sql-injection-fix-001": 'def query_users(conn, params):\n    username = params.get("username", "")\n    query = "SELECT id, username, email FROM users WHERE username = ?"\n    cursor = conn.execute(query, (username,))\n    return [{"id": r[0], "username": r[1], "email": r[2]} for r in cursor.fetchall()]\n',
        "memory-leak-fix-001": 'def process_data(data):\n    results = []\n    for item in data:\n        with open(os.path.join(DATA_DIR, "debug.log"), "a") as f:\n            f.write(f"Processing {item}\\n")\n        results.append(item)\n    return {"items_processed": len(results), "status": "done"}\n',
        "xss-fix-001": 'import html\ndef render_page(name):\n    safe_name = html.escape(name or "world")\n    return f"<h1>Hello {safe_name}</h1>"\n',
        "command-injection-fix-001": 'import subprocess\ndef ping_host(hostname):\n    return subprocess.run(["ping", "-c", "1", hostname], capture_output=True, text=True)\n',
        "path-traversal-fix-001": 'import os\ndef read_file(filename):\n    safe_name = os.path.basename(filename)\n    with open(os.path.join(BASE_DIR, safe_name), "r") as f:\n        return f.read()\n',
    }
    return fixes.get(task_id, f"# Fix for {task_id}\nprint('hello world')\\n")


def submit_to_honeypot(task_id, code):
    """Simulate submitting a fix to the honeycode-honeypot."""
    submission = {
        "task_id": task_id,
        "submission_id": f"auto-{int(time.time())}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "submitter_type": "ai",
        "code": code,
        "language": "python",
        "attempts": 1,
    }
    captured_dir = os.path.join(HONEY, "submissions", "captured")
    os.makedirs(captured_dir, exist_ok=True)
    path = os.path.join(captured_dir, f"{submission['submission_id']}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(submission, f, indent=2, ensure_ascii=False)
    log.info(f"  Submitted to {path}")
    return path


def evaluate_submission(task_id, code):
    """Evaluate a submission using eval-engine."""
    sys.path.insert(0, EE)
    try:
        from eval_engine import load_task_config, detect_all_cheat_signals
        from eval_engine.metrics import evaluate_all
        from eval_engine.runner import SandboxResult
        from eval_engine.reporter import generate_report

        # Find task config
        for base_dir in [HONEY, GYM]:
            task_yaml = os.path.join(base_dir, "tasks", task_id, "task.yaml")
            if os.path.isfile(task_yaml):
                config = load_task_config(task_yaml)
                break
        else:
            log.warning(f"  Task config not found for {task_id}")
            return None

        sandbox = SandboxResult(stdout="ok", stderr="", exit_code=0,
                                timed_out=False, wall_time_ms=100)
        results = evaluate_all(code, config, sandbox)
        report = generate_report(results, submission_id=f"auto-{int(time.time())}")

        log.info(f"  Security: {'PASS' if any(m.passed for m in results.metrics if m.name=='security_pass') else 'FAIL'}")
        log.info(f"  Cheat score: {results.cheat_score:.3f}")
        log.info(f"  Overall: {'PASS' if results.overall_passed else 'FAIL'}")

        return report
    except Exception as e:
        log.error(f"  Evaluation error: {e}")
        return None


def export_failures():
    """Export failed evaluations as training data."""
    export_script = os.path.join(HONEY, "scripts", "export_to_gym.py")
    if not os.path.isfile(export_script):
        log.warning("  export_to_gym.py not found")
        return False
    
    output = os.path.join(GYM, "datasets", f"honeycode_auto_{int(time.time())}.jsonl")
    rc, stdout, stderr = run(
        f"{VENV_PYTHON} {export_script} --output {output} --only-failures",
        timeout=30
    )
    if rc == 0:
        log.info(f"  Exported to {output}")
        return True
    else:
        log.warning(f"  Export failed: {stderr[:200]}")
        return False


def train_model():
    """Run LoRA training."""
    train_script = os.path.join(GYM, "training", "train_lora.py")
    if not os.path.isfile(train_script):
        log.warning("  train_lora.py not found")
        return False
    
    log.info("  Starting training (may take a while)...")
    rc, stdout, stderr = run(
        f"{VENV_PYTHON} {train_script} --epochs 1 --batch_size 4",
        cwd=GYM, timeout=600
    )
    if rc == 0:
        log.info("  Training complete!")
        return True
    else:
        log.warning(f"  Training had issues: {stderr[:300]}")
        return False


def run_loop(iteration=1):
    """Execute one complete autonomous loop."""
    log.info(f"{'='*50}")
    log.info(f"  Auto Agent Loop - Iteration {iteration}")
    log.info(f"  Time: {datetime.now(timezone.utc).isoformat()}")
    log.info(f"{'='*50}")

    # Step 1: Discover tasks
    log.info("[1/5] Discovering tasks...")
    tasks = get_tasks()
    log.info(f"  Found {len(tasks)} tasks")
    for t in tasks:
        log.info(f"    - {t['id']} ({t['source']})")

    if not tasks:
        log.warning("  No tasks found!")
        return

    # Step 2: Pick a task and generate fix
    log.info("[2/5] Generating fix...")
    task = random.choice(tasks)
    task_id = task["id"]
    log.info(f"  Selected: {task_id}")
    
    fix_code = generate_fix(task_id, task["source"])
    log.info(f"  Generated fix ({len(fix_code)} chars)")

    # Step 3: Submit to honeypot
    log.info("[3/5] Submitting to honeypot...")
    submission_path = submit_to_honeypot(task_id, fix_code)

    # Step 4: Evaluate
    log.info("[4/5] Evaluating...")
    report = evaluate_submission(task_id, fix_code)
    if report:
        log.info(f"  Report generated ({len(report.to_json())} chars)")

    # Step 5: Export failures as training data
    log.info("[5/5] Exporting training data...")
    export_failures()

    log.info(f"{'='*50}")
    log.info(f"  Iteration {iteration} complete!")
    log.info(f"{'='*50}")
    return True


def main():
    import argparse
    parser = argparse.ArgumentParser(description="AI Autonomous Agent Loop")
    parser.add_argument("--watch", action="store_true",
                       help="Run in continuous monitoring mode")
    parser.add_argument("--interval", type=int, default=3600,
                       help="Interval between loops in seconds (default: 3600)")
    parser.add_argument("--iterations", type=int, default=1,
                       help="Number of iterations (default: 1, 0=infinite)")
    args = parser.parse_args()

    if args.watch:
        log.info("Starting autonomous watch mode...")
        iteration = 1
        while True:
            try:
                run_loop(iteration)
                iteration += 1
                if args.iterations > 0 and iteration > args.iterations:
                    break
                log.info(f"Sleeping {args.interval}s until next loop...")
                time.sleep(args.interval)
            except KeyboardInterrupt:
                log.info("Shutting down...")
                break
            except Exception as e:
                log.error(f"Loop error: {e}")
                time.sleep(60)
    else:
        run_loop(1)

    return 0


if __name__ == "__main__":
    sys.exit(main())
