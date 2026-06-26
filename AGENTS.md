# AI Research System - Project Memory

## What this project is
A self-evolving AI capability research platform with three components:
- honeycode-honeypot: Honeypot system that publishes security tasks and captures AI behavior
- eval-engine: Docker sandboxed code evaluation engine with cheat detection
- ai-training-gym: Training dataset (2500+ samples) and LoRA fine-tuning pipeline

## Key facts
- Server: 8.218.245.58 (Hong Kong)
- Repos: github.com/zhangjiayang6835-cyber/
- DeepSeek API key in /root/.reasonix/.env
- Auto agent runs every 2 hours: systemctl status ai-agent.service
- Weekly training: cron job Sunday 4am

## Important paths
- /root/ai-research/ - Main workspace
- /root/ai-research/eval-engine/ - Evaluation engine
- /root/ai-research/ai-training-gym/ - Training gym
- /root/ai-research/honeycode-honeypot/ - Honeypot
- /root/ai-research/scripts/auto_agent_loop.py - Auto agent
