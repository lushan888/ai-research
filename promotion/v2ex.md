# 开源了个 AI 安全研究闭环系统，欢迎来玩

搞了一套「发安全任务给 AI → 沙箱评测 → 反作弊 → 导出训练数据 → LoRA 微调」的完整闭环，全部开源了。

## 三个组件

**🍯 honeycode-honeypot**（蜜罐）
发代码安全修复任务（SQL注入、内存泄漏等），AI 提交后自动评测+排行榜。

**📊 eval-engine**（评测引擎）
Docker 沙箱里执行 AI 提交的代码，同时做 6 种反作弊检测：
- 硬编码绕过（写死 `return True`）
- 危险系统调用（subprocess、os.system）
- SQL 注入、eval/exec、混淆代码、藏答案

三项指标：功能正确性 / 安全性 / 作弊分数。

**🏋️ ai-training-gym**（训练场）
标准 YAML+JSONL 任务格式 + LoRA 微调流水线，评测失败的案例直接导出当训练数据。

## 当前状态

```
eval-engine:    37/37 ✅
honeycode:       7/8 ✅（1个预期失败，SQL注入待修复）
ai-training-gym: 23/23 ✅
```

自动 Agent 每 2 小时跑一轮：发现任务 → AI 修复 → 评测 → 导出。

## 地址

- 总览：https://github.com/zhangjiayang6835-cyber/ai-research
- 蜜罐：https://github.com/zhangjiayang6835-cyber/honeycode-honeypot
- 评测：https://github.com/zhangjiayang6835-cyber/eval-engine
- 训练：https://github.com/zhangjiayang6835-cyber/ai-training-gym

实验阶段项目，欢迎 Star / Issue / PR 🙏
