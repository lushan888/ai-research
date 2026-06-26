# 🔥 开源分享：我搭了一套「AI 修 Bug → 沙箱评测 → 反作弊 → 训练模型」的闭环系统

**一个能自动发安全任务给 AI、在 Docker 沙箱里评测它有没有作弊、再把失败案例喂回去微调模型的完整开源项目。**

---

## 为什么做这个

去年开始关注 AI 在**代码安全修复**场景的表现。试了各种模型（DeepSeek、GPT-4 等），发现几个问题：

1. **AI 会作弊** — 有的模型直接写死 `return True` 来绕过安全检查
2. **缺少闭环** — 评测完就完了，失败案例没有沉淀为训练数据
3. **各自为战** — 没有标准化的任务格式，换一个模型就得重新搭评测

于是就搭了这个 **AI Research Platform**，一个从「发布任务 → 捕获 AI 行为 → 沙箱评测 → 反作弊 → 导出训练数据 → LoRA 微调」的完整闭环。

---

## 系统概览

```
发布任务 → AI 提交修复 → Docker 沙箱执行
                              ↓
         导出训练数据 ← 多维度评测（功能+安全+反作弊）
                ↓
          LoRA 微调 → 新一轮评测
```

三个独立开源的组件，串成一条流水线：

### 🍯 1. honeycode-honeypot（蜜罐系统）
- 发布代码安全任务（SQL注入修复、内存泄漏修复等）
- 捕获各 AI 模型的提交行为，自动评分 + 排行榜
- 每个任务自带 `task.yaml` + `tests/` 测试套件

### 📊 2. eval-engine（评测引擎）
这是我最满意的部分。**Docker 沙箱里跑不可信代码**，同时做 6 种作弊检测：

| 检测项 | 严重级别 | 抓什么 |
|--------|---------|--------|
| 硬编码绕过 | 🔴 高 | `is_admin = True`, 写死密码 |
| 危险系统调用 | 🔴 高 | `subprocess`, `os.system`, `ctypes` |
| SQL 注入 | 🟠 中 | f-string 拼 SQL, 字符串拼接 |
| eval/exec | 🔴 高 | 动态执行代码 |
| 混淆代码 | 🟠 中 | base64 decode, `__import__` |
| 预期硬编码 | 🟡 低 | 注释里藏答案 |

每次评测输出三组指标：**功能正确性、安全性、作弊分数**，最后汇总为 PASS/FAIL。

### 🏋️ 3. ai-training-gym（AI 训练场）
- 标准化任务格式（YAML + JSONL）
- 内置数据生成器（数学问题、SQL 安全场景等）
- **LoRA 微调流水线** — 评测失败的案例直接导出为训练数据，喂给模型做下一轮微调

### 🤖 自动 Agent 循环
这三个组件还串了一个自动运行的脚本，每 2 小时：
1. 扫描所有待处理任务
2. 用 DeepSeek 生成修复代码
3. 提交到蜜罐
4. 在沙箱里评测（含反作弊）
5. 导出训练数据

---

## 实际效果

当前跑通了 4 个任务场景，总计 **68 项测试**：

| 组件 | 通过 | 说明 |
|------|------|------|
| eval-engine | 37/37 ✅ | 作弊检测 + 指标计算全过 |
| honeycode-honeypot | 7/8 ✅ | 1 个预期失败（SQL注入任务等修复） |
| ai-training-gym | 23/23 ✅ | 数学题 + SQL 修复全过 |

自动 Agent 已捕获了多轮 AI 提交的修复代码和评测结果。

---

## 快速上手

```bash
git clone https://github.com/zhangjiayang6835-cyber/ai-research.git
cd ai-research

# 激活环境
source venv/bin/activate

# 跑评测引擎测试
cd eval-engine && pytest tests/ -v

# 构建 Docker 沙箱
docker build -t eval-sandbox:latest .
```

---

## 项目地址

| 组件 | GitHub |
|------|--------|
| 🏗️ 平台总览 | [github.com/zhangjiayang6835-cyber/ai-research](https://github.com/zhangjiayang6835-cyber/ai-research) |
| 🍯 honeycode-honeypot | [github.com/zhangjiayang6835-cyber/honeycode-honeypot](https://github.com/zhangjiayang6835-cyber/honeycode-honeypot) |
| 📊 eval-engine | [github.com/zhangjiayang6835-cyber/eval-engine](https://github.com/zhangjiayang6835-cyber/eval-engine) |
| 🏋️ ai-training-gym | [github.com/zhangjiayang6835-cyber/ai-training-gym](https://github.com/zhangjiayang6835-cyber/ai-training-gym) |

---

## 后续规划

- [ ] 更多安全任务场景（XSS、CSRF、RCE 等）
- [ ] 支持更多模型接入（Claude、Gemini 等）
- [ ] 可视化 Dashboard（评测结果趋势、排行榜）
- [ ] 社区贡献的任务模板仓库

---

如果你对 **AI 安全、代码评测、反作弊检测** 感兴趣，欢迎 Star、Fork、提 Issue。PR 更是热烈欢迎 🎉

---

*项目仍处于实验阶段，代码可能有点糙，但核心逻辑是跑通的。欢迎来 GitHub 一起玩！*
