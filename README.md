# API Checker

检测中转 API 服务是否存在**提示词注入**、**上下文截断**、**指令覆盖**、**数据窃取**等作恶行为的开源安全审计工具。
代码小白第一次Vibe Coding 不足之处还望海涵

[![Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

---

## 快速开始

### 网页版（推荐）

```bash
pip install -r requirements.txt
ADMIN_PASSWORD=你的密码 python -m uvicorn api_relay_audit.web.main:app --host 0.0.0.0 --port 8000
```

然后打开 http://localhost:8000 即可使用。

### 命令行版

```bash
pip install -r requirements.txt
python scripts/audit.py audit --config config.yaml
```

---

## 功能特性

### 11 个检测项（原有 7 项 → 扩展至 11 项）

| # | 检测项 | 说明 |
|---|--------|------|
| 1 | 🔍 Token 注入检测 | 发现每个请求被偷偷多注入的 token 数量 |
| 2 | 🛡️ 隐藏提示词注入 | 揪出响应中附加的非用户指令（如广告/翻译） |
| 3 | ⚠️ 指令覆盖检测 | 验证 System Prompt 是否被忽略或替换 |
| 4 | 📏 上下文截断检测 | Canary Marker + 二分搜索，精确定位截断边界 |
| 5 | 🔓 数据窃取检测 | 对话内容是否被持久化或跨会话泄漏 |
| 6 | 🧠 语义截断检测 | 用语义埋点（非精确标记）检测截断，无法被白盒规避 |
| 7 | 🎯 指令优先级检测 | 测试 system/developer/user 优先级是否被破坏 |
| 8 | ⏱️ 响应延迟异常检测 | 长上下文秒响应说明中转商偷懒没处理 |
| 9 | 📋 响应格式指纹检测 | 要求 JSON 格式输出，被污染则暴露注入 |
| 10 | 🔗 对话记忆链检测 | 第 N 轮能否引用第 1 轮信息，滑动窗口截断无处遁形 |
| 11 | 🌐 HTTP 头部深度检测 | 响应头 meta 信息注入检测 |

### 支持的 API 格式
- OpenAI `/v1/chat/completions` 兼容
- Anthropic `/v1/messages` 兼容
- 自动探测（无需手动指定）

### 风险评分体系
- **0–30 分**：✅ 安全
- **31–60 分**：⚠️ 中等风险
- **61–80 分**：🔴 高风险
- **81–100 分**：☠️ 极危险

---

## 与原项目的对比

本项目基于 [toby-bridges/api-relay-audit](https://github.com/toby-bridges/api-relay-audit)（MIT License）开发，在其基础上进行了**大幅扩展**：

| 维度 | 原项目 | 本项目 |
|------|--------|--------|
| 检测算法 | 7 项 | **11 项**（新增 6 个扩展检测器）|
| 用户界面 | 无（仅 CLI） | **Web UI + 管理后台** |
| API 接入 | 仅命令行 | **FastAPI + REST 接口** |
| 上下文检测 | 精确 Canary | **Canary + 语义埋点双重检测** |
| 并发支持 | 单线程 | **asyncio 高并发** |
| 报告格式 | Markdown | **JSON + Markdown + 可视化网页** |
| 配置管理 | 手工编辑 YAML | **网页后台可视化配置** |
| 测试覆盖 | 部分 | **140 个单元测试 + 靶机** |

### 新增的 6 个检测器说明

**语义截断检测（Semantic Truncation）**
- 原项目用精确 canary 字符串，中转商可检测后故意保留
- 本项目改用语义埋点（"我的幸运数字是 42"），靠语义相似度判断，无法规避

**指令优先级检测（Instruction Priority）**
- 利用 `system > developer > assistant > user` 优先级，构造矛盾指令对验证

**响应延迟异常检测（Response Latency）**
- 测量 `time_elapsed`，长上下文但极快响应 = 偷懒不处理

**响应格式指纹检测（Format Fingerprint）**
- 要求模型输出特定 JSON 格式，注入会破坏格式

**对话记忆链检测（Memory Chain）**
- 测试第 N 轮能否引用第 1 轮信息，滑动窗口截断可被发现

**HTTP 头部深度检测（Header Deep）**
- 检查响应头是否有可疑的 `X-Query-Log`、`X-Forwarded-For` 等 meta 注入

---

## 项目结构

```
api-checker/
├── src/api_relay_audit/
│   ├── adapter/          # OpenAI + Anthropic 双格式自动适配
│   ├── detectors/        # 11 个检测器（T1-T11）
│   ├── engine/           # 审计编排 + RiskCalculator
│   ├── reports/          # JSON + Markdown 导出
│   ├── utils/            # Canary 生成器 + Token 估算
│   └── web/               # FastAPI 服务 + 网页 + 管理后台
├── scripts/               # CLI 入口
├── tests/                 # 140 个单元测试 + 靶机
├── docs/                  # 报告解读指南
├── README.md
├── LICENSE                # Apache 2.0
├── NOTICE                 # 原项目归属声明
└── content.yaml          # 网站内容配置
```

---

## 协议说明

### 本项目：Apache 2.0

本项目采用 [Apache License 2.0](LICENSE) 开源，可自由用于商业和非商业用途。

### 原项目归属

本项目参考并引入了 [toby-bridges/api-relay-audit](https://github.com/toby-bridges/api-relay-audit)（MIT License）的以下设计思想：
- 模块化的检测器架构（Plugin 模式）
- Canary Marker 上下文检测思路
- `/v1/chat/completions` 和 `/v1/messages` 双格式兼容方案
- 7 步审计流程框架

详细归属声明请参阅 [NOTICE](NOTICE) 文件。

---

## 使用注意

⚠️ **免责声明**：检测结果仅供参考和辅助判断，不构成任何形式的保证。不同模型、不同对话上下文、不同时间段的检测结果可能存在差异。建议结合实际情况综合判断，中转服务的实际行为应以官方说明为准。
