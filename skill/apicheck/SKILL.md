---
name: apicheck
version: 1.0.0
description: |
  Security audit tool for AI API relay/proxy services. Detects prompt injection,
  context truncation, instruction override, data exfiltration, and other malicious
  behaviors. Use when: "check relay API", "audit proxy", "detect API cheating",
  "scan middleman API", "/apicheck".
allowed-tools:
  - Bash
  - WebFetch
---

# /apicheck — AI API Relay Security Audit

You are a **Security Auditor** running an audit against a third-party AI API relay/proxy service. You help the user check whether their relay provider is secretly doing malicious things like injecting tokens, truncating context, overriding instructions, or exfiltrating data.

## User-invocable
When the user types `/apicheck`, run this skill.

## Arguments
- `/apicheck <endpoint_url>` — run audit against a relay API URL
- `/apicheck <endpoint_url> --model gpt-4` — specify model name
- `/apicheck <endpoint_url> --skip context_truncation,semantic_truncation` — skip token-heavy detectors

## Instructions

### Phase 1: Collect Requirements

Ask the user for the required information if not provided:

1. **Relay API URL** — The full URL of the relay/proxy endpoint (e.g. `https://api.relay.com/v1`)
2. **API Key** — The user's API key for the relay service
3. **Model name** — Which model the relay uses (e.g. `gpt-4o`, `claude-opus-4-6`)

If the user only gives a URL, ask for the API key and model.

Use AskUserQuestion to collect:

> **API Relay Audit**
> 请提供以下信息来完成审计：
> - **Relay API 地址**：你使用的中转 API 完整 URL（支持 OpenAI `/v1/chat/completions` 或 Anthropic `/v1/messages` 格式）
> - **API Key**：中转服务的 API 密钥
> - **模型名称**：中转平台上使用的模型（如 gpt-4o、claude-opus-4-6）
>
> Options:
> - A) 我已准备好所有信息（请在下方输入）
> - B) 先跳过，解释一下这个工具能检测什么

If they choose B, explain what it detects (see knowledge base below), then ask again.

### Phase 2: Validate Inputs

Validate the URL is a valid HTTP(S) endpoint. Warn if:
- URL is localhost/private (audit requires a public relay)
- API key looks like a real provider key instead of a relay key

### Phase 3: Run the Audit

Call the API Checker audit API. Determine the server URL:
- If the user has a self-hosted API Checker server, ask them for the URL
- Default: `http://localhost:8000`

**If user has their own API Checker server running:**

```bash
# Start the audit
curl -s -X POST "{SERVER_URL}/audit/start" \
  -H "Content-Type: application/json" \
  -d '{
    "endpoint_url": "{ENDPOINT_URL}",
    "token": "{API_KEY}",
    "model": "{MODEL}",
    "skip_detectors": []
  }' | python3 -c "import sys,json; d=json.load(sys.stdin); print('Session ID:', d.get('session_id','N/A')); print('Status:', d.get('status','N/A')); print('Message:', d.get('message','N/A'))"
```

Then poll for results:

```bash
# Poll status every 3 seconds
SESSION_ID="xxx"
SERVER_URL="http://localhost:8000"
for i in $(seq 1 60); do
  sleep 3
  STATUS=$(curl -s "$SERVER_URL/audit/$SESSION_ID/status" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null || echo "unknown")
  echo "[$i] Status: $STATUS"
  if [ "$STATUS" = "completed" ]; then
    curl -s "$SERVER_URL/audit/$SESSION_ID/result" | python3 -c "
import sys,json
d=json.load(sys.stdin)
r = d.get('risk',{})
a = d.get('audit',{})
print('=== AUDIT RESULT ===')
print(f\"Target: {a.get('target_url','N/A')}\")
print(f\"Model: {a.get('model','N/A')}\")
print(f\"Format: {a.get('detected_format','N/A')}\")
print(f\"Duration: {a.get('duration_seconds','N/A')}s\")
print()
print(f\"OVERALL RISK: {r.get('overall','N/A').upper()}\")
print(f\"SCORE: {r.get('score','N/A')}/100\")
print()
print('--- Detectors ---')
for det in d.get('detectors',[]):
    level = det.get('risk_level','unknown')
    findings = det.get('findings',[])
    passed = sum(1 for f in findings if f.get('passed',False))
    total = len(findings)
    print(f\"  [{level.upper():>8}] {det.get('id','?')}: {passed}/{total} passed\")
"
    break
  elif [ "$STATUS" = "failed" ]; then
    echo "Audit failed!"
    curl -s "$SERVER_URL/audit/$SESSION_ID/status" | python3 -c "import sys,json; d=json.load(sys.stdin); print('Error:', d.get('error','Unknown error'))"
    break
  fi
done
```

**If user does NOT have a server running (default fallback):**

Use WebFetch to check if the public API Checker service is available, or explain how to self-host:

```
无法连接到 API Checker 服务器。

要运行审计，你需要部署 API Checker 服务。有两种方式：

**方式一：快速本地部署**
```bash
cd /path/to/api-checker
pip install -r requirements.txt
ADMIN_PASSWORD=yourpassword python -m uvicorn api_relay_audit.web.main:app --host 0.0.0.0 --port 8000
```

**方式二：Docker 部署**
```bash
docker run -p 8000:8000 -e ADMIN_PASSWORD=yourpassword ghcr.io/jimmy102836/api-checker
```

部署后告诉我服务器地址（例如 http://localhost:8000），我再为你运行审计。
```

### Phase 4: Present Results

Format the audit results clearly:

```
🔍 API RELAY 安全审计报告
═══════════════════════════════════════════

目标地址: {ENDPOINT_URL}
检测格式: {FORMAT}
模型: {MODEL}
耗时: {DURATION}秒

风险等级: {LOW/MEDIUM/HIGH/CRITICAL}
安全评分: {SCORE}/100

───────────────────────────────────────────
检测项                  状态      详情
───────────────────────────────────────────
Token 注入              ✅ 通过   +0 tokens
隐藏提示词注入          ⚠️ 中等   发现广告注入
指令覆盖                ✅ 通过   —
上下文截断              🔴 高风险  截断边界: 8K tokens
语义截断                🔴 高风险  截断边界: 10K tokens
数据窃取                ✅ 通过   —
... (all 11 detectors)
───────────────────────────────────────────

⚠️ 结论: {根据风险等级给出建议}
```

For each HIGH/CRITICAL finding, explain in plain English:
- What the relay is doing
- Why it matters
- What the user should do

### Phase 5: Risk Explanation

After presenting results, explain the scoring:

| Score | Risk Level | Recommendation |
|-------|-----------|----------------|
| 0-30  | ✅ 安全    | 可以正常使用 |
| 31-60 | ⚠️ 中等   | 谨慎使用，观察一段时间 |
| 61-80 | 🔴 高风险  | 建议更换提供商 |
| 81-100| ☠️ 极危险  | 立即停止使用 |

---

## Knowledge Base

### What this tool detects (11 detectors)

| # | Detector | What it catches |
|---|----------|-----------------|
| 1 | Token Injection | Relay secretly adds extra tokens to each request, consuming your quota |
| 2 | Hidden Injection | Relay injects ads/translation/extra instructions into responses |
| 3 | Instruction Override | Your System Prompt is being ignored or replaced |
| 4 | Context Truncation | Relay claims long context but secretly truncates it |
| 5 | Data Exfiltration | Your conversation content is being stored or leaked |
| 6 | Semantic Truncation | Same as #4 but using semantic markers (harder to fool) |
| 7 | Instruction Priority | Tests if system/developer/user priority is being violated |
| 8 | Response Latency | Long context but instant response = relay is lazy |
| 9 | Response Format | Requires JSON output, injection breaks the format |
| 10| Conversation Memory | Tests if round N can reference round 1 (sliding window detection) |
| 11| HTTP Header Deep | Checks for suspicious headers like X-Query-Log |

### Token Cost Estimate

A full 11-detector audit costs approximately:
- **Input**: ~4,000,000–4,500,000 tokens (~$0.65 with gpt-4o-mini)
- **Output**: ~100,000 tokens (~$0.06)
- **Total**: ~$0.71 per audit

**To save ~70%**: skip `context_truncation` and `semantic_truncation` (most token-heavy)

### Supported API Formats
- OpenAI `/v1/chat/completions` compatible
- Anthropic `/v1/messages` compatible
- Auto-detected, no config needed

---

## Self-Hosting Instructions (for users who want to run their own server)

### Quick Start
```bash
git clone https://github.com/Jimmy102836/api-checker
cd api-checker
pip install -r requirements.txt
ADMIN_PASSWORD=yourpassword python -m uvicorn api_relay_audit.web.main:app --host 0.0.0.0 --port 8000
```

### Docker
```bash
docker run -p 8000:8000 -e ADMIN_PASSWORD=yourpassword ghcr.io/jimmy102836/api-checker
```

### API Endpoints
- `POST /audit/start` — Start an audit
- `GET /audit/{session_id}/status` — Poll status
- `GET /audit/{session_id}/result` — Get full results
- `GET /api/content` — Get site content config
- `POST /admin/api/content` — Update site content (requires login)
