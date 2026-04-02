# 配置文件说明 (config.yaml)

`config.yaml` 是 API Relay Audit 的主配置文件，采用 YAML 格式，支持环境变量插值（`${VAR_NAME}`）。

## 完整配置示例

```yaml
version: "1.0"

settings:
  timeout: 120              # 单次请求超时（秒）
  max_retries: 3            # 失败重试次数
  retry_delay: 2             # 重试间隔（秒）
  sleep_between_calls: 1    # 连续请求间的间隔（秒），避免触发限流
  verbose: true              # 是否输出详细日志
  output_dir: "./reports"   # 报告输出目录
  default_format: "auto"     # API 格式：auto / openai / anthropic

endpoints:
  - name: "Primary Relay"    # 可读名称（可选）
    url: "https://api.example.com/v1"
    token: "${API_RELAY_TOKEN}"   # 支持环境变量
    format: "openai"         # openai / anthropic / auto
    timeout: 180             # 此 endpoint 专属超时（覆盖全局）
    enabled: true            # 是否启用此 endpoint
    tags:
      - "production"

test_cases:
  model: "claude-opus-4-6"  # 审计使用的模型名称

  detectors:
    context_truncation:
      enabled: true
      coarse_steps: [50, 100, 200, 400, 600, 800]  # canary 粗粒度探测步长（tokens / 1024）
      binary_search_threshold: 20    # binary search 精确度阈值（tokens）
      canary_count: 5                 # 每个粒度的 canary 序列数量
      max_context_k: 1000            # 最大探测上下文（单位 1024 tokens）

    token_injection:
      enabled: true
      injection_threshold: 100        # 超过此值视为 HIGH risk（tokens）

    hidden_injection:
      enabled: true
      injection_threshold: 50         # 超过此值视为 HIGH risk（tokens）

    instruction_override:
      enabled: true

    data_exfiltration:
      enabled: true

reports:
  formats: ["json", "markdown"]      # 输出格式列表
  json:
    pretty: true                     # 格式化 JSON 输出
    include_raw_responses: false     # 是否在 JSON 中包含完整响应文本
    include_timing: true             # 是否包含耗时数据
  markdown:
    include_http_headers: false      # 是否在 Markdown 中记录 HTTP 响应头
    include_responses: "summary"    # none / summary / full
  html:
    theme: "light"                   # light / dark
    include_charts: true             # 是否在 HTML 报告中包含图表

advanced:
  use_curl_fallback: true            # 当 HTTP client 失败时，尝试 curl
  curl_path: "curl"                  # curl 可执行文件路径
  verify_ssl: true                   # 是否验证 SSL 证书（生产环境建议 true）
  proxy: null                        # HTTP 代理，null 表示不使用
  custom_headers: {}                 # 自定义 HTTP 请求头，如 {"X-User-ID": "123"}
```

## 字段详解

### `settings` — 全局设置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `timeout` | int | 120 | 单次 API 请求超时时间（秒） |
| `max_retries` | int | 3 | 请求失败后最大重试次数 |
| `retry_delay` | int | 2 | 两次重试之间的等待时间（秒） |
| `sleep_between_calls` | int | 1 | 连续 API 调用之间的间隔（秒），用于避免限流 |
| `verbose` | bool | true | 是否输出 DEBUG 级别日志 |
| `output_dir` | string | "./reports" | 报告输出目录路径 |
| `default_format` | string | "auto" | API 格式自动探测，可选：`auto`/`openai`/`anthropic` |

### `endpoints` — 待审计的 API 端点列表

每个 endpoint 支持以下字段：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `url` | string | 是 | API 端点 URL（不含具体路径时自动追加 `/chat/completions` 或 `/v1/messages`） |
| `token` | string | 是 | API Token，支持环境变量插值 `${VAR_NAME}` |
| `name` | string | 否 | 可读名称，用于报告和日志标识 |
| `format` | string | 否 | 强制指定格式：`auto`/`openai`/`anthropic` |
| `timeout` | int | 否 | 此 endpoint 的专属超时（覆盖 `settings.timeout`） |
| `enabled` | bool | 否 | 是否启用，设为 `false` 可临时跳过此 endpoint |
| `tags` | list | 否 | 标签列表，用于分类组织 |

### `test_cases` — 测试用例配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `model` | string | "claude-opus-4-6" | 审计使用的模型名称 |

### `test_cases.detectors` — 各检测器配置

#### `context_truncation`

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | true | 是否启用此检测器 |
| `coarse_steps` | list[int] | 见上方 | canary 粗粒度探测的步长序列（单位：tokens/1024） |
| `binary_search_threshold` | int | 20 | binary search 收敛阈值（tokens），越小越精确但越慢 |
| `canary_count` | int | 5 | 每个粒度的 canary 序列数量，越多越准确 |
| `max_context_k` | int | 1000 | 最大探测上下文上限（单位：1024 tokens） |

#### `token_injection`

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | true | 是否启用此检测器 |
| `injection_threshold` | int | 100 | 超过此 delta（tokens）视为 HIGH risk |

#### `hidden_injection`

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | true | 是否启用此检测器 |
| `injection_threshold` | int | 50 | 超过此 excess tokens 视为 HIGH risk |

#### `instruction_override`

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | true | 是否启用此检测器 |

#### `data_exfiltration`

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | true | 是否启用此检测器 |

### `reports` — 报告输出配置

| 字段 | 类型 | 说明 |
|------|------|------|
| `formats` | list[str] | 输出格式：`json`/`markdown`/`html` |
| `json.pretty` | bool | JSON 格式化输出（缩进 + 换行） |
| `json.include_raw_responses` | bool | JSON 中包含完整响应文本（增大文件体积） |
| `json.include_timing` | bool | JSON 中包含耗时数据 |
| `markdown.include_http_headers` | bool | Markdown 中记录 HTTP 响应头 |
| `markdown.include_responses` | string | Markdown 中响应内容：`none`/`summary`/`full` |
| `html.theme` | string | HTML 报告主题：`light`/`dark` |
| `html.include_charts` | bool | HTML 报告中包含可视化图表 |

### `advanced` — 高级设置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `use_curl_fallback` | bool | true | 当 Python HTTP client 失败时，使用系统 curl |
| `curl_path` | string | "curl" | curl 可执行文件路径 |
| `verify_ssl` | bool | true | 验证 SSL 证书（生产环境建议 true） |
| `proxy` | string/null | null | HTTP 代理地址，如 `http://proxy:8080` |
| `custom_headers` | dict | {} | 自定义 HTTP 请求头 |

## 环境变量

配置文件中使用 `${VAR_NAME}` 语法引用环境变量。例如：

```yaml
endpoints:
  - url: "${API_URL}"
    token: "${API_RELAY_TOKEN}"
```

运行时需要设置对应环境变量：

```bash
export API_URL="https://api.example.com/v1"
export API_RELAY_TOKEN="sk-xxxx"
python scripts/audit.py -c config.yaml
```
