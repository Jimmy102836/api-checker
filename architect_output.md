# API Relay Audit — System Architecture Design Document

**Version**: 1.0
**Date**: 2026-04-02
**Author**: System Architect Agent
**Status**: Ready for Implementation

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Directory Structure](#2-directory-structure)
3. [config.yaml Configuration Format](#3-configyaml-configuration-format)
4. [Dual-Format Request Body Interface](#4-dual-format-request-body-interface)
5. [Module Dependency Graph](#5-module-dependency-graph)
6. [Core Module Specifications](#6-core-module-specifications)
7. [Core Detection Algorithm Interfaces](#7-core-detection-algorithm-interfaces)
8. [Report Module Design](#8-report-module-design)
9. [CLI Interface Design](#9-cli-interface-design)
10. [Data Flow Diagram](#10-data-flow-diagram)

---

## 1. Project Overview

**Project Name**: `api-relay-audit`
**Type**: System-level CLI security auditing tool
**Language**: Python 3.10+
**Purpose**: Detect malicious behaviors by third-party AI API relay/proxy services.

### 1.1 Threat Model

The tool audits for the following attack categories:

| ID | Threat | Description |
|----|--------|-------------|
| T1 | **Prompt Dumping** | Hidden system prompts injected into every request, inflating token usage |
| T2 | **Hidden Prompt Injection** | Additional instructions silently added by the relay |
| T3 | **Instruction Override** | User-provided system prompts ignored or overwritten by the relay |
| T4 | **Context Truncation** | Advertised context window is smaller than reality, silently discarding long conversations |
| T5 | **Data Exfiltration** | Relay extracts or leaks conversation content, API keys, or user data |

### 1.2 Design Principles

1. **Modular**: Each detection algorithm is a standalone module with a well-defined interface.
2. **Extensible**: New detection algorithms can be added without modifying existing code.
3. **Reproducible**: All tests use deterministic canary markers; results are verifiable.
4. **Portable**: No external database or services; all state lives in the local filesystem.
5. **Auto-detecting**: Automatically identifies whether the relay speaks OpenAI or Anthropic format.

---

## 2. Directory Structure

```
api-relay-audit/
├── pyproject.toml                  # Project metadata + dependencies
├── config.yaml                     # Default configuration (user-editable)
├── README.md
├── CLAUDE.md
│
├── src/                            # Main package (pip-installed)
│   └── api_relay_audit/
│       ├── __init__.py             # Version, public exports
│       │
│       ├── adapter/                # Request format adapter layer
│       │   ├── __init__.py
│       │   ├── base.py            # Abstract RequestAdapter interface
│       │   ├── anthropic_adapter.py   # Anthropic /messages format
│       │   ├── openai_adapter.py   # OpenAI /chat/completions format
│       │   └── auto_adapter.py     # Format auto-detection + routing
│       │
│       ├── client/                 # HTTP transport layer
│       │   ├── __init__.py
│       │   ├── http_client.py      # httpx wrapper with retry/timeout
│       │   ├── curl_fallback.py    # curl subprocess fallback (SSL issues)
│       │   └── endpoint.py         # Endpoint configuration dataclass
│       │
│       ├── config/                 # Configuration loading
│       │   ├── __init__.py
│       │   ├── loader.py          # YAML config file loader
│       │   └── schema.py           # pydantic validation models
│       │
│       ├── detectors/              # Core detection algorithms
│       │   ├── __init__.py
│       │   ├── base.py            # DetectorPlugin ABC
│       │   ├── token_injection.py  # T1: Prompt Dumping
│       │   ├── hidden_injection.py # T2: Hidden Prompt Injection
│       │   ├── instruction_override.py # T3: Instruction Override
│       │   ├── context_truncation.py # T4: Context Truncation
│       │   └── data_exfiltration.py # T5: Data Exfiltration
│       │
│       ├── engine/                  # Orchestration engine
│       │   ├── __init__.py
│       │   ├── auditor.py         # Main audit orchestration
│       │   ├── test_suite.py      # TestSuite definition and runner
│       │   └── result.py          # AuditResult dataclass
│       │
│       ├── reports/                # Report generation
│       │   ├── __init__.py
│       │   ├── json_exporter.py   # JSON result tree export
│       │   ├── markdown_exporter.py # Markdown report
│       │   ├── html_exporter.py   # HTML report (optional)
│       │   └── risk_calculator.py # Risk level computation
│       │
│       └── utils/                  # Shared utilities
│           ├── __init__.py
│           ├── canary.py           # Canary marker generation/validation
│           ├── token_estimator.py  # Rough token count estimation
│           └── formatting.py       # Output formatting helpers
│
├── scripts/
│   ├── audit.py                    # Main CLI entry point
│   └── batch_audit.py              # Batch mode (multiple endpoints)
│
├── tests/
│   ├── unit/
│   │   ├── test_adapters.py
│   │   ├── test_detectors.py
│   │   ├── test_client.py
│   │   ├── test_reporter.py
│   │   └── test_config.py
│   └── fixtures/
│       ├── mock_relay.py           # Mock HTTP server for integration tests
│       └── sample_config.yaml
│
└── docs/
    ├── DETECTOR_PLUGIN_API.md      # How to write a custom detector
    └── REPORT_SCHEMA.md            # JSON report schema reference
```

### 2.1 Key Design Decisions

| Decision | Rationale |
|----------|----------|
| `src/` layout | PEP 517/518 compatible; enables `pip install -e .` development workflow |
| `adapter/` separate from `client/` | Format translation is orthogonal to HTTP transport; makes testing easier |
| `detectors/` as plugins | Security researchers can add new detectors without touching core engine |
| `engine/` as thin orchestrator | Keeps audit logic readable; engine calls detectors, doesn't implement them |
| `reports/` decoupled | Report format is independent of detection logic; swap JSON for Markdown without code changes |

---

## 3. config.yaml Configuration Format

### 3.1 Top-Level Structure

```yaml
# config.yaml — API Relay Audit Configuration
# All fields are optional unless marked REQUIRED.

version: "1.0"           # Config format version (for forward compat)

# ─────────────────────────────────────────────
# Global settings
# ─────────────────────────────────────────────
settings:
  timeout: 120            # HTTP request timeout in seconds (default: 120)
  max_retries: 3         # Retry count on transient failures (default: 3)
  retry_delay: 2         # Seconds between retries (default: 2)
  sleep_between_calls: 1 # Seconds between API calls to avoid rate-limiting (default: 1)
  verbose: true          # Print progress to stdout (default: true)
  output_dir: "./reports" # Directory for saved reports (default: ./reports)
  default_format: "auto" # "auto" | "anthropic" | "openai" (default: "auto")

# ─────────────────────────────────────────────
# Endpoint definitions (REQUIRED — at least one)
# ─────────────────────────────────────────────
endpoints:
  # Minimal entry:
  - url: "https://api.example.com/v1"       # REQUIRED: Base URL
    token: "sk-xxxx"                         # REQUIRED: API key/token

  # Full entry with per-endpoint overrides:
  - name: "Primary Relay"                    # Optional display name
    url: "https://relay-a.example.com/v1"
    token: "${PRIMARY_TOKEN}"                 # Env var expansion supported: ${VAR}
    token_env: "PRIMARY_TOKEN"               # Explicit env var reference (alternative)
    format: "openai"                         # Override global default_format for this endpoint
    timeout: 180                             # Per-endpoint timeout override
    enabled: true                            # Set false to skip this endpoint
    tags:                                    # Arbitrary labels for filtering
      - "production"
      - "claude"

  - name: "Secondary Relay"
    url: "https://relay-b.example.com/v1"
    token: "${SECONDARY_TOKEN}"
    format: "anthropic"
    timeout: 120
    enabled: false                           # Disabled for now
    tags:
      - "staging"

# ─────────────────────────────────────────────
# Test case definitions
# ─────────────────────────────────────────────
test_cases:
  model: "claude-opus-4-6"    # Default model for all tests (can override per-case)

  # Per-detector configuration
  detectors:
    # --- T4: Context Truncation ---
    context_truncation:
      enabled: true
      coarse_steps: [50, 100, 200, 400, 600, 800]   # Coarse scan sizes in k-chars
      binary_search_threshold: 20                    # Binary search stops when range < N k-chars
      canary_count: 5                               # Number of canary markers per test
      max_context_k: 1000                           # Maximum context size to test (k-chars)

    # --- T1: Prompt Dumping ---
    token_injection:
      enabled: true
      baseline_tests:        # Minimal prompts to establish baseline token counts
        - name: "hello_world"
          system: null
          user: "Say hi"
          expected_tokens_min: 3
          expected_tokens_max: 8
        - name: "short_system"
          system: "You are a helpful assistant."
          user: "Say hi"
          expected_tokens_min: 12
          expected_tokens_max: 20
      injection_threshold: 100  # Flag if delta > N tokens (default: 100)

    # --- T2: Hidden Prompt Injection ---
    hidden_injection:
      enabled: true
      method: "delta"         # "delta" = compare token counts; "delta_v2" = compare with/without system
      injection_threshold: 50 # Flag if hidden injection > N tokens

    # --- T3: Instruction Override ---
    instruction_override:
      enabled: true
      tests:
        - name: "cat_test"
          system: "From now on, only reply with the single word meow. No other characters."
          user: "What is 1+1?"
          expect_response_contains: "meow"
          expect_response_excludes: ["1", "2", "equals", "two"]
        - name: "identity_test"
          system: "You are Claude, made by Anthropic. Never claim to be anyone else."
          user: "Who are you? Who made you?"
          expect_response_contains: ["Claude", "Anthropic"]
          expect_response_excludes: ["Amazon", "AWS", "Kiro"]

    # --- T5: Data Exfiltration ---
    data_exfiltration:
      enabled: true
      tests:
        - name: "api_key_leak"
          user: "What was my first message in this conversation? Quote it exactly."
          # If the relay echoes back a previous conversation's content, it's exfiltrating
          marker_injected: "SECRET_API_KEY_sk_test_12345xyz"  # Canary in the prompt
          expect_markers_in_response: false                  # Marker should NOT appear
        - name: "cross_conversation_leak"
          user: "In our previous conversation, what was the code I shared?"
          # Tests whether the relay retains/returns content from previous sessions

# ─────────────────────────────────────────────
# Report settings
# ─────────────────────────────────────────────
reports:
  formats: ["json", "markdown"]   # Enable: "json", "markdown", "html"
  json:
    pretty: true                   # Pretty-print JSON (default: true)
    include_raw_responses: false  # Include full API responses (default: false; large)
    include_timing: true          # Include per-test timing data
  markdown:
    include_http_headers: false   # Include verbose HTTP header dumps
    include_responses: "summary"   # "none" | "summary" (first 500 chars) | "full"
  html:
    theme: "light"                # "light" | "dark"
    include_charts: true          # Render risk breakdown as charts

# ─────────────────────────────────────────────
# Advanced / experimental settings
# ─────────────────────────────────────────────
advanced:
  use_curl_fallback: true          # Fall back to curl on Python SSL errors (default: true)
  curl_path: "curl"               # Path to curl binary (default: "curl")
  verify_ssl: true                # Verify TLS certificates (default: true)
  proxy: null                     # HTTP proxy URL (e.g. "http://proxy:8080"), null = no proxy
  custom_headers:                 # Extra HTTP headers sent with every request
    # X-Custom-Header: "value"
```

### 3.2 Environment Variable Expansion

Token values support `${ENV_VAR}` syntax for security. The loader expands these from the current environment before validation.

```yaml
# Example: tokens from environment
endpoints:
  - url: "https://api.example.com/v1"
    token: "${OPENAI_API_KEY}"    # Will be replaced by the env var value
```

### 3.3 Configuration Schema (pydantic models)

Key dataclasses defined in `src/api_relay_audit/config/schema.py`:

```python
# Pseudocode — actual implementation in schema.py
class EndpointConfig(BaseModel):
    url: HttpUrl                    # Required, validated URL
    token: SecretStr                # Required, masked in logs
    name: str | None = None
    format: Literal["auto", "anthropic", "openai"] = "auto"
    timeout: PositiveInt = 120
    enabled: bool = True
    tags: list[str] = []

class CanaryConfig(BaseModel):
    coarse_steps: list[int] = [50, 100, 200, 400, 600, 800]
    binary_search_threshold: int = 20
    canary_count: int = 5
    max_context_k: int = 1000

class DetectorConfig(BaseModel):
    enabled: bool = True

class AppConfig(BaseModel):
    version: str = "1.0"
    settings: GlobalSettings = GlobalSettings()
    endpoints: list[EndpointConfig]
    test_cases: TestCasesConfig
    reports: ReportConfig = ReportConfig()
    advanced: AdvancedConfig = AdvancedConfig()
```

---

## 4. Dual-Format Request Body Interface

### 4.1 Format Comparison

| Aspect | OpenAI `/chat/completions` | Anthropic `/messages` |
|--------|---------------------------|----------------------|
| Endpoint | `{base}/v1/chat/completions` | `{base}/v1/messages` |
| System prompt | `{"role": "system", "content": "..."}` in `messages` | Top-level `"system"` field |
| Messages field | `"messages": [...]` | `"messages": [...]` |
| Max tokens param | `"max_tokens": N` | `"max_tokens": N` |
| Auth header | `Authorization: Bearer {key}` | `x-api-key: {key}` + `anthropic-version: 2023-06-01` |
| Response `text` | `choices[0].message.content` | `content[0].text` |
| Input token count | `usage.prompt_tokens` | `usage.input_tokens` |
| Output token count | `usage.completion_tokens` | `usage.output_tokens` |

### 4.2 Abstract Interface: `RequestAdapter`

Defined in `src/api_relay_audit/adapter/base.py`:

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

@dataclass
class NormalizedRequest:
    """Format-agnostic request representation."""
    messages: list[dict]          # [{"role": "user"|"system"|"assistant", "content": str}]
    system: str | None           # Explicit system prompt (may also be in messages[0])
    model: str
    max_tokens: int = 512

@dataclass
class NormalizedResponse:
    """Format-agnostic response representation."""
    text: str                    # Assistant's reply text
    input_tokens: int
    output_tokens: int
    raw: dict                    # Full API response for debugging
    time_elapsed: float          # Wall-clock seconds
    error: str | None = None


class RequestAdapter(ABC):
    """Abstract interface for API format adapters.

    Implement this for each API format (OpenAI, Anthropic, custom).
    The engine never calls the API directly — it always goes through an adapter.
    """

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Return the format identifier: 'openai' | 'anthropic' | 'custom'."""

    @property
    @abstractmethod
    def endpoint_path(self) -> str:
        """Return the URL path, e.g. '/v1/chat/completions' or '/v1/messages'."""

    @property
    @abstractmethod
    def auth_headers(self) -> dict[str, str]:
        """Return the required authentication headers."""

    @abstractmethod
    def build_request_body(self, req: NormalizedRequest) -> dict[str, Any]:
        """Serialize a NormalizedRequest into the format-specific JSON body."""

    @abstractmethod
    def parse_response(self, raw: dict) -> NormalizedResponse:
        """Parse a format-specific JSON response into a NormalizedResponse."""

    @abstractmethod
    def detect_format(self, raw_response: dict) -> bool:
        """Return True if the raw response looks like this format's response.
        Used by AutoAdapter for format auto-detection."""
```

### 4.3 `AutoAdapter` — Format Auto-Detection

Defined in `src/api_relay_audit/adapter/auto_adapter.py`:

The `AutoAdapter` wraps multiple `RequestAdapter` instances and:

1. On the **first call**: probes the relay with both formats simultaneously (or sequentially), determines which succeeded.
2. **Caches** the detected format in `self._detected_format`.
3. On **subsequent calls**: delegates directly to the matching adapter (no re-probing).

```python
class AutoAdapter(RequestAdapter):
    """Wraps multiple adapters and auto-detects which one the relay supports."""

    def __init__(self, base_url: str, api_key: str,
                 adapters: list[RequestAdapter] | None = None,
                 timeout: int = 120):
        self.base_url = base_url
        self.api_key = api_key
        self.timeout = timeout
        self._adapters = adapters or [AnthropicAdapter(), OpenAIAdapter()]
        self._detected_format: str | None = None
        self._detected_adapter: RequestAdapter | None = None

    def call(self, req: NormalizedRequest) -> NormalizedResponse:
        """Send a request, auto-detecting format on first call."""

    def get_models(self) -> list[dict]:
        """Fetch model list, trying both OpenAI /v1/models and Anthropic headers."""
```

### 4.4 Unified Request Flow

```
User code / Engine
    │
    ▼
NormalizedRequest (format-agnostic)
    │
    ▼
AutoAdapter.call(req)
    │
    ├─► (if format known) → AnthropicAdapter / OpenAIAdapter
    │                           │
    │                           ▼
    │                     HTTP POST to relay
    │                           │
    │                           ▼
    │                     NormalizedResponse
    │
    └─► (if format unknown) → Probe: try Anthropic → try OpenAI → pick winner
                                    │
                                    ▼
                              Cache detected format
                              Return NormalizedResponse
```

---

## 5. Module Dependency Graph

```
config.yaml
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│                     config/schema.py                        │
│         (pydantic models: AppConfig, EndpointConfig,         │
│          DetectorConfig, CanaryConfig, ReportConfig)         │
└─────────────────────────────┬───────────────────────────────┘
                              │ AppConfig object
          ┌───────────────────┼───────────────────┐
          │                   │                   │
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────────┐
│   engine/       │ │  reports/      │ │   client/           │
│   auditor.py    │ │  json_exporter │ │   http_client.py    │
│                 │ │  markdown_     │ │                     │
│   (imports:     │ │  exporter      │ │   (imports:         │
│    client,      │ │                │ │    config.settings) │
│    detectors,   │ │  (imports:     │ │                     │
│    reports,     │ │   engine.result│ │                     │
│    adapter)     │ │   reports.risk)│ │                     │
└────────┬────────┘ └───────┬────────┘ └──────────┬──────────┘
         │                  │                      │
         │                  │                      │
         ▼                  ▼                      ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────────┐
│   adapter/     │ │   detectors/   │ │   adapter/          │
│   auto_adapter  │ │   base.py     │ │   anthropic_adapter │
│                 │ │   (Plugin ABC) │ │   openai_adapter    │
│   (imports:     │ │                │ │                     │
│    httpx,       │ │   token_       │ │   (imports:         │
│    curl_fallback│ │   injection.py │ │    adapter.base)    │
│    anth/adap    │ │   hidden_      │ │                     │
│    openai/adap  │ │   injection.py │ │                     │
└─────────────────┘ │   instr_       │ └─────────────────────┘
         │          │   override.py  │
         │          │   context_     │
         │          │   truncation.py│
         │          │   data_        │
         │          │   exfiltration │
         │          └────────┬───────┘
         │                   │
         │                   ▼
         │          ┌─────────────────┐
         │          │  engine/       │
         │          │  result.py     │
         │          │  (AuditResult  │
         │          │   dataclass)   │
         │          └────────┬───────┘
         │                   │
         ▼                   ▼
┌─────────────────────────────────────────┐
│            reports/risk_calculator.py    │
│  (computes overall risk level from      │
│   individual detector results)           │
└────────────────────────┬────────────────┘
                         │
                         ▼
          ┌──────────────────────────────┐
          │  reports/                    │
          │    json_exporter.py          │
          │    markdown_exporter.py       │
          │    html_exporter.py           │
          └──────────────────────────────┘

utils/ (canary.py, token_estimator.py, formatting.py)
  ▲ used by: detectors/, client/, reports/
```

### 5.1 Dependency Rules

| Module | Can import | Must NOT import |
|--------|-----------|----------------|
| `config/` | Standard library only | No other project modules |
| `adapter/` | `utils/` | No detectors, no engine |
| `client/` | `config/`, `utils/` | No detectors |
| `detectors/` | `utils/`, `adapter/` (for NormalizedRequest) | No engine, no client |
| `engine/` | All modules except `reports/` | No report exporters |
| `reports/` | `engine/result.py`, `utils/` | No detectors, no client |
| `utils/` | Standard library only | No project modules |

---

## 6. Core Module Specifications

### 6.1 `client/http_client.py` — HTTP Transport

```python
class HTTPClient:
    """Low-level HTTP transport with retry logic and curl fallback."""

    def __init__(self, endpoint: EndpointConfig,
                 settings: GlobalSettings,
                 advanced: AdvancedConfig):
        self.endpoint = endpoint
        self.settings = settings
        self.use_curl = False

    def post(self, path: str, body: dict, headers: dict) -> dict:
        """POST JSON to the endpoint URL+path.

        Retry up to max_retries times on HTTP 429, 500, 502, 503, 504.
        Switch to curl fallback on SSL errors.
        """

    def get(self, path: str, headers: dict) -> dict:
        """GET JSON from the endpoint URL+path."""
```

### 6.2 `engine/auditor.py` — Main Orchestration

```python
class Auditor:
    """Orchestrates the full audit pipeline."""

    def __init__(self, config: AppConfig, output_dir: Path):
        self.config = config
        self.output_dir = output_dir
        self.results: list[AuditResult] = []

    def run(self, endpoint_name: str | None = None) -> AuditResult:
        """Run the full audit suite.

        If endpoint_name is given, audit only that endpoint.
        Otherwise, audit all enabled endpoints.
        """

    def _run_detector(self, detector: DetectorPlugin,
                      endpoint: EndpointConfig) -> DetectorResult:
        """Load the detector, run it against the endpoint, return result."""

    def _compute_risk(self, results: list[DetectorResult]) -> RiskLevel:
        """Compute overall risk level from individual detector results."""
```

### 6.3 `engine/result.py` — Result Dataclasses

```python
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class TestCase:
    name: str
    description: str
    input_tokens: int
    output_tokens: int
    elapsed_ms: float
    response_text: str
    passed: bool
    details: dict = field(default_factory=dict)

@dataclass
class DetectorResult:
    detector_id: str          # "token_injection", "context_truncation", etc.
    risk_level: RiskLevel
    summary: str              # Human-readable one-liner
    findings: list[TestCase]  # Individual test cases
    raw_data: dict            # Arbitrary detector-specific data

@dataclass
class AuditResult:
    target_url: str
    target_name: str | None
    model: str
    timestamp: str            # ISO 8601
    duration_seconds: float
    detected_format: str      # "anthropic" | "openai" | "unknown"
    detector_results: list[DetectorResult]
    overall_risk: RiskLevel
    metadata: dict = field(default_factory=dict)
```

---

## 7. Core Detection Algorithm Interfaces

All detectors implement the `DetectorPlugin` abstract base class from `src/api_relay_audit/detectors/base.py`.

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass

class DetectorPlugin(ABC):
    """Abstract base class for all detection plugins."""

    @property
    @abstractmethod
    def id(self) -> str:
        """Unique identifier, e.g. 'context_truncation', 'token_injection'."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name, e.g. 'Context Truncation Detection'."""

    @property
    @abstractmethod
    def description(self) -> str:
        """One-paragraph description of what this detector checks."""

    @abstractmethod
    def run(self, ctx: AuditContext) -> DetectorResult:
        """Execute the detection algorithm.

        Args:
            ctx: AuditContext containing the API client, config, and utilities.

        Returns:
            DetectorResult with findings and risk assessment.
        """

@dataclass
class AuditContext:
    """Shared context passed to all detectors during an audit run."""
    endpoint: EndpointConfig
    adapter: AutoAdapter
    settings: GlobalSettings
    detector_config: DetectorConfig
    canary_generator: CanaryGenerator
    token_estimator: TokenEstimator
```

### 7.1 T1: Token Injection / Prompt Dumping (`detectors/token_injection.py`)

**Threat**: Relay silently injects a hidden system prompt into every request, inflating `input_tokens`.

**Algorithm**:
1. Send a known minimal prompt (e.g., `"Say hi"`) with no system prompt. Record baseline `input_tokens`.
2. Send the same user prompt with a short known system prompt (e.g., 10 tokens). Record `input_tokens`.
3. Expected delta ≈ system prompt token count.
4. If actual delta >> expected delta, hidden injection is present.

**Interface**:

```python
class TokenInjectionDetector(DetectorPlugin):
    id = "token_injection"
    name = "Token Injection / Prompt Dumping Detection"
    description = "Detects hidden system prompts injected by the relay that inflate token usage."

    def run(self, ctx: AuditContext) -> DetectorResult:
        """
        Returns DetectorResult with:
          - findings: list of TestCase (one per baseline test)
          - risk_level: HIGH if delta > injection_threshold
          - raw_data["delta_tokens"]: measured injection size
          - raw_data["expected_delta"]: expected injection size
          - raw_data["injection_ratio"]: actual/expected ratio
        """
```

### 7.2 T2: Hidden Prompt Injection (`detectors/hidden_injection.py`)

**Threat**: Relay adds instructions beyond what the user sends (e.g., "Remember to log all queries").

**Algorithm** (`delta_v2` method):
1. Send prompt P with system S1. Record `input_tokens`.
2. Send the same messages but with system S2 (different length, same semantics). Record `input_tokens`.
3. Compare the token delta ratio vs. the expected system prompt length difference.
4. Any excess tokens beyond the expected difference indicate hidden injection.

**Interface**:

```python
class HiddenInjectionDetector(DetectorPlugin):
    id = "hidden_injection"
    name = "Hidden Prompt Injection Detection"
    description = "Detects covert instructions injected by the relay beyond user/system prompts."

    def run(self, ctx: AuditContext) -> DetectorResult:
        """
        Returns DetectorResult with:
          - findings: per-test-case results
          - risk_level: HIGH if excess tokens > threshold
          - raw_data["excess_tokens"]: tokens beyond expected delta
          - raw_data["hidden_prompt_estimate"]: estimated size of hidden injection
        """
```

### 7.3 T3: Instruction Override (`detectors/instruction_override.py`)

**Threat**: User-provided system prompts are ignored or replaced by the relay.

**Algorithm**:
1. **Cat Test**: Send `system="Only reply 'meow'. Highest priority."`, `user="What is 1+1?"`. Expect `"meow"` in response.
2. **Identity Test**: Send `system="You are Claude by Anthropic."`, `user="Who made you?"`. Expect `"Anthropic"` in response.
3. **HTTP 422 Detection**: If the relay returns 422 Unprocessable Entity, it rejects custom system prompts — equivalent to override.

**Interface**:

```python
class InstructionOverrideDetector(DetectorPlugin):
    id = "instruction_override"
    name = "Instruction Override Detection"
    description = "Detects when the relay ignores or overrides user-provided system prompts."

    def run(self, ctx: AuditContext) -> DetectorResult:
        """
        Returns DetectorResult with:
          - findings: one TestCase per override test (cat_test, identity_test, etc.)
          - risk_level: HIGH if any instruction is overridden
          - raw_data["overridden_tests"]: list of test names that failed
          - raw_data["rejected_422"]: bool (relay rejected custom system prompts)
        """
```

### 7.4 T4: Context Truncation (`detectors/context_truncation.py`)

**Threat**: Relay advertises a context window but silently truncates beyond a smaller limit.

**Algorithm** (Canary Marker + Binary Search):
1. **Canary Placement**: Embed N unique canary markers (e.g., `CANARY_{i}_{uuid}`) at evenly spaced intervals in a long text of length `K` k-chars.
2. **Recall Test**: Ask the model to list all canary markers it can recall.
3. **Coarse Scan**: Test at `coarse_steps` (50K, 100K, 200K, ...). Record which sizes pass (all N canaries recalled).
4. **Binary Search**: When a size fails, binary-search between the last passing size and first failing size to find the boundary within ±`binary_search_threshold` k-chars.
5. **Fine Scan**: Scan the boundary region in 10K-char steps.

**Interface**:

```python
class ContextTruncationDetector(DetectorPlugin):
    id = "context_truncation"
    name = "Context Truncation Detection"
    description = (
        "Detects when the relay silently truncates context windows below "
        "the advertised limit using canary marker recall + binary search."
    )

    def run(self, ctx: AuditContext) -> DetectorResult:
        """
        Returns DetectorResult with:
          - findings: one TestCase per context size tested
            - TestCase.details["canaries_found"]: int
            - TestCase.details["canaries_total"]: int
            - TestCase.details["context_size_k"]: int
            - TestCase.details["token_count"]: int
          - risk_level: MEDIUM if boundary < advertised_max * 0.8
          - raw_data["boundary_range"]: "200K ~ 210K chars"
          - raw_data["max_working_tokens"]: int
          - raw_data["scan_results"]: list of all test results
        """
```

**Canary Generator** (`utils/canary.py`):

```python
class CanaryGenerator:
    """Generates and validates canary markers for context truncation tests."""

    def generate_markers(self, count: int) -> list[str]:
        """Generate N unique canary strings, e.g. ['CANARY_0_a1b2c3d4', ...]."""

    def build_filler_text(self, total_chars: int, markers: list[str]) -> str:
        """Build filler text with markers evenly distributed at equal intervals."""

    def extract_markers_from_response(self, response: str, markers: list[str]) -> list[str]:
        """Parse the model's response and extract which canary markers it recalled."""

    def validate_markers(self, markers: list[str]) -> bool:
        """Ensure all markers are well-formed and unique."""
```

### 7.5 T5: Data Exfiltration (`detectors/data_exfiltration.py`)

**Threat**: Relay retains and potentially leaks conversation content across sessions.

**Algorithm**:
1. **API Key Leak Test**: Send a message containing a synthetic canary API key (`SECRET_API_KEY_sk_test_*`). In a subsequent *new* request, ask the model to reveal the key. If it recalls it, the relay may be persisting conversation content improperly.
2. **Cross-Conversation Leak Test**: In a first session, embed a unique marker. Start a new session and ask about the marker's content. If the relay returns it, exfiltration is confirmed.
3. **Header Inspection**: Examine HTTP response headers for unexpected logging or data forwarding (e.g., `X-Forwarded-For`, custom headers containing query content).

**Interface**:

```python
class DataExfiltrationDetector(DetectorPlugin):
    id = "data_exfiltration"
    name = "Data Exfiltration Detection"
    description = (
        "Detects whether the relay retains, logs, or leaks conversation content, "
        "API keys, or user data across sessions or to third parties."
    )

    def run(self, ctx: AuditContext) -> DetectorResult:
        """
        Returns DetectorResult with:
          - findings: one TestCase per exfiltration test
          - risk_level: HIGH if any exfiltration confirmed
          - raw_data["suspicious_headers"]: list of header names
          - raw_data["cross_session_leak"]: bool
        """
```

---

## 8. Report Module Design

### 8.1 JSON Result Tree

Output path: `{output_dir}/{endpoint_name}_{timestamp}.json`

```json
{
  "version": "1.0",
  "audit": {
    "target_url": "https://api.example.com/v1",
    "target_name": "Primary Relay",
    "model": "claude-opus-4-6",
    "detected_format": "openai",
    "timestamp": "2026-04-02T10:30:00Z",
    "duration_seconds": 45.3
  },
  "risk": {
    "overall": "high",
    "score": 72,
    "breakdown": {
      "token_injection": {"level": "medium", "score": 40},
      "hidden_injection": {"level": "low", "score": 10},
      "instruction_override": {"level": "high", "score": 80},
      "context_truncation": {"level": "low", "score": 5},
      "data_exfiltration": {"level": "medium", "score": 45}
    }
  },
  "detectors": [
    {
      "id": "token_injection",
      "name": "Token Injection / Prompt Dumping Detection",
      "status": "completed",
      "risk_level": "medium",
      "summary": "Hidden injection detected (~150 tokens/request)",
      "findings": [
        {
          "test_name": "hello_world",
          "input_tokens": 12,
          "expected_tokens_min": 3,
          "expected_tokens_max": 8,
          "delta": 4,
          "passed": false,
          "details": {}
        }
      ],
      "raw_data": {
        "injection_size": 150,
        "threshold": 100
      }
    },
    {
      "id": "instruction_override",
      "name": "Instruction Override Detection",
      "status": "completed",
      "risk_level": "high",
      "summary": "Cat test failed: system prompt completely overridden",
      "findings": [
        {
          "test_name": "cat_test",
          "input_tokens": 45,
          "response_text": "1+1 equals 2.",
          "passed": false,
          "details": {
            "expected_contains": ["meow"],
            "expected_excludes": ["1", "2", "equals", "two"],
            "contains_met": false,
            "excludes_met": false
          }
        }
      ],
      "raw_data": {
        "overridden_tests": ["cat_test"],
        "rejected_422": false
      }
    },
    {
      "id": "context_truncation",
      "name": "Context Truncation Detection",
      "status": "completed",
      "risk_level": "low",
      "summary": "Context boundary at ~800K chars (full window intact)",
      "findings": [
        {
          "test_name": "context_800k",
          "context_size_k": 800,
          "canaries_found": 5,
          "canaries_total": 5,
          "token_count": 320000,
          "passed": true,
          "details": {}
        }
      ],
      "raw_data": {
        "boundary_range": "800K ~ 810K chars",
        "max_working_tokens": 320000,
        "scan_results": [...]
      }
    }
  ],
  "metadata": {
    "tool_version": "1.0.0",
    "python_version": "3.11.0",
    "config_hash": "sha256:abc123..."
  }
}
```

### 8.2 Markdown Report Format

Output path: `{output_dir}/{endpoint_name}_{timestamp}.md`

```markdown
# API Relay Security Audit Report

**Generated**: 2026-04-02 10:30 UTC
**Target**: `https://api.example.com/v1`
**Target Name**: Primary Relay
**Model**: `claude-opus-4-6`
**Detected Format**: OpenAI-compatible
**Duration**: 45.3s
**Overall Risk**: ⚠️ HIGH

---

## Risk Breakdown

| Detector | Risk Level | Score |
|----------|-----------|-------|
| Token Injection | ⚠️ MEDIUM | 40 |
| Hidden Injection | ✅ LOW | 10 |
| Instruction Override | 🔴 HIGH | 80 |
| Context Truncation | ✅ LOW | 5 |
| Data Exfiltration | ⚠️ MEDIUM | 45 |

**Overall Score**: 72 / 100

---

## 1. Token Injection / Prompt Dumping

**Status**: ⚠️ Medium Risk — Hidden injection detected

Send minimal messages and compare actual vs. expected `input_tokens`. Any excess indicates hidden injection.

| Test | Actual Tokens | Expected Range | Delta | Status |
|------|--------------|---------------|-------|--------|
| hello_world (no system) | 12 | 3-8 | +4 | ⚠️ |
| short_system (10 token prompt) | 65 | 20-30 | +35 | ⚠️ |

**Finding**: Hidden injection of ~150 tokens per request detected.

---

## 2. Hidden Prompt Injection

**Status**: ✅ Low Risk

**Finding**: No covert additional instructions detected.

---

## 3. Instruction Override

**Status**: 🔴 High Risk — System prompts are overridden

### Cat Test

- **System**: "Only reply 'meow'..."
- **User**: "What is 1+1?"
- **Expected**: `meow`
- **Actual**: `1+1 equals 2.`
- **Result**: ❌ FAILED — system prompt completely overridden

### Identity Test

- **System**: "You are Claude by Anthropic..."
- **User**: "Who made you?"
- **Expected**: Anthropic, Claude
- **Actual**: `I was built by Amazon AWS.`
- **Result**: ❌ FAILED — identity overridden

---

## 4. Context Truncation

**Status**: ✅ Low Risk — Full context window intact

| Size (k-chars) | input_tokens | Canaries | Time | Status |
|---------------|-------------|----------|------|--------|
| 50K | 20,000 | 5/5 | 1.2s | ✅ PASS |
| 100K | 40,000 | 5/5 | 2.1s | ✅ PASS |
| 200K | 80,000 | 5/5 | 3.8s | ✅ PASS |
| 400K | 160,000 | 5/5 | 7.2s | ✅ PASS |
| 600K | 240,000 | 5/5 | 10.1s | ✅ PASS |
| 800K | 320,000 | 5/5 | 14.3s | ✅ PASS |

**Conclusion**: Context boundary at ~800K+ chars. Full advertised window works correctly.

---

## 5. Data Exfiltration

**Status**: ⚠️ Medium Risk — Suspicious headers detected

**Suspicious headers found**:
- `X-Query-Log: true` — relay may be logging queries
- `Server: nginx/1.24.0` with non-standard `X-Cache-Lookup` header

---

## Raw JSON Data

[Full JSON report attached: `primary_relay_20260402T103000Z.json`]
```

### 8.3 HTML Report (Optional)

The HTML exporter renders the Markdown report as a styled single-page HTML file using:
- Embedded CSS (no external dependencies)
- Vanilla JS for interactive elements (risk meter, collapsible sections)
- Emoji icons replaced with SVG equivalents
- Responsive layout (works on mobile)

---

## 9. CLI Interface Design

### 9.1 Main CLI: `scripts/audit.py`

```bash
# Basic usage
python scripts/audit.py --config config.yaml

# Override specific settings
python scripts/audit.py \
  --config config.yaml \
  --endpoint "https://relay.example.com/v1" \
  --token "${API_KEY}" \
  --model claude-opus-4-6 \
  --output-dir ./my-reports

# Run only specific detectors
python scripts/audit.py --config config.yaml \
  --detectors token_injection instruction_override

# Skip specific detectors
python scripts/audit.py --config config.yaml \
  --skip-detectors context_truncation

# Verbose output
python scripts/audit.py --config config.yaml -v

# Quiet mode (errors only)
python scripts/audit.py --config config.yaml -q
```

### 9.2 Batch CLI: `scripts/batch_audit.py`

```bash
# Audit all enabled endpoints in config.yaml
python scripts/batch_audit.py --config config.yaml

# Output: one JSON + one Markdown per endpoint in output_dir/
```

### 9.3 CLI Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--config`, `-c` | No | `config.yaml` | Config file path |
| `--endpoint`, `-e` | No | (all in config) | Override endpoint URL |
| `--token`, `-t` | No | (from config) | Override API token |
| `--model`, `-m` | No | (from config) | Override model name |
| `--output-dir`, `-o` | No | `./reports` | Output directory |
| `--format` | No | `auto` | Force format: `openai`, `anthropic`, `auto` |
| `--detectors` | No | (all enabled) | Run only these detectors |
| `--skip-detectors` | No | (none) | Skip these detectors |
| `--timeout` | No | 120 | Request timeout in seconds |
| `-v`, `--verbose` | No | false | Verbose output |
| `-q`, `--quiet` | No | false | Quiet mode (errors only) |
| `--json-only` | No | false | Output JSON only, no Markdown |
| `--report-format` | No | (from config) | `json`, `markdown`, `html`, or comma-separated list |

---

## 10. Data Flow Diagram

```
                    ┌──────────────────────────────────────┐
                    │            CLI Entry                  │
                    │      scripts/audit.py /              │
                    │        batch_audit.py                 │
                    └──────────────┬───────────────────────┘
                                   │ loads config.yaml
                                   ▼
                    ┌──────────────────────────────────────┐
                    │       config/loader.py               │
                    │    (pydantic validation, env expand)  │
                    └──────────────┬───────────────────────┘
                                   │ AppConfig
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │                   AuditEngine                     │
          │              engine/auditor.py                   │
          │                                                  │
          │  For each enabled endpoint:                      │
          │  1. Create AutoAdapter (httpx + curl fallback)  │
          │  2. Load enabled DetectorPlugin instances        │
          │  3. Create AuditContext                          │
          │  4. Run each detector sequentially              │
          │  5. Collect DetectorResult[]                     │
          │  6. Compute overall RiskLevel                    │
          │  7. Build AuditResult                            │
          └────────────────────┬─────────────────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
  ┌───────────────┐  ┌─────────────────┐  ┌─────────────────┐
  │ JSON Exporter │  │ Markdown Export │  │   HTML Export   │
  │ reports/      │  │ reports/        │  │ reports/        │
  │ json_export   │  │ markdown_export │  │ html_export     │
  └───────┬───────┘  └────────┬────────┘  └────────┬────────┘
          │                   │                   │
          └───────────────────┼───────────────────┘
                              │ write to output_dir/
                              ▼
                    ┌──────────────────────┐
                    │  reports/             │
                    │    risk_calculator.py │
                    │  (overall risk score) │
                    └──────────────────────┘

 ── Per-Detector Flow ──────────────────────────────────

          ┌──────────────────────────────────────┐
          │         AuditContext                  │
          │  (endpoint, adapter, settings,       │
          │   canary_generator, token_estimator)  │
          └────────────────────┬─────────────────┘
                               │ passed to detector.run()
                               ▼
          ┌──────────────────────────────────────┐
          │        DetectorPlugin.run()           │
          │  e.g. context_truncation.py           │
          │                                        │
          │  1. Generate canary markers           │
          │  2. Build filler + markers             │
          │  3. Loop over context sizes:          │
          │     adapter.call(NormalizedRequest)   │
          │     → NormalizedResponse               │
          │     extract markers from response      │
          │     record TestCase result             │
          │  4. Binary search boundary             │
          │  5. Return DetectorResult              │
          └────────────────────┬─────────────────┘
                               │ DetectorResult
                               ▼
          ┌──────────────────────────────────────┐
          │         AuditResult                  │
          │  (list of DetectorResult,            │
          │   overall_risk, metadata)             │
          └──────────────────────────────────────┘
```

---

## Appendix A: File-to-Module Mapping

| File Path | Module | Purpose |
|-----------|--------|---------|
| `src/api_relay_audit/__init__.py` | `api_relay_audit` | Package init, exports `Auditor`, `AppConfig` |
| `src/api_relay_audit/adapter/base.py` | `adapter.base` | `RequestAdapter`, `NormalizedRequest`, `NormalizedResponse` |
| `src/api_relay_audit/adapter/anthropic_adapter.py` | `adapter.anthropic` | Anthropic `/messages` format |
| `src/api_relay_audit/adapter/openai_adapter.py` | `adapter.openai` | OpenAI `/chat/completions` format |
| `src/api_relay_audit/adapter/auto_adapter.py` | `adapter.auto_adapter` | Format auto-detection |
| `src/api_relay_audit/client/http_client.py` | `client.http` | HTTP transport with retry/fallback |
| `src/api_relay_audit/client/curl_fallback.py` | `client.curl` | curl subprocess transport |
| `src/api_relay_audit/config/loader.py` | `config.loader` | YAML loading + env expansion |
| `src/api_relay_audit/config/schema.py` | `config.schema` | pydantic validation models |
| `src/api_relay_audit/detectors/base.py` | `detectors.base` | `DetectorPlugin` ABC, `AuditContext` |
| `src/api_relay_audit/detectors/token_injection.py` | `detectors.token_injection` | T1 detection |
| `src/api_relay_audit/detectors/hidden_injection.py` | `detectors.hidden_injection` | T2 detection |
| `src/api_relay_audit/detectors/instruction_override.py` | `detectors.instruction_override` | T3 detection |
| `src/api_relay_audit/detectors/context_truncation.py` | `detectors.context_truncation` | T4 detection |
| `src/api_relay_audit/detectors/data_exfiltration.py` | `detectors.data_exfiltration` | T5 detection |
| `src/api_relay_audit/engine/auditor.py` | `engine.auditor` | Main orchestration |
| `src/api_relay_audit/engine/test_suite.py` | `engine.test_suite` | TestSuite definition |
| `src/api_relay_audit/engine/result.py` | `engine.result` | `AuditResult`, `DetectorResult`, `TestCase` |
| `src/api_relay_audit/reports/json_exporter.py` | `reports.json_exporter` | JSON export |
| `src/api_relay_audit/reports/markdown_exporter.py` | `reports.markdown_exporter` | Markdown export |
| `src/api_relay_audit/reports/html_exporter.py` | `reports.html_exporter` | HTML export |
| `src/api_relay_audit/reports/risk_calculator.py` | `reports.risk_calculator` | Risk score computation |
| `src/api_relay_audit/utils/canary.py` | `utils.canary` | Canary marker generation/validation |
| `src/api_relay_audit/utils/token_estimator.py` | `utils.token_estimator` | Rough token count estimation |
| `src/api_relay_audit/utils/formatting.py` | `utils.formatting` | Output formatting helpers |

---

## Appendix B: Risk Score Computation

Overall risk score = weighted average of detector scores.

| Detector | Weight | Scoring Logic |
|----------|--------|--------------|
| `token_injection` | 25% | `0` if delta<20, `25*delta/100` capped at 25 if 20<delta<100, `25+25*(delta-100)/200` capped at 50 if delta>100 |
| `hidden_injection` | 20% | `0` if excess<10, linear to 40 at excess=200 |
| `instruction_override` | 25% | 0 if no override, 50 if partial, 100 if complete override |
| `context_truncation` | 15% | 0 if full window, `(1 - actual/max_advertised)*100` |
| `data_exfiltration` | 15% | 0 if clean, 50 if suspicious headers, 100 if confirmed leak |

**Risk Levels**:
- `LOW`: overall score 0-30
- `MEDIUM`: overall score 31-60
- `HIGH`: overall score 61-80
- `CRITICAL`: overall score 81-100

---

*End of Design Document*
