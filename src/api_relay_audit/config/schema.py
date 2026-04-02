"""Pydantic schema models for configuration validation."""

from typing import Optional, List, Dict, Literal, Any
from pydantic import BaseModel, Field


class GlobalSettings(BaseModel):
    timeout: int = Field(default=120, ge=1)
    max_retries: int = Field(default=3, ge=0)
    retry_delay: int = Field(default=2, ge=0)
    sleep_between_calls: int = Field(default=1, ge=0)
    verbose: bool = True
    output_dir: str = "./reports"
    default_format: Literal["auto", "anthropic", "openai"] = "auto"
    model: str = "claude-opus-4-6"


class EndpointConfig(BaseModel):
    url: str
    token: str
    name: Optional[str] = None
    format: Literal["auto", "anthropic", "openai"] = "auto"
    timeout: int = Field(default=120, ge=1)
    enabled: bool = True
    tags: List[str] = []


class CanaryConfig(BaseModel):
    coarse_steps: List[int] = [50, 100, 200, 400, 600, 800]
    binary_search_threshold: int = 20
    canary_count: int = 5
    max_context_k: int = 1000


class DetectorConfig(BaseModel):
    enabled: bool = True


class TokenInjectionDetectorConfig(DetectorConfig):
    injection_threshold: int = 100


class HiddenInjectionDetectorConfig(DetectorConfig):
    injection_threshold: int = 50


class InstructionOverrideDetectorConfig(DetectorConfig):
    pass


class ContextTruncationDetectorConfig(CanaryConfig, DetectorConfig):
    pass


class DataExfiltrationDetectorConfig(DetectorConfig):
    pass


# Define sub-configs before ReportConfig to avoid forward reference issues
class JSONReportConfig(BaseModel):
    pretty: bool = True
    include_raw_responses: bool = False
    include_timing: bool = True


class MarkdownReportConfig(BaseModel):
    include_http_headers: bool = False
    include_responses: Literal["none", "summary", "full"] = "summary"


class HTMLReportConfig(BaseModel):
    theme: Literal["light", "dark"] = "light"
    include_charts: bool = True


class ReportConfig(BaseModel):
    formats: List[str] = ["json", "markdown"]
    json_settings: JSONReportConfig = Field(default_factory=JSONReportConfig, alias="json")
    markdown: MarkdownReportConfig = Field(default_factory=MarkdownReportConfig)
    html: HTMLReportConfig = Field(default_factory=HTMLReportConfig)


class AdvancedConfig(BaseModel):
    use_curl_fallback: bool = True
    curl_path: str = "curl"
    verify_ssl: bool = True
    proxy: Optional[str] = None
    custom_headers: Dict[str, str] = {}


class TestCasesConfig(BaseModel):
    model: str = "claude-opus-4-6"


class AppConfig(BaseModel):
    version: str = "1.0"
    settings: GlobalSettings = Field(default_factory=GlobalSettings)
    endpoints: List[EndpointConfig] = []
    test_cases: TestCasesConfig = Field(default_factory=TestCasesConfig)
    reports: ReportConfig = Field(default_factory=ReportConfig)
    advanced: AdvancedConfig = Field(default_factory=AdvancedConfig)
