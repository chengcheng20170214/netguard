"""扫描策略 (ScanProfile) 的 Pydantic Schema

对应设计文档 §5.3，定义策略CRUD的请求/响应模型。
各阶段配置独立建模，TimingConfig 含超时层次校验。
"""

import re
from typing import Literal

from pydantic import BaseModel, Field, model_validator


# ──────────────────────────────────────────────────────────
# 阶段配置子模型
# ──────────────────────────────────────────────────────────

class PortScanConfig(BaseModel):
    """阶段1: 端口发现配置"""
    mode: Literal["top1000", "full", "custom"] = "top1000"
    custom_ports: str | None = None       # mode=custom 时必填
    top_ports: int = Field(1000, ge=100, le=65535,
                           description="扫描最常见的N个端口 (--top-ports)")
    scan_mode: Literal["standard", "ip_sequential"] = "standard"
    max_concurrent: int = Field(4, ge=1, le=16,
                                description="并发nmap进程数")

    @model_validator(mode="after")
    def validate_custom_ports(self) -> "PortScanConfig":
        """自定义端口模式下必须指定端口范围"""
        if self.mode == "custom" and not self.custom_ports:
            raise ValueError("自定义端口模式下必须指定端口范围 (custom_ports)")
        if self.mode == "custom" and self.custom_ports:
            # 校验端口格式: 22,80,443,1-1000
            pattern = r'^(\d{1,5}(-\d{1,5})?)(,(\d{1,5}(-\d{1,5})?))*$'
            if not re.match(pattern, self.custom_ports):
                raise ValueError(
                    "自定义端口格式错误，支持格式: 22,80,443,1-1000"
                )
            # 校验端口范围 1-65535
            for part in self.custom_ports.split(","):
                if "-" in part:
                    lo, hi = part.split("-", 1)
                    if not (1 <= int(lo) <= 65535 and 1 <= int(hi) <= 65535):
                        raise ValueError(f"端口范围超出 1-65535: {part}")
                else:
                    if not 1 <= int(part) <= 65535:
                        raise ValueError(f"端口号超出 1-65535: {part}")
        return self


class ServiceDetectConfig(BaseModel):
    """阶段2: 服务版本识别配置"""
    enabled: bool = False
    intensity: int = Field(7, ge=0, le=9,
                           description="探测强度 0-9 (--version-intensity)")
    all_ports: bool = Field(False,
                             description="不跳过任何端口，含9100等打印端口 (--allports)")


class ScriptScanConfig(BaseModel):
    """阶段3: 脚本扫描配置"""
    enabled: bool = False
    categories: list[str] = Field(
        default_factory=lambda: ["default", "safe"],
        description="NSE脚本分类列表 (--script)")
    custom_scripts: str = Field("", description="自定义脚本名，如 http-vuln-*")
    script_args: str = Field("", description="脚本参数 (--script-args)")

    @model_validator(mode="after")
    def validate_categories(self) -> "ScriptScanConfig":
        """启用脚本扫描时至少选一个分类"""
        if self.enabled and not self.categories:
            raise ValueError("启用脚本扫描时至少选择一个脚本分类")
        return self


class OSDetectConfig(BaseModel):
    """阶段4: OS识别配置"""
    enabled: bool = False
    max_tries: int = Field(2, ge=1, le=10,
                           description="OS识别最大尝试次数 (--max-os-tries)")
    scan_guess: bool = Field(False,
                              description="更激进猜测OS (--osscan-guess)")


class TimingConfig(BaseModel):
    """通用时序参数配置

    ★ 超时层次关系: script_timeout_sec << host_timeout << nmap_timeout_sec
      - script_timeout_sec: 单个NSE脚本超时，防止某个脚本卡死
      - host_timeout: nmap对单主机的超时，主机不可达时及时放弃
      - nmap_timeout_sec: Python层面asyncio.wait_for对整个nmap进程的超时，
                          是最终安全网，防止nmap进程整体卡死
    """
    host_timeout: int = Field(0, ge=0,
                              description="单主机超时(秒)，0=不限 → --host-timeout")
    nmap_timeout_sec: int = Field(7200, ge=60,
                                  description="nmap进程整体超时(秒) → asyncio.wait_for 安全网")
    script_timeout_sec: int = Field(60, ge=5,
                                    description="单NSE脚本超时(秒) → --script-timeout")
    max_retries: int = Field(3, ge=0, le=10,
                             description="端口重试次数 → --max-retries")
    min_rate: int = Field(300, ge=1,
                          description="最小发包速率 → --min-rate")
    max_rtt_timeout_ms: int = Field(500, ge=50,
                                    description="最大RTT超时(ms) → --max-rtt-timeout")
    initial_rtt_timeout_ms: int = Field(200, ge=50,
                                        description="初始RTT超时(ms) → --initial-rtt-timeout")
    max_scan_delay_ms: int = Field(10, ge=1,
                                   description="最大扫描延迟(ms) → --max-scan-delay")
    phase_executor: Literal["serial", "grouped"] = Field(
        "grouped",
        description="阶段2/3执行策略: serial=逐IP串行, grouped=分组并行")

    @model_validator(mode="after")
    def validate_timeout_hierarchy(self) -> "TimingConfig":
        """校验超时层次: script_timeout_sec < host_timeout < nmap_timeout_sec"""
        if self.host_timeout > 0 and self.script_timeout_sec >= self.host_timeout:
            raise ValueError(
                f"script_timeout_sec({self.script_timeout_sec}) 必须 < "
                f"host_timeout({self.host_timeout})"
            )
        if self.host_timeout > 0 and self.host_timeout >= self.nmap_timeout_sec:
            raise ValueError(
                f"host_timeout({self.host_timeout}) 必须 < "
                f"nmap_timeout_sec({self.nmap_timeout_sec})"
            )
        # host_timeout=0 表示不限，不需要与nmap_timeout_sec比较
        return self


# ──────────────────────────────────────────────────────────
# CRUD 请求模型
# ──────────────────────────────────────────────────────────

class ScanProfileCreate(BaseModel):
    """创建扫描策略"""
    name: str = Field(..., min_length=1, max_length=100)
    description: str | None = None
    port_scan: PortScanConfig = Field(default_factory=PortScanConfig)
    service_detect: ServiceDetectConfig = Field(default_factory=ServiceDetectConfig)
    script_scan: ScriptScanConfig = Field(default_factory=ScriptScanConfig)
    os_detect: OSDetectConfig = Field(default_factory=OSDetectConfig)
    timing: TimingConfig = Field(default_factory=TimingConfig)


class ScanProfileUpdate(BaseModel):
    """更新扫描策略（所有字段可选，仅传需要修改的）"""
    name: str | None = Field(None, min_length=1, max_length=100)
    description: str | None = None
    port_scan: PortScanConfig | None = None
    service_detect: ServiceDetectConfig | None = None
    script_scan: ScriptScanConfig | None = None
    os_detect: OSDetectConfig | None = None
    timing: TimingConfig | None = None


# ──────────────────────────────────────────────────────────
# 响应模型
# ──────────────────────────────────────────────────────────

class ScanProfileResponse(BaseModel):
    """扫描策略响应"""
    id: int
    name: str
    description: str | None
    is_default: bool
    is_builtin: bool
    port_scan: dict
    service_detect: dict
    script_scan: dict
    os_detect: dict
    timing: dict
    created_at: str | None = None
    updated_at: str | None = None

    model_config = {"from_attributes": True}


class ScanProfileBrief(BaseModel):
    """扫描策略简要信息（用于下拉选择）"""
    id: int
    name: str
    description: str | None
    is_default: bool
    is_builtin: bool

    model_config = {"from_attributes": True}
