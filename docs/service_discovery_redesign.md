# 服务发现重设计：渐进式自动探测 + 独立策略配置

> 版本: v1.0 | 日期: 2026-06-03 | 状态: 设计评审中

---

## 一、当前问题分析

### 1.1 现状

当前服务发现流程：用户在 `ServiceDiscovery.vue` 中手动选择扫描方法组合，后端 `execute_scan` → `run_scan_methods` 顺序执行各方法。

```
前端选择: nmap_syn_full + nmap_service + nmap_script
                    ↓
后端执行: run_scan_methods()
          ├── nmap_syn_full: 全端口分块扫描 (14块×5000端口)
          ├── nmap_service:  又一次全端口 -sV
          └── nmap_script:   又一次全端口 -sC
```

### 1.2 痛点

| # | 痛点 | 影响 |
|---|------|------|
| P1 | **用户必须懂 nmap** | 手动选 nmap_syn_full / nmap_service / nmap_script，普通用户不知如何组合 |
| P2 | **方法间无关联，重复扫描全端口** | nmap_service 和 nmap_script 各跑一遍 65535 端口，浪费 10-100 倍时间 |
| P3 | **无法组合为单次调用** | `-sV + --script` 本可合并为一次 nmap 调用，当前分别执行 |
| P4 | **探测深度不可控** | 没有"快速/标准/深度"分级，用户要么选轻要么选重 |
| P5 | **参数散落** | timeout/retry/rate 在 `config.py` 环境变量里，普通用户改不了 |
| P6 | **快捷组合只是前端预填** | "Top1000+服务识别" 仅预填表单，不走优化路径 |

### 1.3 关键代码位置

| 文件 | 职责 | 问题 |
|------|------|------|
| `backend/app/services/scan_executor.py` | `execute_scan` → `run_scan_methods` 分派 | 服务发现入口，无阶段概念 |
| `backend/app/services/scan_executor.py` | `run_chunked_full_scan` | 全端口分块，无法感知后续阶段 |
| `backend/app/services/scan_executor.py` | `run_scan_methods` | 线性遍历 methods，每个方法独立扫全端口 |
| `backend/app/services/scanner/nmap_scanner.py` | `_build_tcp_scan_args()` | 只支持端口扫描参数，无 -sV/--script/-O |
| `backend/app/api/service_discovery.py` | `SERVICE_METHODS` + `create_service_scan` | 验证 scan_methods，无 profile 概念 |
| `backend/app/schemas/discovery.py` | `ScanRequest` | 前端传 scan_methods 列表 |
| `frontend/src/views/ServiceDiscovery.vue` | 表单 | 手动选择端口扫描方式 + 服务识别勾选 |
| `frontend/src/views/Settings.vue` | 系统设置 | 有"扫描器"Tab 但只是改全局参数 |
| `backend/app/config.py` | `Settings` 类 | SCAN_TOP_*/SCAN_FULL_* 等硬编码环境变量 |

---

## 二、核心设计理念：渐进式自动探测

### 2.1 架构对比

**旧架构（当前）：** 每个方法独立扫描全端口
```
nmap_syn_full  ──→  扫 65535 端口  ──→  结果1
nmap_service   ──→  扫 65535 端口  ──→  结果2  ← 重复扫描!
nmap_script    ──→  扫 65535 端口  ──→  结果3  ← 重复扫描!
```

**新架构（渐进式）：** 端口发现后，只对开放端口做定向探测
```
阶段1 端口发现  ──→  扫全端口/Top1000  ──→  开放端口列表 [22,80,443,3306]
阶段2 服务识别  ──→  只扫 [22,80,443,3306] -sV    ──→  服务名+版本
阶段3 脚本探测  ──→  只扫 [22,80,443,3306] --script ──→  漏洞/额外信息
阶段4 OS识别    ──→  只扫 [22,80,443,3306] -O     ──→  操作系统
```

**效率提升示例：**
- 阶段1：`nmap -sT -p 1-65535 target` → 发现 22, 80, 443, 3306
- 阶段2：`nmap -sT -sV -p 22,80,443,3306 target` → 只探测 4 个端口
- 阶段3：`nmap -sT --script=default,safe -p 22,80,443,3306 target` → 只探测 4 个端口
- **对比当前：** nmap_service 和 nmap_script 各扫一遍 65535 → **效率提升 10-100 倍**

### 2.2 合并执行优化

当阶段 2（-sV）和阶段 3（--script）同时启用时，可合并为一次 nmap 调用：

```bash
# 合并模式（推荐，减少一次全流程扫描）
nmap -sT -sV --version-intensity 7 --script=default,safe -p 22,80,443,3306 target

# 分离模式（仅在需要不同参数时使用）
nmap -sT -sV --version-intensity 7 -p 22,80,443,3306 target
nmap -sT --script=vuln -p 22,80,443,3306 target
```

引擎自动判断是否可合并：
- 阶段2+3 同时启用且无特殊 script_args → 合并为一次调用
- 阶段3 单独启用或 script_args 需独立设置 → 分开调用

### 2.3 进度分配

```
阶段1 端口发现:  0% - 40%  (最耗时，全端口扫描)
阶段2 服务识别: 40% - 65%
阶段3 脚本探测: 65% - 90%
阶段4 OS识别:   90% - 100%

跳过规则：未启用的阶段直接跳过，进度重新分配
例：只启用阶段1+2 → 阶段1 占 0-60%, 阶段2 占 60-100%
```

---

## 三、数据模型设计

### 3.1 ScanProfile 表（新增）

```python
class ScanProfile(Base):
    __tablename__ = "scan_profiles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(String(255), default=None)
    is_default = Column(Boolean, default=False)    # 系统默认策略（新建任务时自动选中）
    is_builtin = Column(Boolean, default=False)     # 内置策略不可删除，可修改参数

    # ===== 阶段1: 端口发现（必须执行）=====
    port_scan = Column(JSON, default=dict)
    # {
    #   "mode": "top1000" | "full" | "custom",
    #   "custom_ports": "22,80,443,1-1000",   # mode=custom 时使用
    #   "top_ports": 1000,                     # mode=top1000 时使用（可改为 top100/500）
    #   "scan_mode": "standard" | "ip_sequential",
    #   "max_concurrent": 4                    # 并发nmap进程数
    # }

    # ===== 阶段2: 服务版本识别（可选）=====
    service_detect = Column(JSON, default=dict)
    # {
    #   "enabled": true,
    #   "intensity": 7,          # --version-intensity 0-9，默认7
    #   "all_ports": false       # --allports (不跳过9100等打印端口)
    # }

    # ===== 阶段3: 脚本扫描（可选）=====
    script_scan = Column(JSON, default=dict)
    # {
    #   "enabled": false,
    #   "categories": ["default", "safe"],   # --script 的分类
    #   "custom_scripts": "",                 # 自定义脚本名，如 "http-vuln-*"
    #   "script_args": ""                     # --script-args
    # }

    # ===== 阶段4: OS识别（可选）=====
    os_detect = Column(JSON, default=dict)
    # {
    #   "enabled": false,
    #   "max_tries": 2,          # --max-os-tries
    #   "scan_guess": false      # --osscan-guess (更激进猜测)
    # }

    # ===== 通用时序参数 =====
    timing = Column(JSON, default=dict)
    # {
    #   "host_timeout": 300,       # 单主机超时(秒)，0=不限
    #   "max_retries": 3,
    #   "min_rate": 300,
    #   "max_rtt_timeout_ms": 500,
    #   "initial_rtt_timeout_ms": 200,
    #   "max_scan_delay_ms": 10
    # }

    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
```

### 3.2 内置预设（初始化时插入）

| ID | 名称 | 端口发现 | 服务识别 | 脚本扫描 | OS识别 | 定位 |
|----|------|----------|----------|----------|--------|------|
| 1 | 快速探测 | top1000 | ❌ | ❌ | ❌ | 最快，只找端口和开放服务 |
| 2 | 标准探测 | top1000 | ✅ intensity=5 | ❌ | ❌ | 日常巡检，速度与信息平衡 |
| 3 | 深度探测 | full | ✅ intensity=7 | ✅ default+safe | ❌ | 全面信息采集 |
| 4 | 安全审计 | full | ✅ intensity=9 | ✅ default+vuln | ✅ | 最全面，耗时最长 |

**预设 JSON 示例：**

```json
// ID=1 快速探测
{
  "name": "快速探测",
  "description": "只扫描Top1000常见端口，速度最快",
  "is_default": true,
  "is_builtin": true,
  "port_scan": {
    "mode": "top1000",
    "top_ports": 1000,
    "scan_mode": "standard",
    "max_concurrent": 4
  },
  "service_detect": { "enabled": false },
  "script_scan": { "enabled": false },
  "os_detect": { "enabled": false },
  "timing": {
    "host_timeout": 60,
    "max_retries": 2,
    "min_rate": 500,
    "max_rtt_timeout_ms": 500,
    "initial_rtt_timeout_ms": 200,
    "max_scan_delay_ms": 10
  }
}

// ID=3 深度探测
{
  "name": "深度探测",
  "description": "全端口扫描 + 服务版本识别 + 安全脚本，全面信息采集",
  "is_default": false,
  "is_builtin": true,
  "port_scan": {
    "mode": "full",
    "scan_mode": "standard",
    "max_concurrent": 4
  },
  "service_detect": {
    "enabled": true,
    "intensity": 7,
    "all_ports": false
  },
  "script_scan": {
    "enabled": true,
    "categories": ["default", "safe"],
    "custom_scripts": "",
    "script_args": ""
  },
  "os_detect": { "enabled": false },
  "timing": {
    "host_timeout": 0,
    "max_retries": 3,
    "min_rate": 300,
    "max_rtt_timeout_ms": 500,
    "initial_rtt_timeout_ms": 200,
    "max_scan_delay_ms": 10
  }
}
```

### 3.3 ScanTask 表修改

```python
# 新增字段
scan_profile_id = Column(Integer, ForeignKey("scan_profiles.id"), nullable=True)

# scan_methods 保留但含义变化：
# - 旧任务: scan_profile_id=NULL, scan_methods 由前端传入（兼容旧逻辑）
# - 新任务: scan_profile_id 有值, scan_methods 由引擎根据 profile 自动填充
#   例如: profile 启用了 service+script → scan_methods=["nmap_syn_full","nmap_service","nmap_script"]
#   用途：前端历史展示、日志理解
```

### 3.4 数据库迁移

```python
# alembic revision
def upgrade():
    # 1. 创建 scan_profiles 表
    op.create_table(
        'scan_profiles',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(100), nullable=False, unique=True),
        sa.Column('description', sa.String(255)),
        sa.Column('is_default', sa.Boolean(), default=False),
        sa.Column('is_builtin', sa.Boolean(), default=False),
        sa.Column('port_scan', sa.JSON(), default=dict),
        sa.Column('service_detect', sa.JSON(), default=dict),
        sa.Column('script_scan', sa.JSON(), default=dict),
        sa.Column('os_detect', sa.JSON(), default=dict),
        sa.Column('timing', sa.JSON(), default=dict),
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
    )
    # 2. scan_tasks 表新增 scan_profile_id
    op.add_column('scan_tasks', sa.Column('scan_profile_id', sa.Integer(), nullable=True))
    op.create_foreign_key('fk_scan_tasks_profile', 'scan_tasks', 'scan_profiles', ['scan_profile_id'], ['id'])

def downgrade():
    op.drop_constraint('fk_scan_tasks_profile', 'scan_tasks', type_='foreignkey')
    op.drop_column('scan_tasks', 'scan_profile_id')
    op.drop_table('scan_profiles')
```

---

## 四、后端执行引擎设计

### 4.1 渐进式探测主流程

```python
async def run_service_discovery(
    targets: str,
    profile: ScanProfile,
    scan_task_id: int,
    all_results: dict,
    db: AsyncSession,
    scan_task: ScanTask,
):
    """渐进式服务发现：端口发现 → 服务识别 → 脚本探测 → OS识别

    核心优化：阶段2/3/4只对阶段1发现的开放端口做定向探测，
    避免重复扫描全端口。
    """
    port_config = profile.port_scan or {}
    svc_config = profile.service_detect or {}
    script_config = profile.script_scan or {}
    os_config = profile.os_detect or {}
    timing_config = profile.timing or {}

    # 计算启用的阶段数（阶段1始终执行）
    enabled_phases = 1  # 端口发现
    if svc_config.get("enabled"):
        enabled_phases += 1
    if script_config.get("enabled"):
        enabled_phases += 1
    if os_config.get("enabled"):
        enabled_phases += 1

    # 计算进度分配
    progress_ranges = _calc_progress_ranges(enabled_phases)

    # ── 阶段1: 端口发现（必须执行）──────────────────────
    await _append_log(db, scan_task, f"[阶段1/端口发现] 开始, 模式: {port_config.get('mode')}")

    open_ports_map = await _phase1_port_scan(
        targets, port_config, timing_config,
        scan_task_id, all_results, db, scan_task
    )
    # open_ports_map = { "192.168.1.1": [22, 80, 443], "192.168.1.2": [3306] }

    phase_idx = 1
    yield progress_ranges[phase_idx][1], [], []  # 阶段1结束进度

    # ── 阶段2+3 合并判断 ──────────────────────────────
    svc_enabled = svc_config.get("enabled", False)
    script_enabled = script_config.get("enabled", False)
    can_merge_svc_script = (
        svc_enabled and script_enabled
        and not script_config.get("script_args")  # 有 script_args 时分开执行
    )

    # ── 阶段2: 服务版本识别（可选）──────────────────────
    if svc_enabled and not can_merge_svc_script:
        phase_idx += 1
        await _append_log(db, scan_task, f"[阶段2/服务识别] 开始, intensity={svc_config.get('intensity', 7)}")
        await _phase2_service_detect(open_ports_map, svc_config, timing_config, ...)
        yield progress_ranges[phase_idx][1], [], []

    # ── 阶段3: 脚本扫描（可选）──────────────────────────
    if script_enabled and not can_merge_svc_script:
        phase_idx += 1
        await _append_log(db, scan_task, f"[阶段3/脚本扫描] 开始, categories={script_config.get('categories')}")
        await _phase3_script_scan(open_ports_map, script_config, timing_config, ...)
        yield progress_ranges[phase_idx][1], [], []

    # ── 阶段2+3 合并执行 ──────────────────────────────
    if can_merge_svc_script:
        phase_idx += 1
        await _append_log(db, scan_task, "[阶段2+3/服务识别+脚本扫描] 合并执行")
        await _phase23_merged(open_ports_map, svc_config, script_config, timing_config, ...)
        yield progress_ranges[phase_idx + 1][1], [], []  # 合并占两个阶段的进度

    # ── 阶段4: OS识别（可选）────────────────────────────
    if os_config.get("enabled"):
        phase_idx += 1
        await _append_log(db, scan_task, "[阶段4/OS识别] 开始")
        await _phase4_os_detect(open_ports_map, os_config, timing_config, ...)
        yield progress_ranges[phase_idx][1], [], []

    # 最终汇总
    ...
    yield 100, [], []
```

### 4.2 各阶段详细设计

#### 阶段1 - 端口发现

```python
async def _phase1_port_scan(
    targets: str,
    port_config: dict,
    timing_config: dict,
    scan_task_id: int,
    all_results: dict,
    db: AsyncSession,
    scan_task: ScanTask,
) -> dict[str, list[int]]:
    """端口发现：根据 profile.port_scan.mode 决定扫描范围

    Returns:
        open_ports_map: { "192.168.1.1": [22, 80, 443], ... }
    """
    mode = port_config.get("mode", "top1000")
    scan_mode = port_config.get("scan_mode", "standard")
    max_concurrent = port_config.get("max_concurrent", 4)

    if mode == "top1000":
        # 复用现有 scan_executor 中的 _phase2_top1000 逻辑
        # nmap -sT --top-ports 1000 -T4 -Pn -n [timing] targets
        top_ports = port_config.get("top_ports", 1000)
        await _phase2_top1000(targets, scan_mode, max_concurrent, ...)

    elif mode == "full":
        # 复用现有 run_chunked_full_scan 逻辑
        # nmap -sT -p 1-65535 分块扫描
        async for progress, errors, new_results in run_chunked_full_scan(...):
            ...

    elif mode == "custom":
        # nmap -sT -p {custom_ports} -T4 -Pn -n [timing] targets
        custom_ports = port_config["custom_ports"]
        scanner = NmapScanner()
        args = build_phase_args("port_scan", custom_ports, timing_config)
        results = await scanner.scan(targets, custom_ports, scan_method="nmap_syn", ...)
        _merge_results(all_results, results, skip_no_ports=True)

    # 构建 open_ports_map
    open_ports_map = {}
    for ip, data in all_results.items():
        open_ports = [p["port"] for p in data.get("ports", []) if p.get("state") == "open"]
        if open_ports:
            open_ports_map[ip] = open_ports

    return open_ports_map
```

#### 阶段2 - 服务版本识别

```python
async def _phase2_service_detect(
    open_ports_map: dict[str, list[int]],
    svc_config: dict,
    timing_config: dict,
    scan_task_id: int,
    all_results: dict,
    db: AsyncSession,
    scan_task: ScanTask,
):
    """对开放端口做 -sV 探测，只扫已发现端口"""
    intensity = svc_config.get("intensity", 7)
    all_ports = svc_config.get("all_ports", False)

    for ip, ports in open_ports_map.items():
        port_spec = ",".join(str(p) for p in ports)
        args = build_phase_args("service_detect", port_spec, timing_config)
        # args 示例: "-sT -sV --version-intensity 7 -p 22,80,443 -Pn -n -T4 ..."

        if all_ports:
            args += " --allports"

        scanner = NmapScanner()
        results = await scanner.scan_with_args(ip, args)

        # 合并：更新 all_results 中该 IP 的 service/version 字段
        _merge_service_info(all_results, results)

        # 持久化
        for r in results:
            await persist_host_incremental(db, scan_task_id, r.get("ip"), r)
```

#### 阶段3 - 脚本扫描

```python
async def _phase3_script_scan(
    open_ports_map: dict[str, list[int]],
    script_config: dict,
    timing_config: dict,
    scan_task_id: int,
    all_results: dict,
    db: AsyncSession,
    scan_task: ScanTask,
):
    """对开放端口运行 NSE 脚本"""
    categories = ",".join(script_config.get("categories", ["default"]))
    script_spec = categories
    if script_config.get("custom_scripts"):
        script_spec += "," + script_config["custom_scripts"]

    for ip, ports in open_ports_map.items():
        port_spec = ",".join(str(p) for p in ports)
        args = build_phase_args("script_scan", port_spec, timing_config)
        # args 示例: "-sT --script=default,safe -p 22,80,443 -Pn -n -T4 ..."

        if script_config.get("script_args"):
            args += f" --script-args={script_config['script_args']}"

        scanner = NmapScanner()
        results = await scanner.scan_with_args(ip, args)

        # 合并：更新 all_results 中该 IP 的 script_output 字段
        _merge_script_info(all_results, results)

        for r in results:
            await persist_host_incremental(db, scan_task_id, r.get("ip"), r)
```

#### 阶段2+3 - 合并执行

```python
async def _phase23_merged(
    open_ports_map: dict[str, list[int]],
    svc_config: dict,
    script_config: dict,
    timing_config: dict,
    scan_task_id: int,
    all_results: dict,
    db: AsyncSession,
    scan_task: ScanTask,
):
    """合并 -sV + --script 为一次 nmap 调用"""
    intensity = svc_config.get("intensity", 7)
    categories = ",".join(script_config.get("categories", ["default"]))
    script_spec = categories
    if script_config.get("custom_scripts"):
        script_spec += "," + script_config["custom_scripts"]

    for ip, ports in open_ports_map.items():
        port_spec = ",".join(str(p) for p in ports)
        args = (
            f"-sT -sV --version-intensity {intensity} "
            f"--script={script_spec} "
            f"-p {port_spec} -Pn -n -T4 "
            f"{_timing_args_str(timing_config)}"
        )
        if svc_config.get("all_ports"):
            args += " --allports"
        if script_config.get("script_args"):
            args += f" --script-args={script_config['script_args']}"

        scanner = NmapScanner()
        results = await scanner.scan_with_args(ip, args)

        _merge_service_info(all_results, results)
        _merge_script_info(all_results, results)

        for r in results:
            await persist_host_incremental(db, scan_task_id, r.get("ip"), r)
```

#### 阶段4 - OS识别

```python
async def _phase4_os_detect(
    open_ports_map: dict[str, list[int]],
    os_config: dict,
    timing_config: dict,
    scan_task_id: int,
    all_results: dict,
    db: AsyncSession,
    scan_task: ScanTask,
):
    """OS识别（需要 root 权限，-O 需要 -sS 或 -sT + root）"""
    # 检测权限
    if os.geteuid() != 0:
        await _append_log(db, scan_task, "⚠️ OS识别(-O)需要root权限，当前非root，已跳过此阶段")
        return

    max_tries = os_config.get("max_tries", 2)
    scan_guess = os_config.get("scan_guess", False)

    for ip, ports in open_ports_map.items():
        # OS识别需要至少1个open+1个closed端口，保留已发现端口
        port_spec = ",".join(str(p) for p in ports)
        args = f"-sT -O --max-os-tries {max_tries}"
        if scan_guess:
            args += " --osscan-guess"
        args += f" -p {port_spec} -Pn -n -T4 {_timing_args_str(timing_config)}"

        # 添加 --osscan-limit 跳过不满足条件的主机
        args += " --osscan-limit"

        scanner = NmapScanner()
        results = await scanner.scan_with_args(ip, args)

        # 更新 OS 信息
        for r in results:
            ip_key = r.get("ip")
            if ip_key and r.get("os"):
                if ip_key in all_results:
                    all_results[ip_key]["os"] = r["os"]
                await persist_host_incremental(db, scan_task_id, ip_key, r)
```

### 4.3 Nmap 参数构建（新方法）

```python
def build_phase_args(
    phase: str,
    port_spec: str | None,
    timing: dict,
) -> list[str]:
    """根据阶段和策略构建 nmap 参数列表

    返回 list[str] 而非 str，更安全地传给 subprocess
    """
    args = ["-sT", "-T4", "-Pn", "-n"]

    # 时序参数
    args.extend(["--max-retries", str(timing.get("max_retries", 3))])
    args.extend(["--min-rate", str(timing.get("min_rate", 300))])
    host_timeout = timing.get("host_timeout", 0)
    if host_timeout > 0:
        args.extend(["--host-timeout", f"{host_timeout}s"])
    args.extend(["--max-rtt-timeout", f"{timing.get('max_rtt_timeout_ms', 500)}ms"])
    args.extend(["--initial-rtt-timeout", f"{timing.get('initial_rtt_timeout_ms', 200)}ms"])
    args.extend(["--max-scan-delay", f"{timing.get('max_scan_delay_ms', 10)}ms"])

    if phase == "port_scan":
        if port_spec:
            args.extend(["-p", port_spec])
        args.extend(["-v", "--reason"])

    elif phase == "service_detect":
        args.append("-sV")
        # intensity 由调用方通过参数传入
        if port_spec:
            args.extend(["-p", port_spec])

    elif phase == "script_scan":
        # --script=... 由调用方拼入
        if port_spec:
            args.extend(["-p", port_spec])

    elif phase == "os_detect":
        args.append("-O")
        args.append("--osscan-limit")
        if port_spec:
            args.extend(["-p", port_spec])

    return args
```

### 4.4 NmapScanner 新增方法

```python
class NmapScanner(BaseScanner):

    # ... 保留现有 scan() 方法不变 ...

    async def scan_with_args(
        self,
        targets: str,
        extra_args: str | list[str],
        progress_callback=None,
    ) -> list[dict]:
        """使用自定义参数执行 nmap 扫描

        用于渐进式探测的阶段2/3/4，由 build_phase_args 构造参数。
        """
        # 基本参数 + extra_args + targets
        # 复用现有的 _run_nmap_process / _parse_output 逻辑
        ...
```

### 4.5 进度计算

```python
def _calc_progress_ranges(enabled_phases: int) -> dict[int, tuple[int, int]]:
    """根据启用的阶段数，均匀分配进度区间

    Returns:
        { 1: (0, 40), 2: (40, 65), 3: (65, 90), 4: (90, 100) }
        如果只有2个阶段: { 1: (0, 60), 2: (60, 100) }
    """
    if enabled_phases == 1:
        return {1: (0, 100)}
    elif enabled_phases == 2:
        return {1: (0, 60), 2: (60, 100)}
    elif enabled_phases == 3:
        return {1: (0, 40), 2: (40, 70), 3: (70, 100)}
    else:  # 4 phases
        return {1: (0, 35), 2: (35, 60), 3: (60, 85), 4: (85, 100)}
```

### 4.6 结果合并辅助函数

```python
def _merge_service_info(all_results: dict, scan_results: list[dict]):
    """合并服务版本信息到全局结果

    更新端口条目的 service/version 字段，不新增端口
    """
    for r in scan_results:
        ip = r.get("ip")
        if not ip or ip not in all_results:
            continue
        existing = all_results[ip]
        existing_ports = {
            f"{p['port']}/{p.get('proto', 'tcp')}": p
            for p in (existing.get("ports") or [])
        }
        for new_port in r.get("ports", []):
            key = f"{new_port['port']}/{new_port.get('proto', 'tcp')}"
            if key in existing_ports:
                # 补充 service/version，不覆盖已有
                p = existing_ports[key]
                if new_port.get("service") and not p.get("service"):
                    p["service"] = new_port["service"]
                if new_port.get("version") and not p.get("version"):
                    p["version"] = new_port["version"]


def _merge_script_info(all_results: dict, scan_results: list[dict]):
    """合并脚本输出到全局结果"""
    for r in scan_results:
        ip = r.get("ip")
        if not ip or ip not in all_results:
            continue
        existing = all_results[ip]
        existing_ports = {
            f"{p['port']}/{p.get('proto', 'tcp')}": p
            for p in (existing.get("ports") or [])
        }
        for new_port in r.get("ports", []):
            key = f"{new_port['port']}/{new_port.get('proto', 'tcp')}"
            if key in existing_ports:
                p = existing_ports[key]
                if new_port.get("script_output"):
                    # 追加脚本输出
                    existing_output = p.get("script_output", "")
                    p["script_output"] = (
                        existing_output + "\n" + new_port["script_output"]
                        if existing_output
                        else new_port["script_output"]
                    )
```

---

## 五、API 设计

### 5.1 ScanProfile CRUD

```
GET    /api/scan-profiles/              # 列出所有策略
POST   /api/scan-profiles/              # 创建自定义策略
GET    /api/scan-profiles/{id}          # 策略详情
PUT    /api/scan-profiles/{id}          # 更新策略
DELETE /api/scan-profiles/{id}          # 删除策略（内置不可删）
POST   /api/scan-profiles/{id}/default  # 设为默认策略
```

**请求/响应示例：**

```json
// GET /api/scan-profiles/
{
  "items": [
    {
      "id": 1,
      "name": "快速探测",
      "description": "只扫描Top1000常见端口，速度最快",
      "is_default": true,
      "is_builtin": true,
      "port_scan": { "mode": "top1000", "top_ports": 1000, "scan_mode": "standard", "max_concurrent": 4 },
      "service_detect": { "enabled": false },
      "script_scan": { "enabled": false },
      "os_detect": { "enabled": false },
      "timing": { "host_timeout": 60, "max_retries": 2, "min_rate": 500, "max_rtt_timeout_ms": 500, "initial_rtt_timeout_ms": 200, "max_scan_delay_ms": 10 },
      "created_at": "...",
      "updated_at": "..."
    }
  ]
}

// POST /api/scan-profiles/
{
  "name": "自定义巡检",
  "description": "Top1000 + 服务识别 + 安全脚本",
  "port_scan": { "mode": "top1000", "top_ports": 1000, "scan_mode": "standard", "max_concurrent": 4 },
  "service_detect": { "enabled": true, "intensity": 5, "all_ports": false },
  "script_scan": { "enabled": true, "categories": ["default", "safe"], "custom_scripts": "", "script_args": "" },
  "os_detect": { "enabled": false },
  "timing": { "host_timeout": 300, "max_retries": 3, "min_rate": 300 }
}
```

### 5.2 服务发现任务（修改）

**旧接口：**
```json
POST /api/service-scans/
{
    "name": "日常巡检",
    "targets": "192.168.1.0/24",
    "scan_methods": ["nmap_syn_full", "nmap_service", "nmap_script"],
    "scan_mode": "standard",
    "ports": null,
    "max_concurrent": 4,
    "scan_type": "one_time"
}
```

**新接口（推荐）：**
```json
POST /api/service-scans/
{
    "name": "日常巡检",
    "targets": "192.168.1.0/24",
    "scan_profile_id": 2,           // ← 选策略，不再手动选 methods
    "scan_type": "one_time"
    // scan_mode / ports / max_concurrent 不再需要，由 profile 决定
    // scan_methods 不再由前端传入，由引擎根据 profile 自动决定
}
```

**兼容模式：**
```json
POST /api/service-scans/
{
    "name": "旧方式任务",
    "targets": "192.168.1.0/24",
    "scan_methods": ["nmap_syn_full", "nmap_service"],
    "scan_mode": "standard",
    "scan_type": "one_time"
    // scan_profile_id 为空 → 走旧逻辑 (run_scan_methods)
}
```

### 5.3 Pydantic Schema

```python
# schemas/profile.py (新文件)

class PortScanConfig(BaseModel):
    mode: Literal["top1000", "full", "custom"] = "top1000"
    custom_ports: str | None = None      # mode=custom 时必填
    top_ports: int = 1000               # mode=top1000 时使用
    scan_mode: Literal["standard", "ip_sequential"] = "standard"
    max_concurrent: int = Field(4, ge=1, le=16)

    @model_validator(mode="after")
    def validate_custom_ports(self):
        if self.mode == "custom" and not self.custom_ports:
            raise ValueError("自定义端口模式下必须指定端口范围")
        return self


class ServiceDetectConfig(BaseModel):
    enabled: bool = False
    intensity: int = Field(7, ge=0, le=9, description="探测强度 0-9")
    all_ports: bool = False


class ScriptScanConfig(BaseModel):
    enabled: bool = False
    categories: list[str] = ["default", "safe"]
    custom_scripts: str = ""
    script_args: str = ""


class OSDetectConfig(BaseModel):
    enabled: bool = False
    max_tries: int = Field(2, ge=1, le=10)
    scan_guess: bool = False


class TimingConfig(BaseModel):
    host_timeout: int = Field(0, ge=0, description="单主机超时(秒)，0=不限")
    max_retries: int = Field(3, ge=0, le=10)
    min_rate: int = Field(300, ge=1)
    max_rtt_timeout_ms: int = Field(500, ge=50)
    initial_rtt_timeout_ms: int = Field(200, ge=50)
    max_scan_delay_ms: int = Field(10, ge=1)


class ScanProfileCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str | None = None
    port_scan: PortScanConfig = PortScanConfig()
    service_detect: ServiceDetectConfig = ServiceDetectConfig()
    script_scan: ScriptScanConfig = ScriptScanConfig()
    os_detect: OSDetectConfig = OSDetectConfig()
    timing: TimingConfig = TimingConfig()


class ScanProfileUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    port_scan: PortScanConfig | None = None
    service_detect: ServiceDetectConfig | None = None
    script_scan: ScriptScanConfig | None = None
    os_detect: OSDetectConfig | None = None
    timing: TimingConfig | None = None


class ScanProfileResponse(BaseModel):
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
    created_at: str | None
    updated_at: str | None

    class Config:
        from_attributes = True
```

### 5.4 ScanRequest 修改

```python
# schemas/discovery.py 修改

class ScanRequest(BaseModel):
    name: str
    targets: str
    scan_category: ScanCategory = ScanCategory.host_discovery
    scan_type: ScanType = ScanType.one_time
    scan_mode: ScanMode = ScanMode.standard
    scan_methods: list[ScanMethod] = []      # 保留，兼容旧模式
    scan_profile_id: int | None = None       # 新增：策略ID
    ports: str | None = None
    max_concurrent: int = 4
    interval_minutes: int | None = None

    @model_validator(mode="after")
    def validate_profile_or_methods(self):
        """新任务用 profile，旧任务用 methods，两者至少有一个"""
        if self.scan_profile_id:
            # 有 profile 时忽略 scan_methods，由后端自动决定
            pass
        elif self.scan_category == ScanCategory.service_discovery and not self.scan_methods:
            raise ValueError("服务发现任务必须指定扫描策略或扫描方法")
        return self
```

---

## 六、前端设计

### 6.1 新增页面：扫描策略管理

位置：设置 → 扫描策略 Tab（在 Settings.vue 中新增 Tab-pane）

```
┌─────────────────────────────────────────────────────────────────┐
│ 系统设置                                                        │
│ [数据库与缓存] [认证与安全] [扫描器] [扫描策略] [NVD漏洞库]       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ 扫描策略配置                                      [+ 新建策略]  │
│                                                                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │⚡快速探测│ │📋标准探测│ │🔍深度探测│ │🛡️安全审计│          │
│  │  (默认)  │ │          │ │          │ │          │          │
│  │Top1000   │ │Top1000   │ │全端口    │ │全端口    │          │
│  │仅端口发现│ │+服务识别 │ │+服务+脚本│ │+全部     │          │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘          │
│                                                                 │
│  ─── 点击策略卡片展开编辑 ───                                   │
│                                                                 │
│  ┌─ 📋 标准探测 ──────────────────────────────────────┐        │
│  │                                                     │        │
│  │ 阶段1 端口发现                                      │        │
│  │ ○ Top1000常见端口  ○ 全端口扫描  ○ 自定义端口       │        │
│  │ 自定义端口范围: [________________]                   │        │
│  │ 扫描模式: ○标准 ○逐IP   并发数: [4]                │        │
│  │                                                     │        │
│  │ 阶段2 服务版本识别  [✓] 启用                        │        │
│  │ 探测强度: ─●────────── 5/9                          │        │
│  │ 提示: 强度越高越准确但越慢，7为默认，9为最全         │        │
│  │                                                     │        │
│  │ 阶段3 脚本扫描  [ ] 启用                            │        │
│  │ 脚本分类: ☑default ☑safe ☐vuln ☐brute ☐intrusive  │        │
│  │ 自定义脚本: [________________]                      │        │
│  │                                                     │        │
│  │ 阶段4 OS识别  [ ] 启用                              │        │
│  │ ⚠️ 需要root权限，容器部署可能不可用                  │        │
│  │ 最大尝试次数: [2]  ☐ 激进猜测                       │        │
│  │                                                     │        │
│  │ 时序参数 (高级)  [▶ 展开]                           │        │
│  │ 单主机超时: [300]s   重传次数: [3]                  │        │
│  │ 最低发包率: [300]/s  RTT超时: [500]ms               │        │
│  │                                                     │        │
│  │ [设为默认]  [保存策略]  [重置]  [删除]               │        │
│  └─────────────────────────────────────────────────────┘        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 服务发现任务创建（简化）

```
┌─────────────────────────────────────────────────────────────────┐
│ 新建服务发现任务                                                │
│                                                                 │
│ 任务名称: [日常巡检___________]                                 │
│ 扫描目标: [从资产选择 / 手动输入]                                │
│                                                                 │
│ 扫描策略: [📋 标准探测 ▼]  ← 下拉选 profile                    │
│                                                                 │
│ 💡 策略预览: Top1000端口 + 服务版本识别(强度5)                   │
│                                                                 │
│ 扫描类型: ○ 一次性  ○ 周期  间隔: [60]分钟                      │
│                                                                 │
│ [开始扫描]                                                      │
└─────────────────────────────────────────────────────────────────┘
```

**移除的表单项：**
- ~~端口扫描方式选择~~ (nmap_syn_full / nmap_syn)
- ~~服务识别勾选~~ (nmap_service / nmap_script)
- ~~端口范围输入~~
- ~~并发数滑块~~
- ~~快捷组合链接~~

**新增的表单项：**
- 扫描策略下拉选择（从 profile 列表）
- 策略预览文字（简要说明当前策略会做什么）

### 6.3 前端文件变更

| 文件 | 变更 | 说明 |
|------|------|------|
| `views/Settings.vue` | 修改 | 新增"扫描策略" Tab-pane |
| `views/ServiceDiscovery.vue` | 重写 | 简化为选 profile + 目标 |
| `api/profiles.js` | 新增 | Profile CRUD API 封装 |
| `api/discovery.js` | 修改 | ScanRequest 加 scan_profile_id |
| `components/ScanProfileEditor.vue` | 新增 | 策略编辑器组件（可复用） |
| `components/ScanProfileCard.vue` | 新增 | 策略卡片展示组件 |

---

## 七、与现有系统的兼容性

### 7.1 兼容策略

| 方面 | 兼容方案 |
|------|----------|
| **旧 ScanTask** | `scan_profile_id = NULL` 的任务走旧逻辑（`run_scan_methods`），新任务走新引擎 |
| **scan_methods 字段** | 保留，新引擎自动填充实际执行的方法列表，兼容前端历史展示 |
| **API 响应** | ScanTaskResponse 新增 `scan_profile_id` 和 `scan_profile_name` 字段 |
| **主机发现** | 不受影响，主机发现走独立的两阶段逻辑 |
| **SystemConfig** | 保留，新引擎 timing 默认值可从中读取 |
| **config.py** | 保留，作为全局兜底默认值 |
| **ScanMode 枚举** | 保留，profile.port_scan.scan_mode 复用 |
| **ScanMethod 枚举** | 保留，scan_methods 字段仍使用 |

### 7.2 兼容执行逻辑

```python
# scan_executor.py 修改

async def execute_scan(scan_task_id: int, **kwargs):
    """扫描任务入口：根据 scan_profile_id 分派新旧引擎"""
    async with async_session() as db:
        scan_task = await db.get(ScanTask, scan_task_id)
        ...

        if scan_task.scan_profile_id:
            # 新引擎：渐进式自动探测
            profile = await db.get(ScanProfile, scan_task.scan_profile_id)
            await run_service_discovery(
                targets=scan_task.targets,
                profile=profile,
                scan_task_id=scan_task_id,
                all_results=all_results,
                db=db,
                scan_task=scan_task,
            )
        else:
            # 旧引擎：兼容 scan_methods 模式
            await run_scan_methods(...)
```

### 7.3 scan_methods 自动填充

```python
def _profile_to_methods(profile: ScanProfile) -> list[str]:
    """根据 profile 配置推断实际执行的 scan_methods（兼容旧字段）"""
    methods = []

    # 端口扫描方法
    mode = profile.port_scan.get("mode", "top1000")
    if mode == "full":
        methods.append("nmap_syn_full")
    elif mode == "custom":
        methods.append("nmap_syn")
    else:  # top1000
        methods.append("nmap_syn")

    # 服务识别
    if profile.service_detect.get("enabled"):
        methods.append("nmap_service")

    # 脚本扫描
    if profile.script_scan.get("enabled"):
        methods.append("nmap_script")

    return methods
```

---

## 八、文件变更清单

### 8.1 后端

| 文件 | 变更类型 | 说明 |
|------|----------|------|
| `models/models.py` | 新增+修改 | ScanProfile 模型，ScanTask 加 `scan_profile_id` |
| `schemas/profile.py` | **新增** | ScanProfile 的 Pydantic schema (CRUD) |
| `schemas/discovery.py` | 修改 | ScanRequest 加 `scan_profile_id`，验证逻辑 |
| `api/scan_profiles.py` | **新增** | Profile CRUD API router |
| `api/service_discovery.py` | 修改 | 支持新/旧两种创建模式 |
| `services/scan_executor.py` | **重写** | 新增 `run_service_discovery` 渐进式引擎 |
| `services/scanner/nmap_scanner.py` | 修改 | 新增 `scan_with_args()` 方法 |
| `services/scanner/nmap_scanner.py` | 修改 | 新增 `build_phase_args()` 参数构建函数 |
| `config.py` | 修改 | 新增 profile 相关默认配置说明 |
| `database.py` | 修改 | `init_db` 中初始化内置 profiles |
| `main.py` | 修改 | 注册 scan_profiles router |
| `alembic/versions/xxx_add_scan_profiles.py` | **新增** | 数据库迁移脚本 |

### 8.2 前端

| 文件 | 变更类型 | 说明 |
|------|----------|------|
| `views/Settings.vue` | 修改 | 新增"扫描策略" Tab-pane |
| `views/ServiceDiscovery.vue` | **重写** | 简化为选 profile + 目标 |
| `api/profiles.js` | **新增** | Profile CRUD API 封装 |
| `api/discovery.js` | 修改 | ScanRequest 加 scan_profile_id |
| `components/ScanProfileEditor.vue` | **新增** | 策略编辑器组件 |
| `components/ScanProfileCard.vue` | **新增** | 策略卡片展示组件 |

---

## 九、待讨论的设计细节

### 9.1 阶段2/3 按IP串行 vs 并行

**当前方案：** 阶段2/3 对 `open_ports_map` 中每个 IP 逐个执行 nmap 调用

**问题：** 如果发现 100 个存活主机，阶段2 要跑 100 次 nmap，串行太慢

**可选方案：**

| 方案 | 优点 | 缺点 |
|------|------|------|
| A. 按IP串行 | 简单，资源占用低 | 100个IP很慢 |
| B. 按IP分组并行 | 和阶段1一样按组并发 | 需要合并不同组的端口列表 |
| C. 所有IP合并为1次nmap | 最快 | 端口参数变长（-p 22,80,443,...），不同IP不同端口无法合并 |
| D. 按端口分组 | 相同端口的IP合并扫描 | 实现复杂 |

**推荐方案B：** 复用 `_split_ips_into_groups` 逻辑，每组IP合并为1次nmap调用，但端口取组内所有IP端口的并集。

```python
# 方案B：按组并发，端口取并集
for ip_group in ip_groups:
    # 组内所有IP的开放端口取并集
    group_ports = set()
    for ip in ip_group:
        group_ports.update(open_ports_map.get(ip, []))
    port_spec = ",".join(str(p) for p in sorted(group_ports))

    # 一次nmap扫描整组
    targets = " ".join(ip_group)
    args = f"-sT -sV --version-intensity {intensity} -p {port_spec} -Pn -n -T4 ..."
    results = await scanner.scan_with_args(targets, args)

    # 结果会包含组内所有IP的信息，有些IP可能没有某个端口的结果（正常）
```

### 9.2 NSE 脚本分类选择 UI

**问题：** NSE 脚本分类有 14 个，全部展示会很长

**推荐：** 分为推荐/高级两行

```
推荐: ☑default ☑safe ☐vuln
高级: ☐auth ☐broadcast ☐brute ☐discovery ☐dos ☐exploit
      ☐external ☐fuzzer ☐intrusive ☐malware ☐version
```

并在分类旁加 tooltip 说明：
- **default**: 等同 -sC，nmap 认为安全且有价值的脚本
- **safe**: 不会对目标造成任何影响
- **vuln**: 检查已知漏洞
- **intrusive**: 可能对目标产生影响，慎用
- **dos**: 可能导致拒绝服务，仅限授权测试

### 9.3 OS 识别权限检测时机

**问题：** -O 需要 root 权限，但在用户配置策略时就应该告知

**方案：**
1. **后端 API** 新增 `/api/scan/capabilities` 接口，返回当前运行环境能力
   ```json
   { "os_detect_available": false, "reason": "需要root权限" }
   ```
2. **前端** 在策略编辑和任务创建时，如果 `os_detect_available=false`：
   - OS识别开关灰化
   - 显示警告："当前服务以非root权限运行，OS识别不可用"

### 9.4 周期扫描与 Profile 变更

**问题：** 周期扫描任务关联了某个 profile，之后用户修改了 profile 参数，周期任务应该用新参数还是旧参数？

**方案对比：**

| 方案 | 优点 | 缺点 |
|------|------|------|
| A. 动态引用（始终用最新profile） | 修改即时生效 | 用户可能不知道周期任务参数变了 |
| B. 快照（创建时复制profile参数） | 行为可预测 | 修改profile不影响已创建任务 |

**推荐方案A（动态引用）：**
- 周期任务只保存 `scan_profile_id`，每次执行时读取最新 profile
- 修改 profile 后，前端弹出提示："此策略关联了 N 个周期任务，修改将影响下次执行"
- 任务日志中记录每次执行时使用的 profile 参数快照（方便回溯）

### 9.5 全端口扫描的分块逻辑

**问题：** 阶段1 mode=full 时，现有 `run_chunked_full_scan` 是 14 块并发扫描，每块完成后持久化。新引擎需要：
1. 复用分块机制
2. 在全部分块完成后，汇总 open_ports_map
3. 再进入阶段2

**方案：** 阶段1 full 模式直接复用 `run_chunked_full_scan`，但增加一个回调在所有分块完成后汇总端口。

```python
async def _phase1_port_scan(...):
    if mode == "full":
        # 复用现有分块扫描
        async for progress, errors, new_results in run_chunked_full_scan(...):
            # 和现有逻辑一样，每个分块完成就持久化
            ...
        # 分块扫描结束后，从 all_results 汇总 open_ports_map
```

### 9.6 脚本扫描超时控制

**问题：** NSE 脚本可能非常耗时（vuln 类脚本单个端口可能需要数分钟）

**方案：**
- `--script-timeout` 参数加入 timing 配置（默认 60s）
- `--host-timeout` 仍然有效（整主机超时）
- 前端提示：脚本扫描可能显著增加扫描时间

```python
# timing 配置新增
"script_timeout": 60,     # --script-timeout 秒
```

### 9.7 Profile 参数校验边界

**需要校验的边界情况：**

| 场景 | 校验规则 |
|------|----------|
| mode=custom 但 custom_ports 为空 | 报错 |
| mode=custom 端口格式错误 | 正则校验：`^(\d{1,5}(-\d{1,5})?)(,(\d{1,5}(-\d{1,5})?))*$` |
| intensity < 0 或 > 9 | Pydantic Field 校验 |
| categories 为空列表但 enabled=true | 至少选一个分类 |
| 删除内置 profile | 后端拒绝，返回 403 |
| 修改内置 profile 参数 | 允许，但 name 和 is_builtin 不可改 |
| 设为默认时已有其他默认 | 自动取消旧默认 |
| 同名 profile | name unique 约束 |

---

## 十、实施路线图

```
Phase 1 - 基础设施 (2-3天)
├── ScanProfile 模型 + 迁移脚本
├── 内置预设初始化 (database.py)
├── Profile CRUD API (api/scan_profiles.py)
├── Pydantic Schema (schemas/profile.py)
├── main.py 注册 router
└── 手动测试 API (curl/httpie)

Phase 2 - 执行引擎 (3-4天)
├── build_phase_args 参数构建
├── NmapScanner.scan_with_args 定向扫描方法
├── run_service_discovery 渐进式引擎
├── _phase1_port_scan (复用现有分块/Top1000)
├── _phase2_service_detect
├── _phase3_script_scan
├── _phase23_merged 合并优化
├── _phase4_os_detect
├── 结果合并辅助函数
├── execute_scan 新旧分派逻辑
└── scan_methods 自动填充

Phase 3 - 前端集成 (2天)
├── api/profiles.js
├── components/ScanProfileCard.vue
├── components/ScanProfileEditor.vue
├── Settings.vue 新增"扫描策略"Tab
├── ServiceDiscovery.vue 重写
└── 进度展示优化 (显示当前阶段)

Phase 4 - 测试 & 收尾 (1-2天)
├── 功能测试 (4种预设 × 2种scan_mode)
├── 旧任务兼容性验证
├── 边界测试 (root权限检测/超时/中断)
├── OS识别权限检测 API
├── 文档更新
└── git commit + tag
```

---

## 附录 A：Nmap 参数速查

| 参数 | 含义 | 适用阶段 |
|------|------|----------|
| `-sT` | TCP Connect 扫描（无需root） | 所有阶段 |
| `-sV` | 服务版本识别 | 阶段2 |
| `--version-intensity 0-9` | 探测强度 | 阶段2 |
| `--allports` | 不跳过任何端口（含9100等） | 阶段2 |
| `--script=...` | NSE脚本 | 阶段3 |
| `--script-args=...` | 脚本参数 | 阶段3 |
| `--script-timeout=60s` | 单脚本超时 | 阶段3 |
| `-O` | OS识别 | 阶段4 |
| `--osscan-limit` | 跳过不满足条件的OS识别 | 阶段4 |
| `--osscan-guess` | 更激进猜测OS | 阶段4 |
| `--max-os-tries` | OS识别最大尝试次数 | 阶段4 |
| `-Pn` | 跳过主机发现 | 所有阶段 |
| `-n` | 不做DNS解析 | 所有阶段 |
| `-T4` | 时序模板（激进） | 所有阶段 |
| `--host-timeout 300s` | 单主机超时 | 所有阶段 |
| `--max-retries 3` | 重传次数 | 所有阶段 |
| `--min-rate 300` | 最低发包速率 | 所有阶段 |
| `--max-rtt-timeout 500ms` | 最大RTT超时 | 所有阶段 |
| `--top-ports 1000` | 扫描最常见的N个端口 | 阶段1 |
| `-p 22,80,443` | 指定端口范围 | 所有阶段 |

## 附录 B：NSE 脚本分类说明

| 分类 | 说明 | 风险等级 | 推荐度 |
|------|------|----------|--------|
| `default` | 等同 -sC，nmap认为安全且有价值的脚本 | 低 | ★★★★★ |
| `safe` | 不会对目标造成任何影响 | 低 | ★★★★ |
| `version` | 辅助服务版本识别 | 低 | ★★★ |
| `discovery` | 获取更多目标信息 | 低 | ★★★ |
| `auth` | 认证相关（默认密码等） | 中 | ★★★ |
| `broadcast` | 广播发现局域网主机 | 低 | ★★ |
| `vuln` | 检查已知漏洞 | 中 | ★★★★ |
| `brute` | 暴力破解 | 高 | ★★ |
| `exploit` | 尝试利用漏洞 | 高 | ★ |
| `intrusive` | 可能对目标产生影响 | 高 | ★★ |
| `dos` | 可能导致拒绝服务 | 极高 | ★ |
| `external` | 向外部服务查询（可能泄露信息） | 中 | ★★ |
| `fuzzer` | 发送异常数据 | 高 | ★ |
| `malware` | 检查后门/恶意软件 | 中 | ★★ |

## 附录 C：内置预设详细配置

### C.1 快速探测

```json
{
  "port_scan": {
    "mode": "top1000",
    "top_ports": 1000,
    "scan_mode": "standard",
    "max_concurrent": 4
  },
  "service_detect": { "enabled": false },
  "script_scan": { "enabled": false },
  "os_detect": { "enabled": false },
  "timing": {
    "host_timeout": 60,
    "max_retries": 2,
    "min_rate": 500,
    "max_rtt_timeout_ms": 500,
    "initial_rtt_timeout_ms": 200,
    "max_scan_delay_ms": 10
  }
}
```

预估时间（/24 网段）：1-3 分钟

### C.2 标准探测

```json
{
  "port_scan": {
    "mode": "top1000",
    "top_ports": 1000,
    "scan_mode": "standard",
    "max_concurrent": 4
  },
  "service_detect": {
    "enabled": true,
    "intensity": 5,
    "all_ports": false
  },
  "script_scan": { "enabled": false },
  "os_detect": { "enabled": false },
  "timing": {
    "host_timeout": 120,
    "max_retries": 2,
    "min_rate": 500,
    "max_rtt_timeout_ms": 500,
    "initial_rtt_timeout_ms": 200,
    "max_scan_delay_ms": 10
  }
}
```

预估时间（/24 网段）：3-8 分钟

### C.3 深度探测

```json
{
  "port_scan": {
    "mode": "full",
    "scan_mode": "standard",
    "max_concurrent": 4
  },
  "service_detect": {
    "enabled": true,
    "intensity": 7,
    "all_ports": false
  },
  "script_scan": {
    "enabled": true,
    "categories": ["default", "safe"],
    "custom_scripts": "",
    "script_args": ""
  },
  "os_detect": { "enabled": false },
  "timing": {
    "host_timeout": 0,
    "max_retries": 3,
    "min_rate": 300,
    "max_rtt_timeout_ms": 500,
    "initial_rtt_timeout_ms": 200,
    "max_scan_delay_ms": 10
  }
}
```

预估时间（/24 网段）：20-60 分钟

### C.4 安全审计

```json
{
  "port_scan": {
    "mode": "full",
    "scan_mode": "ip_sequential",
    "max_concurrent": 4
  },
  "service_detect": {
    "enabled": true,
    "intensity": 9,
    "all_ports": false
  },
  "script_scan": {
    "enabled": true,
    "categories": ["default", "safe", "vuln"],
    "custom_scripts": "",
    "script_args": ""
  },
  "os_detect": {
    "enabled": true,
    "max_tries": 2,
    "scan_guess": false
  },
  "timing": {
    "host_timeout": 0,
    "max_retries": 3,
    "min_rate": 200,
    "max_rtt_timeout_ms": 1000,
    "initial_rtt_timeout_ms": 500,
    "max_scan_delay_ms": 20
  }
}
```

预估时间（/24 网段）：60-180 分钟