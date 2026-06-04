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

**阶段2+3 合并策略（已确认 → 始终合并）：**
- 阶段2+3 同时启用 → 始终合并为一次 nmap 调用（`-sV --script=...`）
- 仅启用阶段2 → 单独 `-sV` 调用
- 仅启用阶段3 → 单独 `--script` 调用
- 注：即使有 `script_args`，也可在合并调用中通过 `--script-args=` 传入，无需分开执行

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
    #   "host_timeout": 300,       # 单主机超时(秒)，0=不限 → --host-timeout
    #   "nmap_timeout_sec": 7200,  # nmap进程整体超时(秒)，0=不限 → asyncio.wait_for 层面
    #   "script_timeout_sec": 60,  # 单个NSE脚本超时(秒) → --script-timeout
    #   "max_retries": 3,          # 端口重试次数 → --max-retries
    #   "min_rate": 300,           # 最小发包速率 → --min-rate
    #   "max_rtt_timeout_ms": 500, # 最大RTT超时(ms) → --max-rtt-timeout
    #   "initial_rtt_timeout_ms": 200, # 初始RTT超时(ms) → --initial-rtt-timeout
    #   "max_scan_delay_ms": 10    # 最大扫描延迟(ms) → --max-scan-delay
    # }
    #
    # ★ 超时层次关系: script_timeout_sec << host_timeout << nmap_timeout_sec
    #   - script_timeout_sec: 单个NSE脚本超时，防止某个脚本卡死
    #   - host_timeout: nmap对单主机的超时，主机不可达时及时放弃
    #   - nmap_timeout_sec: Python层面asyncio.wait_for对整个nmap进程的超时，
    #                       是最终安全网，防止nmap进程整体卡死

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
    "nmap_timeout_sec": 3600,
    "script_timeout_sec": 30,
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
    "nmap_timeout_sec": 14400,
    "script_timeout_sec": 120,
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
    # 3. scan_tasks 表新增断点恢复字段
    op.add_column('scan_tasks', sa.Column('current_phase', sa.Integer(), default=0))
    op.add_column('scan_tasks', sa.Column('last_duration_sec', sa.Integer(), nullable=True))
    # 4. 创建 scan_checkpoints 独立表（替代 ScanTask 上的 JSON 列）
    op.create_table(
        'scan_checkpoints',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('task_id', sa.Integer(), sa.ForeignKey('scan_tasks.id'), nullable=False, index=True),
        sa.Column('phase', sa.Integer(), nullable=False),
        sa.Column('key', sa.String(64), nullable=False),
        sa.Column('value', sa.JSON(), nullable=True),
        sa.Column('updated_at', sa.DateTime()),
        sa.UniqueConstraint('task_id', 'phase', 'key', name='uq_checkpoint_task_phase_key'),
    )

def downgrade():
    op.drop_table('scan_checkpoints')
    op.drop_column('scan_tasks', 'last_duration_sec')
    op.drop_column('scan_tasks', 'current_phase')
    op.drop_constraint('fk_scan_tasks_profile', 'scan_tasks', type_='foreignkey')
    op.drop_column('scan_tasks', 'scan_profile_id')
    op.drop_table('scan_profiles')
```

---

## 四、后端执行引擎设计

> **架构决策②：结果直写DB，去掉 all_results**
> 旧方案在内存中维护 `all_results` 字典不断累积，500主机全端口可达50MB+，
> 一周运行期间持续增长可能 OOM。新方案扫完每个IP立即写DB，内存只保留
> 下一阶段需要的 `open_ports_map`（约140KB vs 10-50MB，降低100-350倍）。

### 4.1 渐进式探测主流程

```python
async def run_service_discovery(
    targets: str,
    profile: ScanProfile,
    scan_task_id: int,
    # ★ 不再传入 all_results — 结果直写DB
    db: AsyncSession,
    scan_task: ScanTask,
):
    """渐进式服务发现：端口发现 → 服务识别 → 脚本探测 → OS识别

    核心设计原则：
    1. 阶段2/3/4只对阶段1发现的开放端口做定向探测，避免重复扫描全端口
    2. 每个IP扫完立即持久化到DB，内存中不累积完整结果
    3. 内存只保留 open_ports_map（下一阶段的输入），约140KB
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

    # ★ open_ports_map 是阶段间唯一在内存中传递的数据
    # 格式: { "192.168.1.1": [22, 80, 443], "192.168.1.2": [3306] }
    # 估算内存: 500IP × 平均10端口 × 28bytes ≈ 140KB
    open_ports_map = await _phase1_port_scan(
        targets, port_config, timing_config,
        scan_task_id, db, scan_task
    )

    phase_idx = 1
    yield progress_ranges[phase_idx][1], [], []  # 阶段1结束进度

    # ── 阶段2+3 合并判断（已确认：始终合并）───────────────
    svc_enabled = svc_config.get("enabled", False)
    script_enabled = script_config.get("enabled", False)

    # ── 阶段2+3 合并执行（同时启用时始终合并）──────────────
    if svc_enabled and script_enabled:
        phase_idx += 1
        await _append_log(db, scan_task, "[阶段2+3/服务识别+脚本扫描] 合并执行")
        await _phase23_merged(open_ports_map, svc_config, script_config, timing_config, ...)
        phase_idx += 1  # 合并占两个阶段的进度

    # ── 阶段2: 仅服务版本识别（脚本未启用时单独执行）────────
    elif svc_enabled:
        phase_idx += 1
        await _append_log(db, scan_task, f"[阶段2/服务识别] 开始, intensity={svc_config.get('intensity', 7)}")
        await _phase2_service_detect(open_ports_map, svc_config, timing_config, ...)
        yield progress_ranges[phase_idx][1], [], []

    # ── 阶段3: 仅脚本扫描（服务识别未启用时单独执行）────────
    elif script_enabled:
        phase_idx += 1
        await _append_log(db, scan_task, f"[阶段3/脚本扫描] 开始, categories={script_config.get('categories')}")
        await _phase3_script_scan(open_ports_map, script_config, timing_config, ...)
        yield progress_ranges[phase_idx][1], [], []

    # ── 阶段4: OS识别（可选）────────────────────────────
    if os_config.get("enabled"):
        phase_idx += 1
        await _append_log(db, scan_task, "[阶段4/OS识别] 开始")
        await _phase4_os_detect(open_ports_map, os_config, timing_config, ...)
        yield progress_ranges[phase_idx][1], [], []

    # ★ 最终汇总 — 从DB查询，不依赖内存
    summary = await _get_scan_summary(db, scan_task_id)
    await _append_log(db, scan_task,
        f"扫描完成: 发现 {summary['total_hosts']} 台主机, "
        f"{summary['total_ports']} 个开放端口")
    yield 100, [], []
```

### 4.2 各阶段详细设计

> **核心变化**：所有阶段函数不再接收 `all_results` 参数。
> 扫描结果立即通过 `persist_host_incremental()` 写入DB，
> 不在内存中累积。阶段间只传递 `open_ports_map`（端口映射）。

#### 阶段1 - 端口发现

```python
async def _phase1_port_scan(
    targets: str,
    port_config: dict,
    timing_config: dict,
    scan_task_id: int,
    # ★ 不再传入 all_results
    db: AsyncSession,
    scan_task: ScanTask,
) -> dict[str, list[int]]:
    """端口发现：根据 profile.port_scan.mode 决定扫描范围

    Returns:
        open_ports_map: { "192.168.1.1": [22, 80, 443], ... }
        ★ 这是阶段间唯一在内存中传递的数据结构
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
            # ★ 逐块直写DB，不在内存中累积
            for r in new_results:
                r_ip = r.get("ip")
                if r_ip:
                    await persist_host_incremental(db, scan_task_id, r_ip, r)

    elif mode == "custom":
        # nmap -sT -p {custom_ports} -T4 -Pn -n [timing] targets
        custom_ports = port_config["custom_ports"]
        scanner = NmapScanner()
        args = build_phase_args("port_scan", custom_ports, timing_config)
        results = await scanner.scan(targets, custom_ports, scan_method="nmap_syn", ...)
        # ★ 直写DB
        for r in results:
            r_ip = r.get("ip")
            if r_ip:
                await persist_host_incremental(db, scan_task_id, r_ip, r)

    # ★ 从DB查询已持久化的结果，构建 open_ports_map
    # 这比内存中的 all_results 小100-350倍
    open_ports_map = await _build_open_ports_map_from_db(db, scan_task_id)

    return open_ports_map
```

```python
async def _build_open_ports_map_from_db(
    db: AsyncSession,
    scan_task_id: int,
) -> dict[str, list[int]]:
    """从DB查询已持久化的端口发现结果，构建下一阶段所需的端口映射

    替代旧方案中从内存 all_results 构建 open_ports_map 的逻辑。
    查询开销远小于维护 all_results 的内存开销。
    """
    from sqlalchemy import func, distinct
    
    # 查询该任务所有已发现主机的开放端口
    # ScanResult 记录已由 persist_host_incremental 写入
    result = await db.execute(
        select(ScanResult.ip, ScanResult.ports)
        .where(ScanResult.scan_task_id == scan_task_id)
    )
    
    open_ports_map = {}
    for ip, ports_json in result.all():
        if ip and ports_json:
            ports = json.loads(ports_json) if isinstance(ports_json, str) else ports_json
            open_ports = [p["port"] for p in ports if p.get("state") == "open"]
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
    # ★ 不再传入 all_results — 结果直写DB
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

        # ★ 直写DB — 不再 _merge_service_info(all_results, results)
        # persist_host_incremental 内部处理合并逻辑：
        # 对同一IP同一端口，补充 service/version 字段
        for r in results:
            r_ip = r.get("ip")
            if r_ip:
                await persist_host_incremental(db, scan_task_id, r_ip, r)
```

#### 阶段3 - 脚本扫描

```python
async def _phase3_script_scan(
    open_ports_map: dict[str, list[int]],
    script_config: dict,
    timing_config: dict,
    scan_task_id: int,
    # ★ 不再传入 all_results — 结果直写DB
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

        # ★ 直写DB — 不再 _merge_script_info(all_results, results)
        # persist_host_incremental 内部处理合并逻辑：
        # 对同一IP同一端口，追加 script_output 字段
        for r in results:
            r_ip = r.get("ip")
            if r_ip:
                await persist_host_incremental(db, scan_task_id, r_ip, r)
```

#### 阶段2+3 - 合并执行

```python
async def _phase23_merged(
    open_ports_map: dict[str, list[int]],
    svc_config: dict,
    script_config: dict,
    timing_config: dict,
    scan_task_id: int,
    # ★ 不再传入 all_results — 结果直写DB
    db: AsyncSession,
    scan_task: ScanTask,
):
    """合并 -sV + --script 为一次 nmap 调用

    ★ 架构决策①：始终合并阶段2+3（去掉 can_merge_svc_script 条件判断）
    即使有 script_args，也可通过 --script-args= 传入，无需分开执行。
    """
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

        # ★ 直写DB — 一次调用同时包含 service+script 信息
        # persist_host_incremental 内部合并：
        # 补充 service/version + 追加 script_output
        for r in results:
            r_ip = r.get("ip")
            if r_ip:
                await persist_host_incremental(db, scan_task_id, r_ip, r)
```

#### 阶段4 - OS识别

```python
async def _phase4_os_detect(
    open_ports_map: dict[str, list[int]],
    os_config: dict,
    timing_config: dict,
    scan_task_id: int,
    # ★ 不再传入 all_results — 结果直写DB
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

        # ★ 直写DB — OS信息更新到已有主机记录
        for r in results:
            ip_key = r.get("ip")
            if ip_key and r.get("os"):
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

### 4.6 结果持久化与合并（DB层）

> **替代旧方案的内存合并**：旧方案用 `_merge_service_info(all_results, ...)`
> 和 `_merge_script_info(all_results, ...)` 在内存中合并结果。新方案
> 将合并逻辑下沉到 `persist_host_incremental()` 内部，在DB层面处理字段合并。

```python
async def persist_host_incremental(
    db: AsyncSession,
    scan_task_id: int,
    ip: str,
    result: dict,
):
    """将单个主机的扫描结果持久化到DB，自动合并已有记录

    合并策略：
    - 同一IP在ScanResult中已有记录时，合并而非覆盖
    - 端口列表：以 port/proto 为key，新端口追加，已有端口合并字段
    - service/version：只补充不覆盖（保留最详细的信息）
    - script_output：追加（同一端口可能被多次脚本扫描）
    - os：取最新值（后续阶段可能提供更准确结果）
    """
    # 查询已有记录
    existing = await db.execute(
        select(ScanResult)
        .where(
            ScanResult.scan_task_id == scan_task_id,
            ScanResult.ip == ip,
        )
    )
    existing_record = existing.scalar_one_or_none()

    if existing_record is None:
        # 首次写入 — 直接创建
        new_record = ScanResult(
            scan_task_id=scan_task_id,
            ip=ip,
            hostname=result.get("hostname"),
            ports=result.get("ports", []),
            os=result.get("os"),
            mac=result.get("mac"),
        )
        db.add(new_record)
    else:
        # 合并更新 — 在DB层面合并字段
        existing_ports = {
            f"{p['port']}/{p.get('proto', 'tcp')}": p
            for p in (existing_record.ports or [])
        }

        for new_port in result.get("ports", []):
            key = f"{new_port['port']}/{new_port.get('proto', 'tcp')}"
            if key in existing_ports:
                # 合并已有端口的附加信息
                p = existing_ports[key]
                if new_port.get("service") and not p.get("service"):
                    p["service"] = new_port["service"]
                if new_port.get("version") and not p.get("version"):
                    p["version"] = new_port["version"]
                if new_port.get("script_output"):
                    existing_output = p.get("script_output", "")
                    p["script_output"] = (
                        existing_output + "\n" + new_port["script_output"]
                        if existing_output
                        else new_port["script_output"]
                    )
                # 补充 state 信息（如 filtered → open）
                if new_port.get("state") and not p.get("state"):
                    p["state"] = new_port["state"]
            else:
                # 新发现的端口 — 追加
                existing_ports[key] = new_port

        # 写回合并后的端口列表
        existing_record.ports = list(existing_ports.values())

        # 更新 OS（取最新、最详细的）
        if result.get("os"):
            existing_record.os = result["os"]

        # 更新 hostname（取非空值）
        if result.get("hostname") and not existing_record.hostname:
            existing_record.hostname = result["hostname"]

    await db.commit()
```

```python
async def _get_scan_summary(db: AsyncSession, scan_task_id: int) -> dict:
    """从DB查询扫描结果摘要（替代内存 all_results 的汇总功能）"""
    from sqlalchemy import func

    # 总主机数
    host_count = await db.execute(
        select(func.count(func.distinct(ScanResult.ip)))
        .where(ScanResult.scan_task_id == scan_task_id)
    )

    # 总端口数
    port_count = await db.execute(
        select(func.count(ScanResult.id))
        .where(ScanResult.scan_task_id == scan_task_id)
    )

    return {
        "total_hosts": host_count.scalar() or 0,
        "total_ports": port_count.scalar() or 0,
    }
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
    host_timeout: int = Field(0, ge=0, description="单主机超时(秒)，0=不限 → --host-timeout")
    nmap_timeout_sec: int = Field(7200, ge=60, description="nmap进程整体超时(秒) → asyncio.wait_for 安全网")
    script_timeout_sec: int = Field(60, ge=5, description="单NSE脚本超时(秒) → --script-timeout")
    max_retries: int = Field(3, ge=0, le=10)
    min_rate: int = Field(300, ge=1)
    max_rtt_timeout_ms: int = Field(500, ge=50)
    initial_rtt_timeout_ms: int = Field(200, ge=50)
    max_scan_delay_ms: int = Field(10, ge=1)

    @model_validator(mode="after")
    def validate_timeout_hierarchy(self) -> "TimingConfig":
        """超时层次: script_timeout_sec < host_timeout < nmap_timeout_sec"""
        if self.host_timeout > 0 and self.script_timeout_sec >= self.host_timeout:
            raise ValueError(f"script_timeout_sec({self.script_timeout_sec}) 必须 < host_timeout({self.host_timeout})")
        if self.host_timeout > 0 and self.host_timeout >= self.nmap_timeout_sec:
            raise ValueError(f"host_timeout({self.host_timeout}) 必须 < nmap_timeout_sec({self.nmap_timeout_sec})")
        return self


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
            # ★ 不再传入 all_results — 结果直写DB
            profile = await db.get(ScanProfile, scan_task.scan_profile_id)
            await run_service_discovery(
                targets=scan_task.targets,
                profile=profile,
                scan_task_id=scan_task_id,
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

### 9.1 阶段2/3 执行策略：按IP串行 vs 分组并行

**背景：** 阶段2/3 只对阶段1发现的开放端口做定向探测（通常每IP几个到几十个端口），不是全端口扫描。

**两种方案：**

| 方案 | 逻辑 | 优点 | 缺点 |
|------|------|------|------|
| **A. 逐IP串行** | 每次nmap扫1个IP，只扫该IP的开放端口 | 简单，端口参数精确 | nmap启动开销×IP数，100个IP跑100次 |
| **B. 分组并行** | N个IP一组，端口取并集，1次nmap扫整组 | nmap启动次数少，并发快 | 部分IP被多扫几个关闭端口（RST响应<1ms，可忽略） |

**决策：两种方案都实现，通过 profile.timing 新增字段切换，实测后选定一种。**

```python
# timing 配置新增字段
"phase_executor": "grouped"  # "serial" = 方案A逐IP串行, "grouped" = 方案B分组并行
```

```python
# 方案A：逐IP串行 —— 精确端口，每次nmap只扫该IP的开放端口
for ip, ports in open_ports_map.items():
    port_spec = ",".join(str(p) for p in ports)
    args = f"-sT -sV --version-intensity {intensity} -p {port_spec} {ip} -Pn -n -T4 ..."
    results = await scanner.scan_with_args(ip, args)

# 方案B：分组并行 —— 复用 _split_ips_into_groups，组内端口取并集
for ip_group in ip_groups:
    group_ports = set()
    for ip in ip_group:
        group_ports.update(open_ports_map.get(ip, []))
    port_spec = ",".join(str(p) for p in sorted(group_ports))

    targets = " ".join(ip_group)
    args = f"-sT -sV --version-intensity {intensity} -p {port_spec} -Pn -n -T4 ..."
    results = await scanner.scan_with_args(targets, args)
    # 结果会包含组内所有IP的信息，有些IP可能没有某个端口的结果（正常）
```

**实测计划：**
1. Phase 2 实现时两种方案都编码，通过 `phase_executor` 参数切换
2. 内置预设默认用 `grouped`，自定义策略可选 `serial`
3. 对同一目标（如 /24 网段 ~50 存活主机）分别跑两种方案，记录耗时
4. 根据实测数据决定最终默认值，淘汰劣势方案（或保留为高级选项）

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
            # ★ 每个分块完成即直写DB，不在内存中累积
            for r in new_results:
                r_ip = r.get("ip")
                if r_ip:
                    await persist_host_incremental(db, scan_task_id, r_ip, r)
        # 分块扫描结束后，从DB查询汇总 open_ports_map
        open_ports_map = await _build_open_ports_map_from_db(db, scan_task_id)
```

### 9.6 脚本扫描超时控制

**问题：** NSE 脚本可能非常耗时（vuln 类脚本单个端口可能需要数分钟）

**方案：**
- `--script-timeout` 参数纳入 timing 配置字段 `script_timeout_sec`（默认 60s）
- `--host-timeout` 仍然有效（整主机超时，由 timing.host_timeout 控制）
- `nmap_timeout_sec` 作为单次 nmap 调用的整体超时（见11.7），兜底保护
- 前端提示：脚本扫描可能显著增加扫描时间

```python
# timing 字段中的超时层次：
# nmap_timeout_sec → 整体超时（asyncio.wait_for，杀进程级保护）
# host_timeout     → 单主机超时（nmap --host-timeout 参数）
# script_timeout_sec → 单脚本超时（nmap --script-timeout 参数）
# 三者关系：script_timeout_sec << host_timeout << nmap_timeout_sec
```

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
    "nmap_timeout_sec": 600,
    "script_timeout_sec": 30,
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
    "nmap_timeout_sec": 1800,
    "script_timeout_sec": 60,
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
    "nmap_timeout_sec": 14400,
    "script_timeout_sec": 120,
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
    "nmap_timeout_sec": 28800,
    "script_timeout_sec": 300,
    "max_retries": 3,
    "min_rate": 200,
    "max_rtt_timeout_ms": 1000,
    "initial_rtt_timeout_ms": 500,
    "max_scan_delay_ms": 20
  }
}
```

预估时间（/24 网段）：60-180 分钟

---

## 十一、扫描任务强健性保障

### 11.1 问题背景

大规模扫描场景（500+ 主机 × 全端口 + 服务识别 + 脚本探测）耗时可能超过一周，期间面临：

| 风险 | 发生概率 | 影响 |
|------|----------|------|
| 服务重启（部署/更新/崩溃） | 高 | 任务中断，进度丢失 |
| 阶段中途崩溃（网络异常/nmap卡死） | 中 | 该阶段从头重跑 |
| 内存溢出（all_results 字典累积） | 中 | OOM 进程被杀 |
| nmap 进程卡死（目标无响应） | 中 | 整个阶段阻塞 |
| DB 连接超时（SQLite 长时间持有 session） | 低 | 写入失败 |
| 磁盘空间不足（scan_results 膨胀） | 低 | 写入失败 |

**核心设计目标：任何阶段、任何时刻中断，重启后都能从断点续跑，不丢失已完成的结果。**

### 11.2 现有机制盘点

| 机制 | 现状 | 覆盖范围 |
|------|------|----------|
| 分块持久化 (ScanChunk) | ✅ 全端口扫描14块，每块完成独立写DB | 仅阶段1全端口扫描 |
| 失败重试 (_retry_failed_chunks) | ✅ 最多重试2次 | 仅 chunk 级别 |
| 增量写入 (persist_host_incremental) | ✅ 每个IP扫完就写DB | 所有阶段 |
| 阶段1 Ping 断点恢复 | ❌ 无 | 死在中间=前面白跑 |
| 阶段1 Top1000 断点恢复 | ❌ 无 | 按组串行，死在中间=前面白跑 |
| 阶段2/3/4 断点恢复 | ❌ 不存在 | — |
| 服务重启恢复 | ❌ scheduler 只恢复定时器，不恢复中断的扫描 | 扫描中重启=任务永远卡 running |
| Celery 超时 | ❌ 未配置 task_time_limit | 无限制，但 worker 重启任务丢失 |
| DB Session 管理 | ⚠️ 单 session 贯穿整个 execute_scan | 长时间持有连接可能超时 |

### 11.3 断点恢复模型

> **架构决策④：checkpoint 拆为独立表**
> 旧方案将 checkpoint/phase_status 存为 ScanTask 的 JSON 列。
> 问题：大JSON每次更新都全量写入，随IP数增长checkpoint可达数MB，
> 每次更新都写整个JSON列 → SQLite WAL 膨胀 + 写入性能差。
> 新方案拆为独立表 `scan_checkpoints(task_id, phase, key, value)`，
> 按key粒度更新，避免全量写入。

#### 11.3.1 数据模型扩展

```python
# models.py ScanTask 新增字段（精简版）

class ScanTask(Base):
    __tablename__ = "scan_tasks"
    
    # ... 现有字段 ...
    
    # --- 断点恢复新增 ---
    current_phase = Column(Integer, default=0)        # 当前阶段 (0=未开始, 1=端口发现, 2=服务识别, 3=脚本扫描, 4=OS识别)
    last_duration_sec = Column(Integer, default=None)  # 上次扫描耗时（秒），用于智能间隔

    # ★ 不再在 ScanTask 上存 checkpoint / phase_status JSON 列
    # ★ 改为独立表 scan_checkpoints（见下方）


# ★ 新增：scan_checkpoints 独立表
class ScanCheckpoint(Base):
    """断点数据独立表 — 按key粒度存储，避免大JSON全量写入"""
    __tablename__ = "scan_checkpoints"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(Integer, ForeignKey("scan_tasks.id"), nullable=False, index=True)
    phase = Column(Integer, nullable=False)             # 阶段编号 (1/2/3/4)
    key = Column(String(64), nullable=False)             # 键名（如 "completed_ips", "open_ports", "status"）
    value = Column(JSON, nullable=True)                  # 值（JSON 格式，按key粒度更新）
    updated_at = Column(DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    # 唯一约束：同一任务同一阶段同一key只有一条记录
    __table_args__ = (
        UniqueConstraint("task_id", "phase", "key", name="uq_checkpoint_task_phase_key"),
    )
```

#### 11.3.2 phase_status 存储结构（scan_checkpoints 表中的记录）

每个阶段的 status 信息存为 scan_checkpoints 表中的一条记录：

| task_id | phase | key | value |
|---------|-------|-----|-------|
| 42 | 1 | "status" | `{"status": "completed", "started_at": "2026-06-01T10:00:00Z", "completed_at": "2026-06-02T08:30:00Z", "hosts_discovered": 523, "open_ports_found": 2847, "duration_sec": 81000}` |
| 42 | 2 | "status" | `{"status": "running", "started_at": "2026-06-02T08:31:00Z", "completed_at": null, "hosts_completed": 280, "hosts_total": 523}` |
| 42 | 3 | "status" | `{"status": "pending"}` |
| 42 | 4 | "status" | `{"status": "skipped"}` |

字段说明：
- `status`: `pending` / `running` / `completed` / `skipped` / `failed`
- `hosts_completed`: 阶段内已完成的IP数（用于进度显示）
- `hosts_total`: 阶段内待处理的IP总数
- `duration_sec`: 阶段耗时，完成后填充，用于预估和智能间隔

#### 11.3.3 checkpoint 数据存储（scan_checkpoints 表中的记录）

| task_id | phase | key | value |
|---------|-------|-----|-------|
| 42 | 1 | "open_ports" | `{"192.168.1.1": [22,80,443], "192.168.1.2": [22,3306], "192.168.1.3": [80,443,8080,8443]}` |
| 42 | 1 | "completed_ips" | `["192.168.1.1", "192.168.1.2", "192.168.1.3"]` |
| 42 | 1 | "chunk_status" | `{"1-5000": "completed", "5001-10000": "completed", "10001-15000": "running"}` |
| 42 | 2 | "completed_ips" | `["192.168.1.1", "192.168.1.2"]` |
| 42 | 3 | "completed_ips" | `[]` |

说明：
- `phase1 / open_ports`: 阶段1成果，作为阶段2/3的输入（端口精准定向）
- `phase* / completed_ips`: 每个阶段已完成的IP列表，恢复时跳过
- `phase1 / chunk_status`: 全端口分块扫描的断点（复用现有 ScanChunk 表，此处为冗余快照）

**优势（vs 旧方案单JSON列）：**
- 按 key 粒度更新：更新 `phase2/completed_ips` 不影响 `phase1/open_ports`
- SQLite 只写变化的那条记录，而非整个 JSON
- 查询方便：`WHERE task_id=? AND phase=? AND key=?` 精准定位

#### 11.3.4 checkpoint 读写函数（独立表版本）

```python
async def _save_checkpoint(
    db: AsyncSession, 
    scan_task_id: int, 
    phase: int, 
    key: str, 
    value: Any,
):
    """保存断点数据到 scan_checkpoints 表（按key粒度更新）"""
    async with _db_lock:
        # UPSERT：存在则更新，不存在则插入
        existing = await db.execute(
            select(ScanCheckpoint).where(
                ScanCheckpoint.task_id == scan_task_id,
                ScanCheckpoint.phase == phase,
                ScanCheckpoint.key == key,
            )
        )
        record = existing.scalar_one_or_none()
        
        if record:
            record.value = value
            record.updated_at = datetime.now(timezone.utc)
        else:
            record = ScanCheckpoint(
                task_id=scan_task_id,
                phase=phase,
                key=key,
                value=value,
            )
            db.add(record)
        
        await db.commit()


async def _load_checkpoint(
    db: AsyncSession,
    scan_task_id: int,
    phase: int,
    key: str,
) -> Any | None:
    """读取单条断点数据"""
    result = await db.execute(
        select(ScanCheckpoint.value).where(
            ScanCheckpoint.task_id == scan_task_id,
            ScanCheckpoint.phase == phase,
            ScanCheckpoint.key == key,
        )
    )
    return result.scalar_one_or_none()


async def _load_all_checkpoints(
    db: AsyncSession,
    scan_task_id: int,
) -> dict[int, dict[str, Any]]:
    """加载任务所有断点数据（用于恢复时一次性读取）
    
    Returns:
        { phase: { key: value, ... }, ... }
        例: { 1: {"open_ports": {...}, "completed_ips": [...]}, 2: {"completed_ips": [...]} }
    """
    result = await db.execute(
        select(ScanCheckpoint).where(
            ScanCheckpoint.task_id == scan_task_id,
        )
    )
    checkpoints = {}
    for record in result.scalars().all():
        if record.phase not in checkpoints:
            checkpoints[record.phase] = {}
        checkpoints[record.phase][record.key] = record.value
    return checkpoints


async def _update_phase_status(db: AsyncSession, scan_task_id: int, 
                                phase: int, status: str, **kwargs):
    """更新阶段状态（写入 scan_checkpoints 表）"""
    async with _db_lock:
        # 读取当前 status 值
        existing_value = await _load_checkpoint(db, scan_task_id, phase, "status")
        if existing_value is None:
            existing_value = {}
        
        existing_value["status"] = status
        for k, v in kwargs.items():
            existing_value[k] = v
        
        await _save_checkpoint(db, scan_task_id, phase, "status", existing_value)
        
        # 同时更新 ScanTask.current_phase（轻量更新）
        scan_task = await db.get(ScanTask, scan_task_id)
        if scan_task:
            scan_task.current_phase = phase
            await db.commit()
```

### 11.4 断点恢复执行流程

#### 11.4.1 execute_scan 改造

```python
async def execute_scan(scan_task_id: int, progress_callback=None, celery_task_id: str | None = None):
    async with async_session() as db:
        scan_task = await db.get(ScanTask, scan_task_id)
        if not scan_task:
            return

        # 判断是否断点恢复
        checkpoints = await _load_all_checkpoints(db, scan_task_id)
        is_resume = (scan_task.current_phase > 0 
                     and checkpoints 
                     and scan_task.status == ScanStatus.running)
        
        if is_resume:
            start_phase = scan_task.current_phase
            phase1_completed = len(checkpoints.get(1, {}).get("completed_ips", []))
            phase2_completed = len(checkpoints.get(2, {}).get("completed_ips", []))
            await _append_log(db, scan_task, 
                f"从断点恢复，阶段 {start_phase} 继续执行 "
                f"(checkpoint: phase1完成IP {phase1_completed}, "
                f"phase2完成IP {phase2_completed})")
        else:
            # 全新任务
            scan_task.status = ScanStatus.running
            scan_task.started_at = datetime.now(timezone.utc)
            scan_task.progress = 0
            scan_task.scan_log = [{"ts": datetime.now(timezone.utc).isoformat(), "msg": "任务开始执行"}]
            scan_task.current_phase = 1
            if celery_task_id:
                scan_task.celery_task_id = celery_task_id
            async with _db_lock:
                await db.commit()
            checkpoints = {}
            start_phase = 1

        # 获取 profile（新引擎）或走旧引擎
        profile = None
        if scan_task.scan_profile_id:
            profile = await db.get(ScanProfile, scan_task.scan_profile_id)

        try:
            if profile:
                # 新引擎：渐进式自动探测（带断点恢复）
                await run_service_discovery(
                    scan_task=scan_task, profile=profile,
                    checkpoints=checkpoints, start_phase=start_phase if is_resume else 1,
                    db=db, scan_task_id=scan_task_id,
                    progress_callback=progress_callback,
                )
            else:
                # 旧引擎：兼容 scan_methods 模式（无断点恢复）
                await _run_legacy_scan(scan_task, db, ...)

            scan_task.status = ScanStatus.completed
            await _append_log(db, scan_task, "任务成功完成")

        except asyncio.CancelledError:
            # 优雅取消：当前断点已在各阶段内按key保存，无需额外操作
            scan_task.status = ScanStatus.cancelled
            await _append_log(db, scan_task, 
                f"任务被取消（阶段 {scan_task.current_phase}，断点已保存）")
            
        except Exception as e:
            # 异常：当前断点已在各阶段内按key保存，标记失败但可恢复
            scan_task.status = ScanStatus.failed
            scan_task.error_message = str(e)
            await _append_log(db, scan_task, f"任务异常: {e}（断点已保存，可恢复）")

        scan_task.completed_at = datetime.now(timezone.utc)
        scan_task.progress = 100
        scan_task.last_duration_sec = int(
            (scan_task.completed_at - scan_task.started_at).total_seconds()
        )
        async with _db_lock:
            await db.commit()
```

#### 11.4.2 run_service_discovery 改造

```python
async def run_service_discovery(
    scan_task: ScanTask, profile: ScanProfile,
    checkpoints: dict, start_phase: int,
    db: AsyncSession, scan_task_id: int,
    progress_callback=None,
):
    """渐进式服务发现主流程（带断点恢复）
    
    checkpoints 格式: { phase: { key: value, ... }, ... }
    由 _load_all_checkpoints() 从 scan_checkpoints 表加载
    """
    targets = scan_task.targets
    scan_mode_val = scan_task.scan_mode.value
    max_concurrent = scan_task.max_concurrent

    # ========================================
    # 阶段1: 端口发现（从断点恢复）
    # ========================================
    if start_phase <= 1:
        await _update_phase_status(db, scan_task_id, 1, "running",
                                   started_at=datetime.now(timezone.utc).isoformat())

        # 阶段1内部也有断点（chunk级已有，IP级新增）
        phase1_results = await _phase1_port_scan_with_checkpoint(
            targets, scan_mode_val, profile, max_concurrent,
            scan_task_id, db, scan_task, checkpoints,
        )

        # 阶段1完成后，汇总 open_ports_map 写入 checkpoint（独立表按key存储）
        await _save_checkpoint(db, scan_task_id, 1, "open_ports", phase1_results["open_ports_map"])
        await _save_checkpoint(db, scan_task_id, 1, "completed_ips", list(phase1_results["open_ports_map"].keys()))

        hosts_discovered = len(phase1_results["open_ports_map"])
        open_ports_found = sum(len(v) for v in phase1_results["open_ports_map"].values())
        await _update_phase_status(db, scan_task_id, 1, "completed",
                                   completed_at=datetime.now(timezone.utc).isoformat(),
                                   hosts_discovered=hosts_discovered,
                                   open_ports_found=open_ports_found,
                                   duration_sec=phase1_results["duration_sec"])

    # ========================================
    # 阶段2+3: 服务识别 + 脚本扫描（始终合并执行）
    # ========================================
    # ★ 从独立表读取 phase1 的 open_ports（如刚完成则用内存中的，如恢复则从DB读）
    open_ports_map = checkpoints.get(1, {}).get("open_ports")
    if open_ports_map is None:
        open_ports_map = await _load_checkpoint(db, scan_task_id, 1, "open_ports") or {}
    
    if not open_ports_map:
        await _append_log(db, scan_task, "阶段1未发现开放端口，跳过后续阶段")
        return

    svc_enabled = profile.service_detect.get("enabled", False)
    script_enabled = profile.script_scan.get("enabled", False)

    if start_phase <= 2 and (svc_enabled or script_enabled):
        phase_num = 2
        await _update_phase_status(db, scan_task_id, phase_num, "running",
                                   started_at=datetime.now(timezone.utc).isoformat())

        await _phase23_service_and_script_with_checkpoint(
            open_ports_map, profile, scan_mode_val, max_concurrent,
            scan_task_id, db, scan_task, checkpoints,
        )

        await _update_phase_status(db, scan_task_id, phase_num, "completed",
                                   completed_at=datetime.now(timezone.utc).isoformat())

    # ========================================
    # 阶段4: OS识别
    # ========================================
    os_enabled = profile.os_detect.get("enabled", False)
    if start_phase <= 4 and os_enabled:
        await _update_phase_status(db, scan_task_id, 4, "running",
                                   started_at=datetime.now(timezone.utc).isoformat())

        await _phase4_os_detect_with_checkpoint(
            open_ports_map, profile, scan_mode_val, max_concurrent,
            scan_task_id, db, scan_task, checkpoints,
        )

        await _update_phase_status(db, scan_task_id, 4, "completed",
                                   completed_at=datetime.now(timezone.utc).isoformat())
```

#### 11.4.3 阶段内断点恢复（以阶段2为例）

```python
async def _phase23_service_and_script_with_checkpoint(
    open_ports_map, profile, scan_mode, max_concurrent,
    scan_task_id, db, scan_task, checkpoints,
):
    """阶段2/3 服务识别+脚本扫描，带IP粒度断点"""
    
    # 获取已完成IP，计算剩余（从独立表读取）
    completed_ips = set(await _load_checkpoint(db, scan_task_id, 2, "completed_ips") or [])
    remaining = {ip: ports for ip, ports in open_ports_map.items() 
                 if ip not in completed_ips}
    
    if not remaining:
        await _append_log(db, scan_task, "阶段2/3 已全部完成，跳过")
        return
    
    await _append_log(db, scan_task, 
        f"阶段2/3 开始, {len(remaining)} 个IP待扫描 "
        f"(已完成 {len(completed_ips)}/{len(open_ports_map)})")
    
    # 选择执行策略
    executor = profile.timing.get("phase_executor", "grouped")
    
    if executor == "serial":
        # 方案A：逐IP串行
        total = len(remaining)
        for i, (ip, ports) in enumerate(remaining.items()):
            try:
                args = _build_phase23_args(ip, ports, profile)
                results = await _run_nmap_with_timeout(
                    ip, args, timeout_sec=3600,
                    scan_task_id=scan_task_id, db=db, scan_task=scan_task,
                )
                # 持久化结果
                for r in results:
                    await persist_host_incremental(db, scan_task_id, ip, r)
                
                # 更新断点（独立表按key保存）
                completed_ips.add(ip)
                await _save_checkpoint(db, scan_task_id, 2, "completed_ips", list(completed_ips))
                
            except Exception as e:
                logger.warning(f"Phase2/3 failed for {ip}: {e}")
                # 单IP失败不阻塞，继续下一个
                await _append_log(db, scan_task, f"IP {ip} 扫描失败: {e}（跳过，后续可补扫）")
            
            # 更新进度
            progress_in_phase = int((i + 1) / total * 100)
            await _update_phase_status(db, scan_task_id, 2, "running",
                                       hosts_completed=len(completed_ips),
                                       hosts_total=len(open_ports_map))
    
    else:  # "grouped"
        # 方案B：分组并行
        ip_list = list(remaining.keys())
        ip_groups = _split_ips_into_groups(ip_list, max_concurrent)
        
        for group_idx, ip_group in enumerate(ip_groups):
            try:
                # 组内端口取并集
                group_ports = set()
                for ip in ip_group:
                    group_ports.update(remaining.get(ip, []))
                port_spec = ",".join(str(p) for p in sorted(group_ports))
                targets = " ".join(ip_group)
                
                args = _build_phase23_args(targets, port_spec, profile, is_group=True)
                results = await _run_nmap_with_timeout(
                    targets, args, timeout_sec=3600,
                    scan_task_id=scan_task_id, db=db, scan_task=scan_task,
                )
                
                # 持久化
                for r in results:
                    r_ip = r.get("ip")
                    if r_ip:
                        await persist_host_incremental(db, scan_task_id, r_ip, r)
                
                # 更新断点（整组完成，独立表按key保存）
                for ip in ip_group:
                    completed_ips.add(ip)
                await _save_checkpoint(db, scan_task_id, 2, "completed_ips", list(completed_ips))
                
            except Exception as e:
                logger.warning(f"Phase2/3 group {group_idx} failed: {e}")
                await _append_log(db, scan_task, 
                    f"组 {group_idx+1} 扫描失败: {e}（跳过，后续可补扫）")
            
            await _update_phase_status(db, scan_task_id, 2, "running",
                                       hosts_completed=len(completed_ips),
                                       hosts_total=len(open_ports_map))
```

### 11.5 服务重启恢复

```python
# main.py 启动时
@app.on_event("startup")
async def startup():
    await init_db()
    await scheduler_service.start()
    await _recover_interrupted_tasks()  # 新增


async def _recover_interrupted_tasks():
    """恢复中断的扫描任务
    
    扫描中服务重启 → 任务 status=running 但实际已停止
    根据 checkpoint 决定是自动恢复还是标记失败
    """
    async with async_session() as db:
        result = await db.execute(
            select(ScanTask).where(ScanTask.status == ScanStatus.running)
        )
        interrupted = result.scalars().all()
        
        if not interrupted:
            return
        
        logger.info(f"发现 {len(interrupted)} 个中断任务，尝试恢复")
        
        for task in interrupted:
            # 从独立表读取断点数据
            checkpoints = await _load_all_checkpoints(db, task.id)
            
            # 有断点数据 → 自动恢复
            if task.current_phase and task.current_phase > 0 and checkpoints:
                p1_ips = len(checkpoints.get(1, {}).get("completed_ips", []))
                p2_ips = len(checkpoints.get(2, {}).get("completed_ips", []))
                logger.info(f"恢复任务 {task.id}: 从阶段 {task.current_phase} 继续 "
                           f"(已完成IP: phase1={p1_ips}, phase2={p2_ips})")
                
                # 异步启动恢复，不阻塞其他启动流程
                asyncio.create_task(execute_scan(task.id))
            
            # 旧任务无断点 → 标记为可重试的失败
            else:
                task.status = ScanStatus.failed
                task.error_message = "服务重启导致任务中断（无断点数据），请重新执行"
                await _append_log(db, task, "服务重启导致中断，无断点可恢复")
                async with _db_lock:
                    await db.commit()
```

### 11.6 内存保护

#### 11.6.1 问题

当前 `execute_scan` 在内存中维护 `all_results` 字典，随扫描进行不断膨胀：

```
500主机 × 平均10端口 × 每端口 ~500字节数据 ≈ 2.5MB（纯数据）
加上 Python dict 开销 ≈ 10-15MB
如果全端口(每主机100+端口) ≈ 50MB+
```

一周运行期间，内存持续增长，可能 OOM。

#### 11.6.2 方案：结果直写DB，内存只保留 checkpoint

```python
# ===== 旧方式（内存累积）=====
all_results = {}
# ... 扫描 ...
all_results[ip] = result  # 越来越大
# 最后统一写DB

# ===== 新方式（直写DB + 独立表 checkpoint）=====
# 结果立即写DB
await persist_host_incremental(db, scan_task_id, ip, result)

# 阶段1完成后，open_ports 按key写入 scan_checkpoints 独立表
await _save_checkpoint(db, scan_task_id, 1, "open_ports", open_ports_map)

# 内存中只在当前阶段内维护轻量的 working set
# （如：当前分组的端口列表、已完成的IP set）
# 阶段完成后即清空，从 DB 读取下一阶段输入

# 估算内存占用：
# 工作集：当前组 20IP × 平均10端口 × 端口号(int=28bytes) ≈ 5.6KB
# checkpoint独立表：不再在内存中维护
# vs 旧方式 10-50MB
# 内存降低 100-350 倍
```

#### 11.6.3 结果汇总查询

去掉 `all_results` 后，需要从 DB 查询汇总：

```python
async def _get_scan_summary(db: AsyncSession, scan_task_id: int) -> dict:
    """从DB查询扫描结果摘要（替代内存 all_results）"""
    from sqlalchemy import func
    
    # 总主机数
    host_count = await db.execute(
        select(func.count(func.distinct(ScanResult.ip)))
        .where(ScanResult.scan_task_id == scan_task_id)
    )
    
    # 总端口数
    port_count = await db.execute(
        select(func.count(ScanResult.id))
        .where(ScanResult.scan_task_id == scan_task_id)
    )
    
    return {
        "total_hosts": host_count.scalar() or 0,
        "total_ports": port_count.scalar() or 0,
    }
```

### 11.7 nmap 进程卡死保护

#### 11.7.1 超时控制

```python
async def _run_nmap_with_timeout(
    targets: str, args: str,
    timeout_sec: int = 3600,      # 默认1小时超时
    scan_task_id: int = 0,
    db: AsyncSession = None,
    scan_task: ScanTask = None,
) -> list[dict]:
    """带超时的 nmap 执行，防止进程卡死"""
    scanner_cls = SCANNER_REGISTRY.get("nmap_syn")
    scanner = scanner_cls()
    
    try:
        results = await asyncio.wait_for(
            scanner.scan_with_args(targets, args),
            timeout=timeout_sec,
        )
        return results
    
    except asyncio.TimeoutError:
        logger.warning(f"nmap 扫描超时 ({timeout_sec}s): {targets}")
        if db and scan_task:
            await _append_log(db, scan_task, 
                f"扫描超时 ({timeout_sec}s): {targets}，强制终止")
        
        # 清理残留 nmap 进程
        await _kill_orphan_nmap_processes(scan_task_id)
        raise
    
    except asyncio.CancelledError:
        # 任务被取消，清理进程
        await _kill_orphan_nmap_processes(scan_task_id)
        raise


async def _kill_orphan_nmap_processes(scan_task_id: int = 0):
    """清理残留的 nmap 进程"""
    import psutil
    
    for proc in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
        try:
            if proc.info["name"] == "nmap":
                # 可选：只杀属于当前任务的 nmap（通过 cmdline 判断）
                # 简单策略：杀掉所有运行超过2小时的 nmap
                create_time = proc.info.get("create_time", 0)
                if create_time and (time.time() - create_time > 7200):
                    proc.kill()
                    logger.info(f"清理残留 nmap 进程: PID={proc.info['pid']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
```

#### 11.7.2 超时配置

```python
# profile.timing 中的超时字段（完整列表见 §3.1）
"host_timeout": 300,           # 单主机超时(秒)，0=不限 → --host-timeout
"nmap_timeout_sec": 7200,     # nmap进程整体超时(秒) → asyncio.wait_for 层面
"script_timeout_sec": 60,     # 单个NSE脚本超时(秒) → --script-timeout

# ★ 超时层次: script_timeout_sec << host_timeout << nmap_timeout_sec
#   - script_timeout_sec 防止单个NSE脚本卡死（默认60s）
#   - host_timeout 防止单主机不可达时浪费时间（默认300s）
#   - nmap_timeout_sec 是最终安全网，防止nmap进程整体卡死（默认7200s）

# 内置预设默认值
# 快速探测: nmap_timeout_sec=600,  script_timeout_sec=30
# 标准探测: nmap_timeout_sec=1800, script_timeout_sec=60
# 深度探测: nmap_timeout_sec=14400,script_timeout_sec=120
# 安全审计: nmap_timeout_sec=28800,script_timeout_sec=300
```

### 11.8 DB Session 长连接保护

#### 11.8.1 问题

当前 `execute_scan` 在一个 `async with async_session() as db` 中执行所有阶段，一周运行期间 SQLite 可能：
- 连接超时
- 写锁冲突（其他请求访问DB时）
- WAL 文件膨胀

#### 11.8.2 方案：阶段/组粒度独立 session

```python
async def run_service_discovery(scan_task, profile, checkpoints, ...):
    # 阶段1
    if start_phase <= 1:
        async with async_session() as db:           # 阶段1独立 session
            scan_task = await db.get(ScanTask, scan_task_id)
            await _phase1_port_scan_with_checkpoint(...)
            # checkpoint 已在各阶段内按key写入独立表，无需额外保存
    
    # 阶段2/3
    if start_phase <= 2:
        async with async_session() as db:           # 阶段2独立 session
            scan_task = await db.get(ScanTask, scan_task_id)
            await _phase23_service_and_script_with_checkpoint(...)
            # checkpoint 已在各阶段内按key写入独立表，无需额外保存
    
    # 阶段4
    if start_phase <= 4:
        async with async_session() as db:           # 阶段4独立 session
            scan_task = await db.get(ScanTask, scan_task_id)
            await _phase4_os_detect_with_checkpoint(...)
            # checkpoint 已在各阶段内按key写入独立表，无需额外保存
```

组粒度（阶段内每组IP用独立 session）：

```python
async def _phase23_service_and_script_with_checkpoint(...):
    for ip_group in ip_groups:
        async with async_session() as db:           # 每组独立 session
            scan_task = await db.get(ScanTask, scan_task_id)
            results = await _run_nmap_with_timeout(...)
            for r in results:
                r_ip = r.get("ip")
                if r_ip:
                    await persist_host_incremental(db, scan_task_id, r_ip, r)
            
            # 更新断点（独立表按key保存）
            for ip in ip_group:
                completed_ips.add(ip)
            await _save_checkpoint(db, scan_task_id, 2, "completed_ips", list(completed_ips))
```

### 11.9 任务取消与优雅退出

```python
# scan_executor.py 全局取消信号
_cancel_events: dict[int, asyncio.Event] = {}


def request_cancel(scan_task_id: int):
    """请求取消扫描任务"""
    if scan_task_id in _cancel_events:
        _cancel_events[scan_task_id].set()


async def _check_cancelled(scan_task_id: int):
    """检查是否被请求取消"""
    if scan_task_id in _cancel_events and _cancel_events[scan_task_id].is_set():
        raise asyncio.CancelledError(f"任务 {scan_task_id} 被用户取消")


# 在每个 nmap 调用前检查
async def _phase23_service_and_script_with_checkpoint(...):
    for ip_group in ip_groups:
        await _check_cancelled(scan_task_id)    # 检查取消信号
        
        results = await _run_nmap_with_timeout(...)
        ...
```

取消流程：
1. 用户点击取消 → API 调用 `request_cancel(task_id)`
2. 当前 nmap 调用完成后（不会中途杀进程），检查到取消信号
3. 保存当前 checkpoint
4. 标记任务 `status=cancelled`
5. 前端显示"已取消，可从断点恢复继续"

### 11.10 周期扫描强健性

#### 11.10.1 改造后的 scheduler

```python
class SchedulerService:
    def __init__(self):
        self._periodic_tasks: dict[int, asyncio.Task] = {}
        self._running = False
        self._semaphore = asyncio.Semaphore(2)  # 最多同时2个周期任务

    async def _run_periodic(self, scan_task_id: int, interval_minutes: int):
        from app.services.scan_executor import execute_scan

        while self._running:
            start_time = time.monotonic()

            # 信号量控制并发
            async with self._semaphore:
                try:
                    await execute_scan(scan_task_id)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Periodic scan {scan_task_id} error: {e}")

            # 计算实际耗时
            elapsed_sec = time.monotonic() - start_time

            # 更新任务元数据
            async with async_session() as db:
                result = await db.execute(
                    select(ScanTask).where(ScanTask.id == scan_task_id)
                )
                task = result.scalar_one_or_none()
                if not task or not task.is_active or task.scan_type != ScanType.periodic:
                    break

                task.last_run = datetime.now(timezone.utc)
                task.last_duration_sec = int(elapsed_sec)

                # 智能间隔：根据耗时动态调整
                if task.smart_interval:
                    suggested = self._suggest_interval(elapsed_sec, task)
                    task.next_run = datetime.now(timezone.utc) + timedelta(seconds=suggested)
                    remaining = max(10, suggested - elapsed_sec)
                else:
                    task.next_run = datetime.now(timezone.utc) + timedelta(minutes=interval_minutes)
                    remaining = max(10, interval_minutes * 60 - elapsed_sec)

                await db.commit()

            # 等待剩余间隔（保证一轮完成后再等）
            await asyncio.sleep(remaining)

        self._periodic_tasks.pop(scan_task_id, None)

    @staticmethod
    def _suggest_interval(last_duration_sec: int, task: ScanTask) -> int:
        """根据上次耗时和策略复杂度建议间隔（秒）"""
        try:
            profile = task.scan_profile  # 如果有关联 profile
            phase_count = 1
            if profile and profile.service_detect.get("enabled"): phase_count += 1
            if profile and profile.script_scan.get("enabled"): phase_count += 1
            if profile and profile.os_detect.get("enabled"): phase_count += 1
        except Exception:
            phase_count = 2  # 默认保守估计
        
        multiplier = 1.5 + phase_count * 0.5   # 2.0 ~ 3.5
        buffer_sec = 300                         # 5分钟缓冲
        suggested_sec = max(600, int(last_duration_sec * multiplier) + buffer_sec)
        return min(suggested_sec, 7 * 24 * 3600)  # 最长7天
```

#### 11.10.2 周期扫描任务模型扩展

```python
# ScanTask 新增字段
smart_interval = Column(Boolean, default=True)  # 智能间隔模式
```

前端 UI：
```
扫描周期:
  ○ 智能建议 ← 默认
    上次耗时: 8分23秒 | 推荐间隔: 约30分钟
  ○ 固定间隔
    间隔: [60] 分钟
```

### 11.11 磁盘空间保护（可选）

```python
async def _check_disk_space(min_gb: float = 1.0) -> bool:
    """检查磁盘可用空间"""
    import shutil
    usage = shutil.disk_usage(".")
    available_gb = usage.free / (1024 ** 3)
    if available_gb < min_gb:
        logger.error(f"磁盘空间不足: {available_gb:.1f}GB < {min_gb}GB")
        return False
    return True


# 在 execute_scan 开头检查
if not await _check_disk_space(min_gb=2.0):
    scan_task.status = ScanStatus.failed
    scan_task.error_message = "磁盘空间不足（<2GB），请清理后重试"
    await db.commit()
    return
```

### 11.12 阶段1端口发现的断点恢复

阶段1已有 ScanChunk 机制（全端口分块），但 Ping 和 Top1000 模式缺少断点。

#### 11.11.1 Top1000 模式断点

```python
async def _phase1_top1000_with_checkpoint(
    targets, scan_mode, max_concurrent,
    scan_task_id, db, scan_task, checkpoints,
):
    """Top1000 端口发现，带IP组粒度断点"""
    
    ip_list = _expand_targets_to_ips(targets)
    completed_ips = set(await _load_checkpoint(db, scan_task_id, 1, "completed_ips") or [])
    remaining_ips = [ip for ip in ip_list if ip not in completed_ips]
    
    if not remaining_ips:
        await _append_log(db, scan_task, "阶段1 Top1000 已全部完成，跳过")
        return
    
    await _append_log(db, scan_task, 
        f"阶段1 Top1000: {len(remaining_ips)} IP待扫描 "
        f"(已完成 {len(completed_ips)}/{len(ip_list)})")
    
    # ... 执行扫描逻辑（同 _phase23 的 serial/grouped 模式）...
    
    # 每完成一个IP/组，更新 checkpoint（独立表按key保存）
    completed_ips.add(ip)
    await _save_checkpoint(db, scan_task_id, 1, "completed_ips", list(completed_ips))
```

#### 11.11.2 全端口分块模式断点

现有 ScanChunk 已提供分块级断点，补充 IP 组级断点即可：

```python
async def _phase1_full_scan_with_checkpoint(
    targets, scan_mode, max_concurrent,
    scan_task_id, db, scan_task, checkpoints,
):
    """全端口分块扫描，已有 chunk 机制 + 新增 IP 组断点"""
    
    # 确保分块记录存在
    await _ensure_chunks(db, scan_task_id, scan_task)
    
    # 重试失败分块
    await _retry_failed_chunks(db, scan_task_id, scan_task)
    
    # 获取待处理分块
    result = await db.execute(
        select(ScanChunk).where(
            ScanChunk.scan_task_id == scan_task_id,
            ScanChunk.status == ScanChunkStatus.pending,
        ).order_by(ScanChunk.port_start)
    )
    pending_chunks = result.scalars().all()
    
    if not pending_chunks:
        # 所有分块完成，从 ScanChunk 汇总 open_ports_map，写入独立表
        open_ports_map = await _collect_open_ports_from_chunks(db, scan_task_id)
        await _save_checkpoint(db, scan_task_id, 1, "open_ports", open_ports_map)
        await _save_checkpoint(db, scan_task_id, 1, "completed_ips", list(open_ports_map.keys()))
        return
    
    # 执行分块扫描（现有逻辑，略）
    # 每个分块完成后增量更新 open_ports（独立表按key保存）
    for chunk in pending_chunks:
        # ... 扫描 ...
        chunk.status = ScanChunkStatus.completed
        await db.commit()
        
        # 增量更新 open_ports 到独立表
        await _update_open_ports_from_chunk(db, scan_task_id, chunk)
```

### 11.13 强健性保障清单总览

| 风险 | 保障机制 | 粒度 | 优先级 |
|------|----------|------|--------|
| 服务重启 | 阶段级 checkpoint + 启动自动恢复 | 阶段 | 🔴 必须 |
| 阶段中途崩溃 | 阶段内按IP/组粒度 checkpoint | IP/组 | 🔴 必须 |
| 全端口分块失败 | ScanChunk 重试机制（已有） | 分块 | ✅ 已有 |
| 内存溢出 | 去掉 all_results，结果直写DB | 全局 | 🔴 必须 |
| nmap 进程卡死 | asyncio.wait_for 超时 + 孤儿进程清理 | 调用 | 🟡 重要 |
| DB 连接超时 | 每组IP独立 session | 组 | 🟡 重要 |
| 任务取消 | 取消信号 + 优雅退出 + 保存断点 | 阶段 | 🟡 重要 |
| 周期任务重叠 | await 完成再 sleep + 信号量 | 任务 | 🔴 必须 |
| 磁盘空间不足 | 扫描前检查 + 阈值告警 | 全局 | 🟢 可选 |
| 单IP失败阻塞 | 单IP失败跳过，记录错误，不中断阶段 | IP | 🟡 重要 |

### 11.14 数据库迁移

```python
# alembic/versions/xxx_add_checkpoint_fields.py

def upgrade():
    # ScanTask 新增字段
    op.add_column('scan_tasks', sa.Column('current_phase', sa.Integer(), nullable=True, server_default='0'))
    op.add_column('scan_tasks', sa.Column('last_duration_sec', sa.Integer(), nullable=True))
    op.add_column('scan_tasks', sa.Column('smart_interval', sa.Boolean(), nullable=True, server_default='1'))
    
    # 创建 scan_checkpoints 独立表
    op.create_table(
        'scan_checkpoints',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('task_id', sa.Integer(), sa.ForeignKey('scan_tasks.id'), nullable=False, index=True),
        sa.Column('phase', sa.Integer(), nullable=False),
        sa.Column('key', sa.String(64), nullable=False),
        sa.Column('value', sa.JSON(), nullable=True),
        sa.Column('updated_at', sa.DateTime()),
        sa.UniqueConstraint('task_id', 'phase', 'key', name='uq_checkpoint_task_phase_key'),
    )


def downgrade():
    op.drop_table('scan_checkpoints')
    op.drop_column('scan_tasks', 'smart_interval')
    op.drop_column('scan_tasks', 'last_duration_sec')
    op.drop_column('scan_tasks', 'current_phase')
```

### 11.15 前端进度展示改造

#### 11.15.1 任务详情页

```
┌─ 扫描任务 #42 ──────────────────────────────────────────┐
│                                                          │
│  状态: 执行中 ████████████░░░░░░ 68%                     │
│                                                          │
│  阶段进度:                                               │
│  ├─ ✅ 阶段1: 端口发现       (523/523主机)  完成 22h15m  │
│  ├─ 🔄 阶段2: 服务识别       (356/523主机)  执行中...    │
│  │   当前: 192.168.3.120 (组 18/27)                      │
│  ├─ ⏳ 阶段3: 脚本扫描       等待中                       │
│  └─ ⏭ 阶段4: OS识别         跳过(未启用)                 │
│                                                          │
│  [暂停] [取消] [查看日志]                                 │
└──────────────────────────────────────────────────────────┘
```

#### 11.15.2 断点恢复提示

```
┌─ 扫描任务 #42 ──────────────────────────────────────────┐
│                                                          │
│  ⚠️ 上次扫描在阶段2中断（已完成 356/523 主机）            │
│                                                          │
│  [从断点恢复]  [重新开始]  [取消]                         │
│                                                          │
│  提示：从断点恢复将跳过已完成的356个主机，节省约16小时     │
└──────────────────────────────────────────────────────────┘
```

#### 11.15.3 API 扩展

```python
# GET /api/service-discovery/tasks/{task_id}/progress
{
    "task_id": 42,
    "status": "running",
    "progress": 68,
    "current_phase": 2,
    "phase_status": {
        "phase1": {
            "status": "completed",
            "hosts_completed": 523,
            "hosts_total": 523,
            "duration_sec": 80100
        },
        "phase2": {
            "status": "running",
            "hosts_completed": 356,
            "hosts_total": 523,
            "current_group": "18/27"
        },
        "phase3": { "status": "pending" },
        "phase4": { "status": "skipped" }
    },
    "checkpoint_info": {
        "can_resume": true,
        "phase1_completed_ips": 523,
        "phase2_completed_ips": 356
    },
    "elapsed_sec": 97200,
    "estimated_remaining_sec": 43200
}
```

```python
# POST /api/service-discovery/tasks/{task_id}/resume
# 从断点恢复执行

# POST /api/service-discovery/tasks/{task_id}/restart
# 忽略断点，重新开始
```

### 11.16 依赖项新增

```txt
# requirements.txt 新增
psutil>=5.9.0       # 进程管理（nmap 孤儿进程清理）
```

无需其他外部依赖，所有核心机制基于 asyncio + SQLAlchemy + SQLite 原生能力。

### 11.17 实现优先级与里程碑

| 阶段 | 内容 | 预估工时 | 依赖 |
|------|------|----------|------|
| **M1: 数据模型** | ScanTask 新增字段 + 迁移脚本 | 0.5天 | 无 |
| **M2: 断点核心** | checkpoint 读写 + execute_scan 改造 + 阶段级恢复 | 2天 | M1 |
| **M3: 阶段内断点** | IP/组粒度断点 + 阶段1 Ping/Top1000/全端口断点 | 2天 | M2 |
| **M4: 重启恢复** | _recover_interrupted_tasks + 启动流程集成 | 0.5天 | M2 |
| **M5: 内存优化** | 去掉 all_results + 结果直写DB + 汇总查询 | 1天 | M2 |
| **M6: 进程保护** | nmap 超时 + 孤儿进程清理 | 0.5天 | M2 |
| **M7: Session 管理** | 阶段/组粒度独立 session | 0.5天 | M5 |
| **M8: 取消机制** | 取消信号 + 优雅退出 | 0.5天 | M2 |
| **M9: 周期扫描** | scheduler 改造 + 智能间隔 | 1天 | M2+M4 |
| **M10: 前端适配** | 进度展示 + 断点恢复UI + API | 2天 | M2-M9 |
| **M11: 测试验证** | 模拟中断恢复 + 大规模压力测试 | 2天 | 全部 |

**总计约 12.5 天**，核心路径 M1→M2→M3→M4→M5（约6天），其余可并行。