# 主机发现完整逻辑思维导图

> 基于 commit `c526f6d` 代码梳理
> 可视化版: [host_discovery_mindmap.svg](./host_discovery_mindmap.svg)

---

```
主机发现
├── 前端 UI
│   ├── 表单字段
│   │   ├── 任务名称
│   │   ├── 扫描目标 (IP/CIDR/域名)
│   │   ├── 扫描类型 (一次性/周期)
│   │   ├── 扫描策略
│   │   │   ├── standard: 分块并行扫描
│   │   │   └── ip_sequential: 逐IP分端口扫描
│   │   ├── 发现方法: 固定文字 "Ping探测 → Top1000端口发现"
│   │   └── 并发数 (1-16 滑块)
│   └── 提交 payload
│       ├── name / targets / scan_type
│       ├── scan_mode / max_concurrent
│       ├── scan_category: 'host_discovery'
│       └── ❌ 无 scan_methods (已清理)
│
├── 后端 API
│   ├── POST /api/host-scans/
│   │   ├── scan_methods 存空列表 (主机发现固定两阶段，不参与调度)
│   │   └── 调度 _dispatch_scan
│   └── _dispatch_scan
│       ├── 优先 Celery: run_scan_task.delay(id, targets, scan_mode, ports)
│       └── 回退 asyncio: execute_scan(task_id)
│
├── 执行器 scan_executor
│   ├── execute_scan()
│   │   ├── 读 scan_category → 判断为主机发现
│   │   └── 统一调用 run_host_discovery(scan_mode)
│   │
│   ├── run_host_discovery()
│   │   ├── 阶段1: _phase1_ping  (0-30% 进度)
│   │   └── 阶段2: _phase2_top1000 (30-100% 进度)
│   │
│   ├── _phase1_ping (scan_method=nmap_ping)
│   │   ├── SCANNER_REGISTRY["nmap_ping"] → NmapScanner
│   │   ├── 展开目标为 IP 列表
│   │   ├── standard 模式: 分组串行
│   │   │   ├── 每 max_concurrent 个IP为一组
│   │   │   ├── 组内多IP合并为 1 次 nmap 调用
│   │   │   └── ⚠️ 组间串行执行 (不是"同时扫描")
│   │   └── ip_sequential 模式: 逐IP并发
│   │       ├── Semaphore(max_concurrent) 控制
│   │       ├── 每IP单独 1 次 nmap 调用
│   │       └── ✅ IP间真正并行
│   │
│   └── _phase2_top1000 (scan_method=nmap_syn, top_ports=1000)
│       ├── SCANNER_REGISTRY["nmap_syn"] → NmapScanner
│       ├── 展开目标为 IP 列表
│       ├── skip_no_ports=True (跳过无开放端口的主机)
│       ├── standard 模式: 分组串行 (同阶段1)
│       └── ip_sequential 模式: 逐IP并发 (同阶段1)
│
├── 扫描器 NmapScanner
│   ├── scan() 入口分派
│   │   ├── nmap_ping → _build_ping_args() → 同步执行
│   │   ├── nmap_syn + top_ports → _scan_port_chunked() top_ports 快捷路径
│   │   │   └── ⚠️ 不走端口分块，单次 nmap 调用扫完
│   │   └── nmap_syn_full → 全端口分块扫描 (仅服务发现用)
│   │
│   └── 最终 nmap 命令
│       ├── 阶段1 Ping:
│       │   nmap -sn -T4
│       │        --max-rtt-timeout 500ms
│       │        --initial-rtt-timeout 200ms
│       │        <TARGET>
│       │
│       └── 阶段2 Top1000:
│           nmap -sT -T4 --top-ports 1000
│                -Pn -n --max-retries 2
│                --min-rate 500 --host-timeout 60s
│                --max-rtt-timeout 1000ms
│                --initial-rtt-timeout 500ms
│                --max-scan-delay 10ms
│                -v --reason
│                <TARGET>
│
└── ❌ 前后端不一致
    ├── 策略描述不准
    │   ├── standard 前端描述: "所有IP同时扫描，按端口块(5000/块)并行"
    │   │   └── 实际行为: 分组串行，不分端口块
    │   └── ip_sequential 前端描述: "多IP并发，每个IP按端口块(5000/块)并行"
    │       └── 实际行为: 不分端口块，走 top_ports 路径
    │
    ├── 并发数语义
    │   ├── 前端描述: "同时运行的 nmap 进程数"
    │   ├── standard 实际: 每组IP数量，组间串行 ⚠️
    │   └── ip_sequential 实际: Semaphore 限制，并发正确 ✅
    │
    └── "端口块(5000/块)" 概念
        ├── 仅在全端口扫描 (nmap_syn_full) 时生效
        ├── 主机发现根本不涉及
        └── 应从前端描述中移除
```

---

## 修复建议

前端 HostDiscovery.vue 策略描述应改为：

| 字段 | 当前描述 | 建议改为 |
|------|---------|---------|
| standard 标签 | "分块并行扫描" | "合并扫描" |
| standard 说明 | "所有IP同时扫描，按端口块(5000/块)并行" | "多IP合并为一次nmap调用，分组依次执行" |
| ip_sequential 标签 | "逐IP分端口扫描" | "逐IP扫描" |
| ip_sequential 说明 | "多IP并发扫描，每个IP按端口块(5000/块)并行" | "每个IP单独扫描，多IP并发执行" |
| 并发数说明 | "同时运行的 nmap 进程数" | "合并扫描时为每组IP数；逐IP扫描时为最大并发进程数" |
