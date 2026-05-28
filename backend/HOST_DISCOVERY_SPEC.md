# NetGuard 主机发现 — 完整需求规格

## 一、用户入口（前端 HostDiscovery.vue）

### 1.1 表单字段

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| 任务名称 | el-input | ✅ | 字符串，最大200字符 |
| 扫描目标 | 标签式输入 | ✅ | 逐个回车添加，带格式检查（见1.2） |
| 扫描类型 | el-radio-button | ✅ | 一次性扫描 / 周期扫描 |
| 扫描间隔 | el-input-number | 周期时必填 | 1-10080 分钟 |
| 并发数 | el-slider | ✅ | 1-8，默认4，步长1 |
| 发现方法 | 静态文本 | — | "自动执行 Ping探测 → ARP探测 → TCP端口扫描，端口扫描阶段按端口块并行" |

### 1.2 扫描目标格式检查（前端+后端双重校验）

| 格式 | 示例 | 校验规则 |
|---|---|---|
| 单IP | `192.168.1.1` | 4段0-255，点分隔 |
| CIDR网段 | `10.6.191.0/24` | 合法IP + /(8-32) |
| IP范围 | `192.168.1.1-254` | 合法IP前3段 + `-` + 1-3位尾数 |
| 域名 | `example.com` | 字母数字连字符，至少1个点，无`..` |
| 非法 | `999.999.999.999` | 红色标签+错误提示 |

### 1.3 移除项

- ~~扫描模式~~ → 移除，固定标准模式
- ~~端口范围~~ → 移除，固定全端口扫描
- ~~SYN扫描(-sS)~~ → 移除，直接使用TCP Connect(-sT)，避免root权限需求

---

## 二、权限约束

**核心原则：所有nmap操作均不依赖root权限。**

| nmap参数 | 需要root | 决策 |
|---|---|---|
| `-sS` (SYN半开扫描) | ✅ 需要 | **禁用**，改用 `-sT` |
| `-sT` (TCP Connect) | ❌ 不需要 | ✅ 使用 |
| `-sn` (Ping) | ❌ 不需要 | ✅ 使用（无root时自动用connect探测80/443） |
| `-sn -PR` (ARP) | ❌ 不需要 | ✅ 使用（无root时自动退化为connect） |
| `-sV` (服务版本) | ❌ 不需要 | ✅ 使用 |
| `-sU` (UDP) | ✅ 需要 | **禁用** |
| `-O` (OS指纹) | ✅ 需要 | **禁用**，用 `-sV` 间接获取 |

---

## 三、扫描流程（三阶段串行 + 阶段3内部并行）

```
阶段1: Ping探测 (nmap -sn -T4)              ~5-15秒
  │ 完成后
  ▼
阶段2: ARP探测 (nmap -sn -PR -T4)           ~5秒
  │ 完成后
  ▼
阶段3: TCP端口扫描 (nmap -sT -T4 -p 1-65535)  ← 最耗时
  │ 1-65535 拆为5000/块(14块)，Semaphore(并发数)并行
  │ 每块: nmap -sT -T4 -p {port_start}-{port_end} <targets>
  ▼
合并三阶段结果 → 去重 → 持久化
```

### 3.1 阶段1: Ping探测

```
nmap -sn -T4 <targets>
```
- 无root时：自动向80/443发TCP connect探测存活性
- 产出：存活主机IP列表

### 3.2 阶段2: ARP探测

```
nmap -sn -PR -T4 <targets>
```
- 无root时：自动退化为connect探测，仍可发现同网段主机+获取MAC
- 产出：存活主机IP + MAC地址

### 3.3 阶段3: TCP端口扫描（核心，最耗时）

```
nmap -sT -T4
  -p {port_start}-{port_end}           # 端口块范围
  -Pn                                    # 跳过主机发现（阶段1/2已完成）
  -n                                     # 不做DNS解析
  --max-retries 2                        # 无响应端口最多重传2次(原默认6次)
  --min-rate 300                         # 最低发包速率300/秒
  --host-timeout 30m                     # 单主机超时30分钟
  --max-rtt-timeout 1s                   # 最大RTT超时1秒(原默认~10秒)
  --initial-rtt-timeout 500ms            # 初始RTT超时500ms
  --max-scan-delay 200ms                 # 最大扫描延迟200ms
  -v --reason                            # 输出进度+原因
  -oX <xml_path>                         # XML输出
  <targets>
```

**参数优化效果**（减少无响应主机端口等待）：
- `--max-retries 2`：重传从6次降到2次，减少2/3等待
- `--max-rtt-timeout 1s`：RTT超时从10秒降到1秒
- `--initial-rtt-timeout 500ms`：首次探测500ms即超时
- `--max-scan-delay 200ms`：探测间隔上限200ms
- 综合：无响应主机端口等待从分钟级降到秒级

### 3.4 并发执行逻辑（阶段3）

```
port_chunks = [(1,5000), (5001,10000), ..., (65001,65535)]  # 14块
semaphore = asyncio.Semaphore(max_concurrent)  # 默认4

14块全部作为asyncio.gather任务提交
semaphore控制同时最多max_concurrent个nmap进程运行
每块独立执行、独立解析XML、独立错误处理
完成一块即合并一块的结果
```

---

## 四、结果合并

合并优先级 TCP端口扫描 > ARP > Ping：

| 字段 | 来源 |
|---|---|
| ports | 只从TCP端口扫描阶段取 |
| mac | 优先ARP |
| hostname | 优先TCP端口扫描 > ARP > Ping |
| os | 优先TCP端口扫描(通过-sV间接获取) |

Ping/ARP发现但TCP端口扫描无端口 → 保留IP记录，ports=[]，标记为存活。

---

## 五、扫描健壮性

### 5.1 端口不遗漏

- 全端口1-65535，端口块无间隙无重叠
- 每块独立XML，解析失败只影响该块
- 合并去重：同IP同端口只保留一条

### 5.2 端口块错误重试

```
单块失败 → 自动重试(最多2次)
  ├─ 重试成功 → 合并结果
  └─ 重试仍失败 → 跳过该块，记录日志，不影响其他块
```

### 5.3 阶段容错

```
Ping失败 → 记录错误 → 继续ARP和TCP端口扫描
ARP失败  → 记录错误 → 继续TCP端口扫描
TCP端口扫描全部失败 → 任务标记failed(前序结果仍保留)
TCP端口扫描部分块失败 → 任务标记completed(日志记录失败块)
```

### 5.4 超时

```
单块nmap进程超过30分钟 → kill → 重试1次 → 仍超时则跳过
```

### 5.5 任务状态

| 场景 | 状态 |
|---|---|
| 全部成功 | completed |
| 部分端口块失败但有结果 | completed(日志记录) |
| TCP端口扫描全部失败 | failed |
| 用户取消 | cancelled |

---

## 六、实时进度

```
总进度 = 阶段1(0-10%) + 阶段2(10-20%) + 阶段3(20-100%)
阶段3进度 = 20 + 已完成块数/总块数 × 80
```

nmap 30秒无stdout → 心跳日志，避免前端"黑屏"。

---

## 七、配置项

| 配置 | 默认值 | 说明 |
|---|---|---|
| SCAN_CHUNK_SIZE | 5000 | 端口块大小 |
| SCAN_MAX_RETRIES | 2 | --max-retries |
| SCAN_MIN_RATE | 300 | --min-rate |
| SCAN_HOST_TIMEOUT_MIN | 30 | --host-timeout |
| SCAN_MAX_RTT_TIMEOUT_MS | 1000 | --max-rtt-timeout |
| SCAN_INITIAL_RTT_TIMEOUT_MS | 500 | --initial-rtt-timeout |
| SCAN_MAX_SCAN_DELAY_MS | 200 | --max-scan-delay |
| SCAN_HOST_DISCOVERY_TIMEOUT | 30 | 单阶段超时(分钟) |
| SCAN_CHUNK_MAX_RETRIES | 2 | 失败端口块最大重试次数 |
| SCAN_MAX_CONCURRENT | 4 | 默认最大并发 |
