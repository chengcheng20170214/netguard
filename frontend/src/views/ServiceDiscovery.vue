<template>
  <div>
    <el-card>
      <template #header><span>新建服务发现任务</span></template>
      <el-form :model="scanForm" :rules="scanRules" ref="scanFormRef" label-width="100px">
        <el-form-item label="任务名称" prop="name">
          <el-input v-model="scanForm.name" placeholder="输入任务名称" />
        </el-form-item>
        <el-form-item label="扫描目标" prop="targets">
          <div class="target-input-wrapper">
            <el-select v-model="selectedAssetIds" multiple filterable placeholder="选择资产（可搜索 IP/主机名）" style="width:100%" @change="handleAssetSelect">
              <el-option v-for="a in assetTargets" :key="a.id" :label="a.ip + (a.hostname ? ' (' + a.hostname + ')' : '')" :value="a.id">
                <span>{{ a.ip }}</span>
                <span v-if="a.hostname" style="margin-left:8px;color:#909399;font-size:12px">{{ a.hostname }}</span>
                <el-tag v-if="!a.is_online" type="danger" size="small" style="margin-left:8px">离线</el-tag>
              </el-option>
            </el-select>
            <div v-if="!assetTargets.length" style="margin-top:4px;color:#909399;font-size:12px">暂无资产，请先导入或扫描发现资产</div>
            <div v-if="selectedAssetIds.length" style="margin-top:4px;display:flex;gap:8px;align-items:center">
              <span style="color:#909399;font-size:12px">已选 {{ selectedAssetIds.length }} 个资产</span>
              <el-button type="danger" link size="small" @click="clearAssetSelection">清空选择</el-button>
            </div>
          </div>
        </el-form-item>
        <el-form-item label="扫描类型" prop="scan_type">
          <el-radio-group v-model="scanForm.scan_type">
            <el-radio-button value="one_time">一次性扫描</el-radio-button>
            <el-radio-button value="periodic">周期扫描</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="scanForm.scan_type === 'periodic'" label="扫描间隔" prop="interval_minutes">
          <el-input-number v-model="scanForm.interval_minutes" :min="1" :max="10080" />
          <span style="margin-left:8px;color:#909399">分钟</span>
        </el-form-item>
        <el-form-item label="扫描模式" prop="scan_mode">
          <el-radio-group v-model="scanForm.scan_mode">
            <el-tooltip content="仅扫描常见Top100端口，速度最快，适合快速摸底" placement="top">
              <el-radio-button value="quick">快速扫描</el-radio-button>
            </el-tooltip>
            <el-tooltip content="扫描所有指定端口+服务识别，平衡速度与精度，日常推荐" placement="top">
              <el-radio-button value="standard">标准扫描</el-radio-button>
            </el-tooltip>
            <el-tooltip content="T2时序，扫描间隔400ms，每秒最多50包，约5-10倍标准时间" placement="top">
              <el-radio-button value="stealth_light">隐蔽-轻度</el-radio-button>
            </el-tooltip>
            <el-tooltip content="T1时序，扫描间隔3s，每秒最多10包，报文分片+随机化，约20-50倍标准时间" placement="top">
              <el-radio-button value="stealth_medium">隐蔽-中度</el-radio-button>
            </el-tooltip>
            <el-tooltip content="T0时序，扫描间隔10s，每秒最多5包，分片+诱饵+源端口伪造，可能需要数小时" placement="top">
              <el-radio-button value="stealth_deep">隐蔽-深度</el-radio-button>
            </el-tooltip>
            <el-tooltip content="手动指定所有扫描参数" placement="top">
              <el-radio-button value="custom">自定义</el-radio-button>
            </el-tooltip>
          </el-radio-group>
        </el-form-item>
        <el-alert v-if="scanForm.scan_mode && scanForm.scan_mode.startsWith('stealth')" type="warning" :closable="false" style="margin-bottom:16px">
          <template v-if="scanForm.scan_mode==='stealth_light'">隐蔽-轻度：扫描间隔400ms，速率上限50包/秒，约需标准扫描5-10倍时间。可绕过基础防火墙检测。</template>
          <template v-else-if="scanForm.scan_mode==='stealth_medium'">隐蔽-中度：扫描间隔3秒，速率上限10包/秒，启用报文分片+主机随机化。约需20-50倍时间。可绕过多数IDS/防火墙。</template>
          <template v-else-if="scanForm.scan_mode==='stealth_deep'">隐蔽-深度：扫描间隔10秒，速率上限5包/秒，启用分片+诱饵主机+源端口53伪造+随机填充。可能需要数小时。用于高安全目标。</template>
        </el-alert>
        <el-form-item label="端口扫描" prop="port_scan_method">
          <el-radio-group v-model="scanForm.port_scan_method">
            <el-tooltip content="SYN全端口分块扫描(1-65535)，每块独立保存可恢复，充足重传防丢包漏报，推荐" placement="top">
              <el-radio-button value="nmap_syn_full">SYN全端口扫描</el-radio-button>
            </el-tooltip>
            <el-tooltip content="TCP SYN半开扫描，速度快且隐蔽，不完成完整握手（nmap需root，内置扫描器自动降级为全连接）" placement="top">
              <el-radio-button value="nmap_syn">SYN扫描</el-radio-button>
            </el-tooltip>
            <el-tooltip content="TCP全连接扫描，完成完整三次握手，最可靠，无需root权限" placement="top">
              <el-radio-button value="nmap_connect">全连接扫描</el-radio-button>
            </el-tooltip>
            <el-tooltip content="UDP端口扫描，速度慢，用于发现DNS(53)/SNMP(161)等UDP服务" placement="top">
              <el-radio-button value="nmap_udp">UDP扫描</el-radio-button>
            </el-tooltip>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="服务识别">
          <el-checkbox-group v-model="scanForm.service_detect">
            <el-tooltip content="探测开放端口上运行的服务及版本号，强烈推荐搭配端口扫描使用" placement="top">
              <el-checkbox value="nmap_service">服务版本识别</el-checkbox>
            </el-tooltip>
            <el-tooltip content="通过TCP/IP指纹识别目标操作系统，需root且目标需至少1个开放端口" placement="top">
              <el-checkbox value="nmap_os">操作系统识别</el-checkbox>
            </el-tooltip>
            <el-tooltip content="运行Nmap默认脚本进行漏洞探测和安全检查，耗时较长" placement="top">
              <el-checkbox value="nmap_script">脚本扫描</el-checkbox>
            </el-tooltip>
          </el-checkbox-group>
        </el-form-item>
        <div style="margin:-8px 0 16px 100px;color:#909399;font-size:12px">
          <span>快捷组合：</span>
          <el-link type="primary" :underline="false" @click="applyPreset('syn_svc')">SYN+服务识别</el-link>
          <span style="margin:0 8px">|</span>
          <el-link type="primary" :underline="false" @click="applyPreset('connect_svc')">全连接+服务识别</el-link>
          <span style="margin:0 8px">|</span>
          <el-link type="primary" :underline="false" @click="applyPreset('full')">全面扫描</el-link>
        </div>
        <el-form-item label="端口范围">
          <el-input v-model="scanForm.ports" placeholder="留空则扫描全端口1-65535，自定义如 22,80,443 或 1-1000" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="submitting" @click="handleSubmit">开始扫描</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card style="margin-top:20px">
      <template #header><span>服务发现历史</span></template>
      <el-tabs v-model="historyTab">
        <el-tab-pane label="一次性扫描" name="one_time">
          <el-table :data="oneTimeScans" stripe border>
            <el-table-column prop="name" label="名称" width="150" />
            <el-table-column prop="targets" label="目标" show-overflow-tooltip />
            <el-table-column prop="scan_mode" label="模式" width="120">
              <template #default="{ row }">{{ modeLabel(row.scan_mode) }}</template>
            </el-table-column>
            <el-table-column prop="status" label="状态" width="100">
              <template #default="{ row }"><el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag></template>
            </el-table-column>
            <el-table-column label="进度" width="200">
              <template #default="{ row }"><el-progress :percentage="row.progress || 0" /></template>
            </el-table-column>
            <el-table-column prop="created_at" label="创建时间" width="180" />
            <el-table-column label="操作" width="150">
              <template #default="{ row }">
                <el-button size="small" @click="viewDetail(row)">详情</el-button>
                <el-button v-if="row.status==='running'" size="small" type="danger" @click="handleCancel(row)">取消</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
        <el-tab-pane label="周期扫描" name="periodic">
          <el-table :data="periodicScans" stripe border>
            <el-table-column prop="name" label="名称" width="150" />
            <el-table-column prop="targets" label="目标" show-overflow-tooltip />
            <el-table-column prop="scan_mode" label="模式" width="120">
              <template #default="{ row }">{{ modeLabel(row.scan_mode) }}</template>
            </el-table-column>
            <el-table-column prop="interval_minutes" label="间隔" width="80">
              <template #default="{ row }">{{ row.interval_minutes }}分钟</template>
            </el-table-column>
            <el-table-column label="状态" width="100">
              <template #default="{ row }"><el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag></template>
            </el-table-column>
            <el-table-column label="调度" width="100">
              <template #default="{ row }"><el-tag :type="row.is_active?'success':'info'" size="small">{{ row.is_active?'运行中':'已停用' }}</el-tag></template>
            </el-table-column>
            <el-table-column prop="next_run" label="下次执行" width="180">
              <template #default="{ row }">{{ row.next_run ? row.next_run.slice(0,19) : '-' }}</template>
            </el-table-column>
            <el-table-column label="操作" width="200">
              <template #default="{ row }">
                <el-button size="small" @click="viewDetail(row)">详情</el-button>
                <el-button v-if="row.is_active" size="small" type="warning" @click="handleDeactivate(row)">停用</el-button>
                <el-button v-else size="small" type="success" @click="handleActivate(row)">启用</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <el-dialog v-model="detailVisible" title="服务发现详情" width="80%">
      <el-tabs>
        <el-tab-pane label="扫描结果">
          <el-table v-if="detailData" :data="detailData.results || []" stripe border>
            <el-table-column prop="ip" label="IP" width="150" />
            <el-table-column prop="hostname" label="主机名" width="150" />
            <el-table-column prop="os" label="操作系统" width="150" />
            <el-table-column label="开放端口" min-width="200">
              <template #default="{ row }">
                <span v-for="p in (row.ports || [])" :key="p.port" style="margin-right:8px">{{ p.port }}/{{ p.service || p.proto }}</span>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
        <el-tab-pane label="执行日志">
          <div class="log-container">
            <div v-if="detailData && detailData.scan_log && detailData.scan_log.length" class="log-lines">
              <div v-for="(entry, idx) in detailData.scan_log" :key="idx" class="log-line">
                <span class="log-ts">{{ entry.ts ? entry.ts.slice(11, 19) : '' }}</span>
                <span class="log-msg">{{ entry.msg }}</span>
              </div>
            </div>
            <div v-else class="log-empty">暂无日志</div>
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { createServiceScan, getServiceScans, getServiceScanDetail, cancelServiceScan, activateServiceScan, deactivateServiceScan } from '../api/discovery'
import { getAssetTargets } from '../api/assets'
import { ElMessage } from 'element-plus'

const scanFormRef = ref(null)
const submitting = ref(false)
const detailVisible = ref(false)
const detailData = ref(null)
const historyTab = ref('one_time')
const assetTargets = ref([])
const selectedAssetIds = ref([])
const scans = ref([])

const handleAssetSelect = (selectedIds) => {
  const selectedIps = assetTargets.value
    .filter(a => selectedIds.includes(a.id))
    .map(a => a.ip)
  scanForm.targets = selectedIps.join('\n')
}

const clearAssetSelection = () => {
  selectedAssetIds.value = []
  scanForm.targets = ''
}

const fetchAssetTargets = async () => {
  try {
    const res = await getAssetTargets()
    assetTargets.value = res.data || []
  } catch (e) {
    console.error('Failed to fetch asset targets:', e)
  }
}

const oneTimeScans = computed(() => scans.value.filter(s => s.scan_type === 'one_time'))
const periodicScans = computed(() => scans.value.filter(s => s.scan_type === 'periodic'))

const scanForm = reactive({ name: '', targets: '', scan_type: 'one_time', interval_minutes: 60, scan_mode: 'standard', port_scan_method: 'nmap_syn_full', service_detect: ['nmap_service'], ports: '' })
const scanRules = {
  name: [{ required: true, message: '请输入任务名称', trigger: 'blur' }],
  targets: [{ required: true, message: '请选择扫描目标', trigger: 'change' }],
  scan_mode: [{ required: true, message: '请选择扫描模式', trigger: 'change' }]
}

const modeLabel = (m) => ({ quick: '快速', standard: '标准', stealth_light: '隐蔽-轻度', stealth_medium: '隐蔽-中度', stealth_deep: '隐蔽-深度', custom: '自定义' }[m] || m)
const statusType = (s) => ({ pending: 'info', running: 'warning', completed: 'success', failed: 'danger', cancelled: 'info' }[s] || 'info')
const statusLabel = (s) => ({ pending: '等待中', running: '扫描中', completed: '已完成', failed: '失败', cancelled: '已取消' }[s] || s)

const applyPreset = (preset) => {
  const presets = {
    syn_svc:     { port_scan_method: 'nmap_syn_full', service_detect: ['nmap_service'] },
    connect_svc: { port_scan_method: 'nmap_connect', service_detect: ['nmap_service'] },
    full:        { port_scan_method: 'nmap_syn_full', service_detect: ['nmap_service', 'nmap_os', 'nmap_script'] },
  }
  const p = presets[preset]
  if (p) Object.assign(scanForm, p)
}

const fetchScans = async () => {
  try {
    const res = await getServiceScans()
    scans.value = res.data.items || res.data
  } catch (e) { /* ignore */ }
}

const handleSubmit = async () => {
  const valid = await scanFormRef.value.validate().catch(() => false)
  if (!valid) return
  if (!scanForm.targets) {
    ElMessage.warning('请选择扫描目标')
    return
  }
  submitting.value = true
  try {
    const payload = { name: scanForm.name, targets: scanForm.targets, scan_type: scanForm.scan_type, interval_minutes: scanForm.interval_minutes, scan_category: 'service_discovery', scan_methods: [scanForm.port_scan_method, ...scanForm.service_detect], scan_mode: scanForm.scan_mode, ports: scanForm.ports || null }
    await createServiceScan(payload)
    ElMessage.success('服务发现任务已创建')
    scanForm.name = ''
    scanForm.targets = ''
    selectedAssetIds.value = []
    await fetchScans()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '创建失败')
  } finally { submitting.value = false }
}

const viewDetail = async (row) => {
  try {
    const res = await getServiceScanDetail(row.id)
    detailData.value = res.data
    detailVisible.value = true
  } catch (e) { ElMessage.error('获取详情失败') }
}

const handleCancel = async (row) => {
  try { await cancelServiceScan(row.id); ElMessage.success('已取消'); await fetchScans() } catch (e) { ElMessage.error('取消失败') }
}

const handleActivate = async (row) => {
  try { await activateServiceScan(row.id); ElMessage.success('已启用'); await fetchScans() } catch (e) { ElMessage.error('启用失败') }
}

const handleDeactivate = async (row) => {
  try { await deactivateServiceScan(row.id); ElMessage.success('已停用'); await fetchScans() } catch (e) { ElMessage.error('停用失败') }
}

onMounted(() => { fetchScans(); fetchAssetTargets() })
</script>

<style scoped>
.target-input-wrapper {
  width: 100%;
}
.log-container {
  max-height: 400px;
  overflow-y: auto;
  background: #1e1e1e;
  border-radius: 4px;
  padding: 12px;
  font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
  font-size: 13px;
}
.log-lines {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.log-line {
  display: flex;
  gap: 12px;
  line-height: 1.6;
}
.log-ts {
  color: #6a9955;
  white-space: nowrap;
  flex-shrink: 0;
}
.log-msg {
  color: #d4d4d4;
  word-break: break-all;
}
.log-empty {
  color: #6a9955;
  text-align: center;
  padding: 20px;
}
</style>
