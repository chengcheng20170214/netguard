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
        <el-form-item label="并发数">
          <el-slider v-model="scanForm.max_concurrent" :min="1" :max="8" :step="1" show-stops :marks="{ 1:'1', 4:'4(默认)', 8:'8(最大)' }" style="width:300px" />
          <span style="margin-left:12px;color:#909399;font-size:12px">同时运行的 nmap 进程数，越大越快但更占资源</span>
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
              <template #default="{ row }">
                <el-progress :percentage="row.progress || 0" :status="row.status === 'failed' ? 'exception' : (row.status === 'completed' ? 'success' : '')" />
              </template>
            </el-table-column>
            <el-table-column prop="created_at" label="创建时间" width="180" />
            <el-table-column label="耗时" width="100">
              <template #default="{ row }">{{ scanDuration(row) }}</template>
            </el-table-column>
            <el-table-column label="操作" width="260" fixed="right">
              <template #default="{ row }">
                <el-button size="small" @click="viewDetail(row)">详情</el-button>
                <el-button v-if="row.status==='running'" size="small" type="danger" @click="handleCancel(row)">取消</el-button>
                <el-button v-if="row.status!=='running'" size="small" type="primary" @click="handleRescan(row)">重新扫描</el-button>
                <el-button v-if="row.status!=='running'" size="small" type="warning" @click="handleEdit(row)">编辑</el-button>
                <el-button v-if="row.status!=='running'" size="small" type="danger" @click="handleDelete(row)">删除</el-button>
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
            <el-table-column label="耗时" width="100">
              <template #default="{ row }">{{ scanDuration(row) }}</template>
            </el-table-column>
            <el-table-column label="操作" width="280" fixed="right">
              <template #default="{ row }">
                <el-button size="small" @click="viewDetail(row)">详情</el-button>
                <el-button v-if="row.status!=='running'" size="small" type="primary" @click="handleRescan(row)">重新扫描</el-button>
                <el-button v-if="row.is_active" size="small" type="warning" @click="handleDeactivate(row)">停用</el-button>
                <el-button v-else size="small" type="success" @click="handleActivate(row)">启用</el-button>
                <el-button v-if="row.status!=='running'" size="small" type="warning" @click="handleEdit(row)">编辑</el-button>
                <el-button v-if="row.status!=='running'" size="small" type="danger" @click="handleDelete(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <!-- Edit Dialog -->
    <el-dialog v-model="editVisible" title="编辑服务发现任务" width="600px">
      <el-form :model="editForm" label-width="100px">
        <el-form-item label="任务名称">
          <el-input v-model="editForm.name" />
        </el-form-item>
        <el-form-item label="扫描目标">
          <el-input v-model="editForm.targets" type="textarea" :rows="3" placeholder="每行一个目标" />
        </el-form-item>
        <el-form-item label="扫描模式">
          <el-select v-model="editForm.scan_mode">
            <el-option label="快速" value="quick" />
            <el-option label="标准" value="standard" />
            <el-option label="隐蔽-轻度" value="stealth_light" />
            <el-option label="隐蔽-中度" value="stealth_medium" />
            <el-option label="隐蔽-深度" value="stealth_deep" />
            <el-option label="自定义" value="custom" />
          </el-select>
        </el-form-item>
        <el-form-item label="端口范围">
          <el-input v-model="editForm.ports" placeholder="留空则扫描全端口" />
        </el-form-item>
        <el-form-item v-if="editForm.scan_type === 'periodic'" label="扫描间隔">
          <el-input-number v-model="editForm.interval_minutes" :min="1" :max="10080" />
          <span style="margin-left:8px;color:#909399">分钟</span>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="editSubmitting" @click="submitEdit">保存</el-button>
      </template>
    </el-dialog>

    <!-- Detail Dialog -->
    <el-dialog v-model="detailVisible" title="服务发现详情" width="80%">
      <el-tabs v-model="detailTab">
        <el-tab-pane label="扫描结果" name="result">
          <div v-if="detailData && detailData.status === 'running'" style="margin-bottom:12px">
            <el-progress :percentage="detailData.progress || 0" :stroke-width="18" :text-inside="true" />
            <span style="margin-left:8px;color:#909399;font-size:12px">扫描进行中...</span>
          </div>
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
          <div v-if="detailData && !detailData.results?.length" style="text-align:center;color:#909399;padding:20px">暂无扫描结果</div>
        </el-tab-pane>
        <el-tab-pane label="执行日志" name="log">
          <div class="log-container" ref="logContainerRef">
            <div v-if="detailData && detailData.scan_log && detailData.scan_log.length" class="log-lines">
              <div v-for="(entry, idx) in detailData.scan_log" :key="idx" class="log-line">
                <span class="log-ts">{{ entry.ts ? entry.ts.slice(11, 19) : '' }}</span>
                <span :class="['log-msg', entry.msg && entry.msg.includes('失败') ? 'log-error' : '']">{{ entry.msg }}</span>
              </div>
            </div>
            <div v-else class="log-empty">暂无日志</div>
          </div>
        </el-tab-pane>
        <el-tab-pane label="扫描概要" name="summary" v-if="detailData">
          <el-descriptions :column="2" border>
            <el-descriptions-item label="任务名称">{{ detailData.name }}</el-descriptions-item>
            <el-descriptions-item label="扫描目标">{{ detailData.targets }}</el-descriptions-item>
            <el-descriptions-item label="扫描模式">{{ modeLabel(detailData.scan_mode) }}</el-descriptions-item>
            <el-descriptions-item label="状态"><el-tag :type="statusType(detailData.status)" size="small">{{ statusLabel(detailData.status) }}</el-tag></el-descriptions-item>
            <el-descriptions-item label="进度">{{ detailData.progress || 0 }}%</el-descriptions-item>
            <el-descriptions-item label="发现主机数">{{ detailData.result_summary?.total_hosts ?? 0 }}</el-descriptions-item>
            <el-descriptions-item label="发现端口数">{{ detailData.result_summary?.total_ports ?? 0 }}</el-descriptions-item>
            <el-descriptions-item label="创建时间">{{ detailData.created_at }}</el-descriptions-item>
            <el-descriptions-item label="完成时间">{{ detailData.completed_at || '-' }}</el-descriptions-item>
            <el-descriptions-item label="错误信息" :span="2" v-if="detailData.error_message">
              <span style="color:#F56C6C">{{ detailData.error_message }}</span>
            </el-descriptions-item>
          </el-descriptions>
        </el-tab-pane>
      </el-tabs>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted, nextTick } from 'vue'
import { createServiceScan, getServiceScans, getServiceScanDetail, cancelServiceScan, activateServiceScan, deactivateServiceScan, updateServiceScan, deleteServiceScan, rescanServiceScan } from '../api/discovery'
import { getAssetTargets } from '../api/assets'
import { ElMessage, ElMessageBox } from 'element-plus'

const scanFormRef = ref(null)
const submitting = ref(false)
const detailVisible = ref(false)
const detailData = ref(null)
const detailTab = ref('result')
const historyTab = ref('one_time')
const assetTargets = ref([])
const selectedAssetIds = ref([])
const scans = ref([])
const logContainerRef = ref(null)

// Edit dialog state
const editVisible = ref(false)
const editSubmitting = ref(false)
const editForm = reactive({ id: null, name: '', targets: '', scan_type: '', scan_mode: '', ports: '', interval_minutes: 60 })

// Auto-refresh timer
let refreshTimer = null

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

const scanForm = reactive({ name: '', targets: '', scan_type: 'one_time', max_concurrent: 4, interval_minutes: 60, scan_mode: 'standard', port_scan_method: 'nmap_syn_full', service_detect: ['nmap_service'], ports: '' })
const scanRules = {
  name: [{ required: true, message: '请输入任务名称', trigger: 'blur' }],
  targets: [{ required: true, message: '请选择扫描目标', trigger: 'change' }],
  scan_mode: [{ required: true, message: '请选择扫描模式', trigger: 'change' }]
}

const modeLabel = (m) => ({ quick: '快速', standard: '标准', stealth_light: '隐蔽-轻度', stealth_medium: '隐蔽-中度', stealth_deep: '隐蔽-深度', custom: '自定义' }[m] || m)
const statusType = (s) => ({ pending: 'info', running: 'warning', completed: 'success', failed: 'danger', cancelled: 'info' }[s] || 'info')
const statusLabel = (s) => ({ pending: '等待中', running: '扫描中', completed: '已完成', failed: '失败', cancelled: '已取消' }[s] || s)
const scanDuration = (row) => {
  if (!row.started_at) return '-'
  const start = new Date(row.started_at)
  const end = row.completed_at ? new Date(row.completed_at) : (row.status === 'running' ? new Date() : null)
  if (!end) return '-'
  const sec = Math.round((end - start) / 1000)
  if (sec < 60) return sec + '秒'
  const m = Math.floor(sec / 60), s = sec % 60
  if (m < 60) return m + '分' + s + '秒'
  const h = Math.floor(m / 60), rm = m % 60
  return h + '时' + rm + '分'
}

const applyPreset = (preset) => {
  const presets = {
    syn_svc:     { port_scan_method: 'nmap_syn_full', service_detect: ['nmap_service'] },
    connect_svc: { port_scan_method: 'nmap_connect', service_detect: ['nmap_service'] },
    full:        { port_scan_method: 'nmap_syn_full', service_detect: ['nmap_service', 'nmap_os', 'nmap_script'] },
  }
  const p = presets[preset]
  if (p) Object.assign(scanForm, p)
}

const hasRunningScans = computed(() => scans.value.some(s => s.status === 'running'))

const fetchScans = async () => {
  try {
    const res = await getServiceScans()
    scans.value = res.data.items || res.data
  } catch (e) { /* ignore */ }
}

const startAutoRefresh = () => {
  stopAutoRefresh()
  if (hasRunningScans.value) {
    refreshTimer = setInterval(() => {
      fetchScans()
    }, 3000)
  }
}

const stopAutoRefresh = () => {
  if (refreshTimer) {
    clearInterval(refreshTimer)
    refreshTimer = null
  }
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
    const payload = { name: scanForm.name, targets: scanForm.targets, scan_type: scanForm.scan_type, max_concurrent: scanForm.max_concurrent, interval_minutes: scanForm.interval_minutes, scan_category: 'service_discovery', scan_methods: [scanForm.port_scan_method, ...scanForm.service_detect], scan_mode: scanForm.scan_mode, ports: scanForm.ports || null }
    await createServiceScan(payload)
    ElMessage.success('服务发现任务已创建')
    scanForm.name = ''
    scanForm.targets = ''
    selectedAssetIds.value = []
    await fetchScans()
    startAutoRefresh()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '创建失败')
  } finally { submitting.value = false }
}

const viewDetail = async (row) => {
  try {
    const res = await getServiceScanDetail(row.id)
    detailData.value = res.data
    detailTab.value = 'result'
    detailVisible.value = true

    if (row.status === 'running') {
      startDetailPolling(row.id)
    }
  } catch (e) { ElMessage.error('获取详情失败') }
}

let detailPollingTimer = null
const startDetailPolling = (taskId) => {
  stopDetailPolling()
  detailPollingTimer = setInterval(async () => {
    try {
      const res = await getServiceScanDetail(taskId)
      detailData.value = res.data
      await nextTick()
      if (logContainerRef.value) {
        logContainerRef.value.scrollTop = logContainerRef.value.scrollHeight
      }
      if (res.data.status !== 'running') {
        stopDetailPolling()
        await fetchScans()
      }
    } catch (e) { /* ignore */ }
  }, 2000)
}

const stopDetailPolling = () => {
  if (detailPollingTimer) {
    clearInterval(detailPollingTimer)
    detailPollingTimer = null
  }
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

const handleRescan = async (row) => {
  try {
    await ElMessageBox.confirm('确定要使用相同配置重新扫描吗？', '重新扫描', { type: 'info' })
    await rescanServiceScan(row.id)
    ElMessage.success('已重新发起扫描')
    await fetchScans()
    startAutoRefresh()
  } catch (e) {
    if (e !== 'cancel') {
      ElMessage.error(e.response?.data?.detail || '重新扫描失败')
    }
  }
}

const handleEdit = (row) => {
  editForm.id = row.id
  editForm.name = row.name
  editForm.targets = row.targets
  editForm.scan_type = row.scan_type
  editForm.scan_mode = row.scan_mode
  editForm.ports = row.ports || ''
  editForm.interval_minutes = row.interval_minutes || 60
  editVisible.value = true
}

const submitEdit = async () => {
  if (!editForm.name.trim()) {
    ElMessage.warning('请输入任务名称')
    return
  }
  if (!editForm.targets.trim()) {
    ElMessage.warning('请输入扫描目标')
    return
  }
  editSubmitting.value = true
  try {
    await updateServiceScan(editForm.id, {
      name: editForm.name,
      targets: editForm.targets,
      scan_mode: editForm.scan_mode,
      ports: editForm.ports || null,
      interval_minutes: editForm.scan_type === 'periodic' ? editForm.interval_minutes : null
    })
    ElMessage.success('任务已更新')
    editVisible.value = false
    await fetchScans()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '更新失败')
  } finally { editSubmitting.value = false }
}

const handleDelete = async (row) => {
  try {
    await ElMessageBox.confirm('确定要删除此扫描任务吗？删除后不可恢复。', '删除确认', { type: 'warning' })
    await deleteServiceScan(row.id)
    ElMessage.success('任务已删除')
    await fetchScans()
  } catch (e) {
    if (e !== 'cancel') {
      ElMessage.error(e.response?.data?.detail || '删除失败')
    }
  }
}

onMounted(() => {
  fetchScans()
  fetchAssetTargets()
  startAutoRefresh()
})

onUnmounted(() => {
  stopAutoRefresh()
  stopDetailPolling()
})
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
.log-error {
  color: #f56c6c;
}
.log-empty {
  color: #6a9955;
  text-align: center;
  padding: 20px;
}
</style>
