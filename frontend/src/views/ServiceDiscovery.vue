<template>
  <div>
    <el-card>
      <template #header>
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span>新建服务发现任务</span>
          <el-button type="info" link @click="$router.push('/scan-profiles')">
            <el-icon style="margin-right:4px"><Setting /></el-icon>管理扫描策略
          </el-button>
        </div>
      </template>
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
        <el-form-item label="扫描策略" prop="scan_profile_id">
          <el-select v-model="scanForm.scan_profile_id" placeholder="选择扫描策略" style="width:100%" @change="handleProfileChange">
            <el-option v-for="p in profileOptions" :key="p.id" :label="p.name" :value="p.id">
              <div style="display:flex;justify-content:space-between;align-items:center;width:100%">
                <span>{{ p.name }}</span>
                <span style="color:#909399;font-size:12px;margin-left:12px">{{ p.description }}</span>
              </div>
            </el-option>
          </el-select>
          <div v-if="selectedProfileDetail" style="margin-top:8px;width:100%">
            <el-descriptions :column="2" border size="small">
              <el-descriptions-item label="端口发现">
                <el-tag size="small" :type="selectedProfileDetail.port_scan?.mode === 'full' ? 'danger' : 'info'">
                  {{ portModeLabel(selectedProfileDetail.port_scan) }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="服务识别">
                <el-tag size="small" :type="selectedProfileDetail.service_detect?.enabled ? 'success' : 'info'">
                  {{ selectedProfileDetail.service_detect?.enabled ? '启用 (强度 ' + selectedProfileDetail.service_detect?.intensity + ')' : '未启用' }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="脚本扫描">
                <el-tag size="small" :type="selectedProfileDetail.script_scan?.enabled ? 'warning' : 'info'">
                  {{ selectedProfileDetail.script_scan?.enabled ? '启用 (' + (selectedProfileDetail.script_scan?.categories || []).join(', ') + ')' : '未启用' }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="OS识别">
                <el-tag size="small" :type="selectedProfileDetail.os_detect?.enabled ? 'warning' : 'info'">
                  {{ selectedProfileDetail.os_detect?.enabled ? '启用' : '未启用' }}
                </el-tag>
              </el-descriptions-item>
            </el-descriptions>
          </div>
          <div v-else style="margin-top:4px;color:#909399;font-size:12px">选择策略后显示详细配置</div>
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
            <el-table-column label="策略" width="130">
              <template #default="{ row }">{{ profileNameForTask(row) }}</template>
            </el-table-column>
            <el-table-column prop="status" label="状态" width="100">
              <template #default="{ row }"><el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag></template>
            </el-table-column>
            <el-table-column label="阶段" width="140">
              <template #default="{ row }">
                <span v-if="row.current_phase">{{ phaseLabel(row.current_phase) }}</span>
                <span v-else style="color:#909399">-</span>
              </template>
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
            <el-table-column label="策略" width="130">
              <template #default="{ row }">{{ profileNameForTask(row) }}</template>
            </el-table-column>
            <el-table-column prop="interval_minutes" label="间隔" width="80">
              <template #default="{ row }">{{ row.interval_minutes }}分钟</template>
            </el-table-column>
            <el-table-column label="状态" width="100">
              <template #default="{ row }"><el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag></template>
            </el-table-column>
            <el-table-column label="阶段" width="140">
              <template #default="{ row }">
                <span v-if="row.current_phase">{{ phaseLabel(row.current_phase) }}</span>
                <span v-else style="color:#909399">-</span>
              </template>
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
        <el-form-item label="扫描策略">
          <el-select v-model="editForm.scan_profile_id" placeholder="选择扫描策略" style="width:100%" clearable>
            <el-option v-for="p in profileOptions" :key="p.id" :label="p.name" :value="p.id" />
          </el-select>
          <div style="margin-top:4px;color:#E6A23C;font-size:12px" v-if="editForm.scan_profile_id">
            ⚠️ 修改策略将影响下次扫描，运行中的任务不受影响
          </div>
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
            <div style="display:flex;align-items:center;gap:12px">
              <el-progress :percentage="detailData.progress || 0" :stroke-width="18" :text-inside="true" style="flex:1" />
              <el-tag v-if="detailData.current_phase" type="warning" size="small">{{ phaseLabel(detailData.current_phase) }}</el-tag>
            </div>
          </div>
          <!-- 扫描结果表格：支持展开行查看端口详情 -->
          <el-table v-if="detailData" :data="detailData.results || []" stripe border row-key="id"
            :expand-row-keys="expandedResultRows" @expand-change="onResultExpand">
            <el-table-column type="expand">
              <template #default="{ row }">
                <el-table :data="row.ports || []" size="small" border style="margin:4px 0 8px 48px;width:calc(100% - 56px)">
                  <el-table-column prop="port" label="端口" width="70" />
                  <el-table-column prop="proto" label="协议" width="70" />
                  <el-table-column prop="service" label="服务" width="100" />
                  <el-table-column prop="product" label="产品" min-width="120">
                    <template #default="{ row: p }">{{ p.product || '-' }}</template>
                  </el-table-column>
                  <el-table-column prop="version" label="版本" min-width="150">
                    <template #default="{ row: p }">{{ p.version || '-' }}</template>
                  </el-table-column>
                  <el-table-column prop="extrainfo" label="附加信息" min-width="150">
                    <template #default="{ row: p }">{{ p.extrainfo || '-' }}</template>
                  </el-table-column>
                  <el-table-column prop="cpe" label="CPE" min-width="160">
                    <template #default="{ row: p }">{{ p.cpe || '-' }}</template>
                  </el-table-column>
                  <el-table-column label="脚本" min-width="120">
                    <template #default="{ row: p }">
                      <template v-if="p.scripts && p.scripts.length">
                        <el-tag v-for="(s, i) in p.scripts" :key="i" size="small" type="info" style="margin:2px">{{ s.id || s }}</el-tag>
                      </template>
                      <span v-else>-</span>
                    </template>
                  </el-table-column>
                </el-table>
              </template>
            </el-table-column>
            <el-table-column prop="ip" label="IP" width="150" />
            <el-table-column prop="hostname" label="主机名" width="150" />
            <el-table-column prop="os" label="操作系统" width="150">
              <template #default="{ row }">{{ row.os || row.os_match || '-' }}</template>
            </el-table-column>
            <el-table-column label="开放端口" min-width="200">
              <template #default="{ row }">
                <span v-for="p in (row.ports || [])" :key="p.port" style="margin-right:8px">
                  {{ p.port }}/{{ p.service || p.proto }}
                  <el-tag v-if="p.product" size="small" type="success" style="margin-left:2px;font-size:11px">{{ p.product }}</el-tag>
                </span>
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
            <el-descriptions-item label="扫描策略">{{ profileNameForTask(detailData) }}</el-descriptions-item>
            <el-descriptions-item label="状态"><el-tag :type="statusType(detailData.status)" size="small">{{ statusLabel(detailData.status) }}</el-tag></el-descriptions-item>
            <el-descriptions-item label="当前阶段">{{ detailData.current_phase ? phaseLabel(detailData.current_phase) : '-' }}</el-descriptions-item>
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
import { createServiceScan, getServiceScans, getServiceScanDetail, cancelServiceScan, activateServiceScan, deactivateServiceScan, updateServiceScan, deleteServiceScan, rescanServiceScan, getScanProfilesBrief, getScanProfile } from '../api/discovery'
import { getAssetTargets } from '../api/assets'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Setting } from '@element-plus/icons-vue'

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

// Profile data
const profileOptions = ref([])           // brief list for dropdown
const selectedProfileDetail = ref(null)  // full detail of selected profile
const profileCache = ref({})             // id -> name cache for history table

// 展开行控制
const expandedResultRows = ref([])
const onResultExpand = ({ id }, expandedRows) => {
  expandedResultRows.value = expandedRows.map(r => r.id)
}

// Edit dialog state
const editVisible = ref(false)
const editSubmitting = ref(false)
const editForm = reactive({ id: null, name: '', targets: '', scan_type: '', scan_profile_id: null, interval_minutes: 60 })

// Auto-refresh timer
let refreshTimer = null

// ──── Profile helpers ────

const fetchProfiles = async () => {
  try {
    const res = await getScanProfilesBrief()
    const list = res.data || []
    profileOptions.value = list
    // Build name cache
    list.forEach(p => { profileCache.value[p.id] = p.name })
  } catch (e) {
    console.error('Failed to fetch scan profiles:', e)
  }
}

const handleProfileChange = async (profileId) => {
  if (!profileId) {
    selectedProfileDetail.value = null
    return
  }
  try {
    const res = await getScanProfile(profileId)
    selectedProfileDetail.value = res.data
  } catch (e) {
    selectedProfileDetail.value = null
  }
}

const portModeLabel = (portScan) => {
  if (!portScan) return '-'
  const modeMap = { top1000: 'Top1000', full: '全端口', custom: '自定义' }
  return modeMap[portScan.mode] || portScan.mode || '-'
}

const phaseLabel = (phase) => {
  if (!phase) return '-'
  const map = {
    port_scan: '端口发现',
    service_and_script: '服务识别+脚本',
    service_detect: '服务识别',
    script_scan: '脚本扫描',
    os_detect: 'OS识别',
    completed: '已完成',
  }
  return map[phase] || phase
}

const profileNameForTask = (row) => {
  if (row.scan_profile_id && profileCache.value[row.scan_profile_id]) {
    return profileCache.value[row.scan_profile_id]
  }
  // Fallback: show scan_mode for legacy tasks
  const modeMap = { standard: '标准', ip_sequential: '逐IP' }
  return modeMap[row.scan_mode] || row.scan_mode || '-'
}

// ──── Asset helpers ────

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

// ──── Computed ────

const oneTimeScans = computed(() => scans.value.filter(s => s.scan_type === 'one_time'))
const periodicScans = computed(() => scans.value.filter(s => s.scan_type === 'periodic'))

// ──── Form ────

const scanForm = reactive({ name: '', targets: '', scan_type: 'one_time', interval_minutes: 60, scan_profile_id: null })
const scanRules = {
  name: [{ required: true, message: '请输入任务名称', trigger: 'blur' }],
  targets: [{ required: true, message: '请选择扫描目标', trigger: 'change' }],
  scan_profile_id: [{ required: true, message: '请选择扫描策略', trigger: 'change' }]
}

// ──── Common helpers ────

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

const hasRunningScans = computed(() => scans.value.some(s => s.status === 'running'))

// ──── Data fetching ────

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

// ──── Submit ────

const handleSubmit = async () => {
  const valid = await scanFormRef.value.validate().catch(() => false)
  if (!valid) return
  if (!scanForm.targets) {
    ElMessage.warning('请选择扫描目标')
    return
  }
  submitting.value = true
  try {
    const payload = {
      name: scanForm.name,
      targets: scanForm.targets,
      scan_type: scanForm.scan_type,
      interval_minutes: scanForm.scan_type === 'periodic' ? scanForm.interval_minutes : null,
      scan_category: 'service_discovery',
      scan_profile_id: scanForm.scan_profile_id,
      // Legacy fields — not used by new engine but required by schema
      scan_mode: 'standard',
      scan_methods: [],
    }
    await createServiceScan(payload)
    ElMessage.success('服务发现任务已创建')
    // Reset form
    scanForm.name = ''
    scanForm.targets = ''
    scanForm.scan_profile_id = null
    selectedAssetIds.value = []
    selectedProfileDetail.value = null
    await fetchScans()
    startAutoRefresh()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '创建失败')
  } finally { submitting.value = false }
}

// ──── Detail ────

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

// ──── Actions ────

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
  editForm.scan_profile_id = row.scan_profile_id || null
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
      scan_profile_id: editForm.scan_profile_id || null,
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
    ElMessage.success('已删除')
    await fetchScans()
  } catch (e) {
    if (e !== 'cancel') {
      ElMessage.error(e.response?.data?.detail || '删除失败')
    }
  }
}

// ──── Lifecycle ────

onMounted(() => {
  fetchProfiles()
  fetchAssetTargets()
  fetchScans()
})

onUnmounted(() => {
  stopAutoRefresh()
  stopDetailPolling()
})
</script>

<style scoped>
.target-input-wrapper { width: 100% }
.log-container { max-height: 500px; overflow-y: auto; background: #1e1e1e; border-radius: 4px; padding: 12px; font-family: 'Consolas', 'Monaco', monospace; font-size: 13px; }
.log-lines { display: flex; flex-direction: column; gap: 2px; }
.log-line { display: flex; gap: 8px; color: #d4d4d4; }
.log-ts { color: #6a9955; white-space: nowrap; }
.log-msg { word-break: break-all; }
.log-error { color: #f56c6c; }
.log-empty { text-align: center; color: #666; padding: 40px; }
</style>