<template>
  <div>
    <el-card>
      <template #header><span>新建主机发现任务</span></template>
      <el-form :model="scanForm" :rules="scanRules" ref="scanFormRef" label-width="100px">
        <el-form-item label="任务名称" prop="name">
          <el-input v-model="scanForm.name" placeholder="输入任务名称" />
        </el-form-item>
        <el-form-item label="扫描目标" prop="targets">
          <div class="target-input-wrapper">
            <div class="target-tags" v-if="targetList.length">
              <el-tag v-for="(t, i) in targetList" :key="i" :type="t.valid ? (t.type === 'invalid' ? 'danger' : '') : 'danger'" closable size="large" style="margin:2px 4px" @close="removeTarget(i)">
                <span :title="t.typeLabel">{{ t.value }}</span>
                <span style="margin-left:4px;font-size:11px;color:#909399">{{ t.typeLabel }}</span>
              </el-tag>
            </div>
            <el-input v-model="targetInput" placeholder="输入IP/CIDR/域名后回车添加，例如: 192.168.1.1 / 192.168.1.0/24 / example.com" size="large" @keyup.enter.prevent="addTarget" style="margin-top:4px">
              <template #append>
                 <el-button @click="addTarget" :disabled="!targetInput.trim()">添加</el-button>
              </template>
            </el-input>
            <div style="margin-top:4px;display:flex;gap:8px;align-items:center">
              <span style="color:#909399;font-size:12px">支持: 单IP / CIDR网段 / IP范围 / 域名</span>
              <el-button v-if="targetList.length" type="danger" link size="small" @click="clearTargets">清空全部</el-button>
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
        <el-form-item label="发现方法">
          <el-text type="info">自动执行 Ping探测 → ARP探测 → SYN端口扫描 三阶段递进扫描，确保无遗漏</el-text>
        </el-form-item>
        <el-form-item label="并发数">
          <el-slider v-model="scanForm.max_concurrent" :min="1" :max="8" :step="1" show-stops :marks="{ 1:'1', 4:'4(默认)', 8:'8(最大)' }" style="width:300px" />
          <span style="margin-left:12px;color:#909399;font-size:12px">同时运行的 nmap 进程数，越大越快但更占资源</span>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="submitting" @click="handleSubmit">开始发现</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card style="margin-top:20px">
      <template #header><span>主机发现历史</span></template>
      <el-tabs v-model="historyTab">
        <el-tab-pane label="一次性扫描" name="one_time">
          <el-table :data="oneTimeScans" stripe border>
            <el-table-column prop="name" label="名称" width="150" />
            <el-table-column prop="targets" label="目标" show-overflow-tooltip />
            <el-table-column prop="status" label="状态" width="100">
              <template #default="{ row }"><el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag></template>
            </el-table-column>
            <el-table-column label="进度" width="200">
              <template #default="{ row }">
                <el-progress :percentage="row.progress || 0" :status="row.status === 'failed' ? 'exception' : (row.status === 'completed' ? 'success' : '')" />
              </template>
            </el-table-column>
            <el-table-column label="发现主机" width="100">
              <template #default="{ row }">{{ row.result_summary?.total_hosts ?? '-' }}</template>
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
    <el-dialog v-model="editVisible" title="编辑主机发现任务" width="600px">
      <el-form :model="editForm" label-width="100px">
        <el-form-item label="任务名称">
          <el-input v-model="editForm.name" />
        </el-form-item>
        <el-form-item label="扫描目标">
          <el-input v-model="editForm.targets" type="textarea" :rows="3" placeholder="每行一个目标" />
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
    <el-dialog v-model="detailVisible" title="主机发现详情" width="80%">
      <el-tabs v-model="detailTab">
        <el-tab-pane label="扫描结果" name="result">
          <div v-if="detailData && detailData.status === 'running'" style="margin-bottom:12px">
            <el-progress :percentage="detailData.progress || 0" :stroke-width="18" :text-inside="true" status="" />
            <span style="margin-left:8px;color:#909399;font-size:12px">扫描进行中...</span>
          </div>
          <el-table v-if="detailData" :data="detailData.results || []" stripe border>
            <el-table-column prop="ip" label="IP" width="150" />
            <el-table-column prop="mac" label="MAC地址" width="180" />
            <el-table-column prop="hostname" label="主机名" width="200" />
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
import { createHostScan, getHostScans, getHostScanDetail, cancelHostScan, activateHostScan, deactivateHostScan, updateHostScan, deleteHostScan, rescanHostScan } from '../api/discovery'
import { ElMessage, ElMessageBox } from 'element-plus'

const scanFormRef = ref(null)
const submitting = ref(false)
const detailVisible = ref(false)
const detailData = ref(null)
const detailTab = ref('result')
const historyTab = ref('one_time')
const targetInput = ref('')
const scans = ref([])
const logContainerRef = ref(null)

// Edit dialog state
const editVisible = ref(false)
const editSubmitting = ref(false)
const editForm = reactive({ id: null, name: '', targets: '', scan_type: '', interval_minutes: 60 })

// Auto-refresh timer for running tasks
let refreshTimer = null

const IP_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/
const CIDR_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/
const RANGE_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$/
const HOSTNAME_RE = /^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$/

const detectTargetType = (val) => {
  if (CIDR_RE.test(val)) return { type: 'cidr', typeLabel: 'CIDR', valid: true }
  if (IP_RE.test(val)) {
    const parts = val.split('.').map(Number)
    if (parts.every(p => p >= 0 && p <= 255)) return { type: 'ip', typeLabel: 'IP', valid: true }
    return { type: 'invalid', typeLabel: '无效', valid: false }
  }
  if (RANGE_RE.test(val)) return { type: 'range', typeLabel: 'IP范围', valid: true }
  if (HOSTNAME_RE.test(val) && !val.includes('..')) return { type: 'hostname', typeLabel: '域名', valid: true }
  return { type: 'invalid', typeLabel: '无效', valid: false }
}

const targetList = computed(() => {
  if (!scanForm.targets) return []
  return scanForm.targets.split('\n').filter(l => l.trim()).map(t => {
    const info = detectTargetType(t.trim())
    return { value: t.trim(), ...info }
  })
})

const addTarget = () => {
  const val = targetInput.value.trim()
  if (!val) return
  const info = detectTargetType(val)
  if (!info.valid) {
    ElMessage.warning(`无效的扫描目标: ${val}`)
    return
  }
  const existing = (scanForm.targets || '').split('\n').map(l => l.trim()).filter(Boolean)
  if (existing.includes(val)) {
    ElMessage.info('目标已存在')
    targetInput.value = ''
    return
  }
  existing.push(val)
  scanForm.targets = existing.join('\n')
  targetInput.value = ''
}

const removeTarget = (index) => {
  const lines = (scanForm.targets || '').split('\n').filter(l => l.trim())
  lines.splice(index, 1)
  scanForm.targets = lines.join('\n')
}

const clearTargets = () => {
  scanForm.targets = ''
}

const oneTimeScans = computed(() => scans.value.filter(s => s.scan_type === 'one_time'))
const periodicScans = computed(() => scans.value.filter(s => s.scan_type === 'periodic'))

const scanForm = reactive({ name: '', targets: '', scan_type: 'one_time', max_concurrent: 4, interval_minutes: 60 })
const scanRules = {
  name: [{ required: true, message: '请输入任务名称', trigger: 'blur' }],
  targets: [{ required: true, message: '请输入扫描目标', trigger: 'blur' }]
}

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

const fetchScans = async () => {
  try {
    const res = await getHostScans()
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
  const invalidTargets = targetList.value.filter(t => !t.valid)
  if (invalidTargets.length) {
    ElMessage.error(`存在无效目标: ${invalidTargets.map(t => t.value).join(', ')}`)
    return
  }
  submitting.value = true
  try {
    const payload = { name: scanForm.name, targets: scanForm.targets, scan_type: scanForm.scan_type, max_concurrent: scanForm.max_concurrent, interval_minutes: scanForm.interval_minutes, scan_category: 'host_discovery', scan_methods: ['nmap_ping', 'nmap_arp', 'nmap_syn'], scan_mode: 'standard' }
    await createHostScan(payload)
    ElMessage.success('主机发现任务已创建')
    scanForm.name = ''
    scanForm.targets = ''
    targetInput.value = ''
    await fetchScans()
    startAutoRefresh()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '创建失败')
  } finally { submitting.value = false }
}

const viewDetail = async (row) => {
  try {
    const res = await getHostScanDetail(row.id)
    detailData.value = res.data
    detailTab.value = 'result'
    detailVisible.value = true

    // If running, start polling for detail updates
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
      const res = await getHostScanDetail(taskId)
      detailData.value = res.data
      // Auto-scroll log to bottom
      await nextTick()
      if (logContainerRef.value) {
        logContainerRef.value.scrollTop = logContainerRef.value.scrollHeight
      }
      // Stop polling when done
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
  try { await cancelHostScan(row.id); ElMessage.success('已取消'); await fetchScans() } catch (e) { ElMessage.error('取消失败') }
}

const handleActivate = async (row) => {
  try { await activateHostScan(row.id); ElMessage.success('已启用'); await fetchScans() } catch (e) { ElMessage.error('启用失败') }
}

const handleDeactivate = async (row) => {
  try { await deactivateHostScan(row.id); ElMessage.success('已停用'); await fetchScans() } catch (e) { ElMessage.error('停用失败') }
}

const handleRescan = async (row) => {
  try {
    await ElMessageBox.confirm('确定要使用相同配置重新扫描吗？', '重新扫描', { type: 'info' })
    await rescanHostScan(row.id)
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
    await updateHostScan(editForm.id, {
      name: editForm.name,
      targets: editForm.targets,
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
    await deleteHostScan(row.id)
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
.target-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 2px;
  padding: 8px;
  border: 1px solid #dcdfe6;
  border-radius: 4px;
  min-height: 40px;
  background: #fafafa;
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
