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

    <el-dialog v-model="detailVisible" title="主机发现详情" width="80%">
      <el-tabs>
        <el-tab-pane label="扫描结果">
          <el-table v-if="detailData" :data="detailData.results || []" stripe border>
            <el-table-column prop="ip" label="IP" width="150" />
            <el-table-column prop="mac" label="MAC地址" width="180" />
            <el-table-column prop="hostname" label="主机名" width="200" />
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
import { createHostScan, getHostScans, getHostScanDetail, cancelHostScan, activateHostScan, deactivateHostScan } from '../api/discovery'
import { ElMessage } from 'element-plus'

const scanFormRef = ref(null)
const submitting = ref(false)
const detailVisible = ref(false)
const detailData = ref(null)
const historyTab = ref('one_time')
const targetInput = ref('')
const scans = ref([])

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

const scanForm = reactive({ name: '', targets: '', scan_type: 'one_time', interval_minutes: 60 })
const scanRules = {
  name: [{ required: true, message: '请输入任务名称', trigger: 'blur' }],
  targets: [{ required: true, message: '请输入扫描目标', trigger: 'blur' }]
}

const statusType = (s) => ({ pending: 'info', running: 'warning', completed: 'success', failed: 'danger', cancelled: 'info' }[s] || 'info')
const statusLabel = (s) => ({ pending: '等待中', running: '扫描中', completed: '已完成', failed: '失败', cancelled: '已取消' }[s] || s)

const fetchScans = async () => {
  try {
    const res = await getHostScans()
    scans.value = res.data.items || res.data
  } catch (e) { /* ignore */ }
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
    const payload = { name: scanForm.name, targets: scanForm.targets, scan_type: scanForm.scan_type, interval_minutes: scanForm.interval_minutes, scan_category: 'host_discovery', scan_methods: ['nmap_ping', 'nmap_arp', 'nmap_syn'], scan_mode: 'standard' }
    await createHostScan(payload)
    ElMessage.success('主机发现任务已创建')
    scanForm.name = ''
    scanForm.targets = ''
    targetInput.value = ''
    await fetchScans()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '创建失败')
  } finally { submitting.value = false }
}

const viewDetail = async (row) => {
  try {
    const res = await getHostScanDetail(row.id)
    detailData.value = res.data
    detailVisible.value = true
  } catch (e) { ElMessage.error('获取详情失败') }
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

onMounted(() => { fetchScans() })
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
.log-empty {
  color: #6a9955;
  text-align: center;
  padding: 20px;
}
</style>
