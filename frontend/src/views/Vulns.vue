<template>
  <div>
    <el-card>
      <template #header>
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span>漏洞库状态</span>
          <div style="display:flex;gap:8px">
            <el-button size="small" type="primary" :disabled="updating" @click="handleFullUpdate">全量更新</el-button>
            <el-button size="small" type="success" :disabled="updating" @click="handleIncrementalUpdate">增量更新</el-button>
            <el-button size="small" :loading="scanningAll" @click="handleScanAll">全量扫描</el-button>
            <el-button size="small" @click="showAutoConfig=true">自动扫描配置</el-button>
          </div>
        </div>
      </template>
      <el-row :gutter="20" v-if="dbStatus">
        <el-col :span="6">
          <el-statistic title="漏洞库CVE总数" :value="dbStatus.total_cves" />
        </el-col>
        <el-col :span="6">
          <el-statistic title="上次全量更新" :value="dbStatus.last_full_update ? dbStatus.last_full_update.slice(0,19) : '从未'" />
        </el-col>
        <el-col :span="6">
          <el-statistic title="上次增量更新" :value="dbStatus.last_incremental_update ? dbStatus.last_incremental_update.slice(0,19) : '从未'" />
        </el-col>
        <el-col :span="6">
          <div style="padding-top:20px">
            <el-tag v-if="dbStatus.auto_scan_enabled" type="success">自动扫描：每{{ dbStatus.auto_scan_interval_hours }}小时</el-tag>
            <el-tag v-else type="info">自动扫描：未启用</el-tag>
          </div>
        </el-col>
      </el-row>
      <div v-if="updating" style="margin-top:16px">
        <el-progress :percentage="updateProgress.percent" :format="() => updateProgress.message" />
      </div>
      <el-row :gutter="12" style="margin-top:16px" v-if="dbStatus && dbStatus.by_severity">
        <el-col :span="6" v-for="(count, sev) in dbStatus.by_severity" :key="sev">
          <el-tag :type="severityType(sev)" style="width:100%;text-align:center">{{ sev || '未知' }}: {{ count }}</el-tag>
        </el-col>
      </el-row>
    </el-card>

    <el-card style="margin-top:20px">
      <template #header><span>漏洞列表</span></template>
      <div style="margin-bottom:16px;display:flex;gap:12px">
        <el-select v-model="filters.severity" placeholder="严重程度" clearable style="width:120px" @change="fetchData">
          <el-option label="严重" value="Critical" />
          <el-option label="高危" value="High" />
          <el-option label="中危" value="Medium" />
          <el-option label="低危" value="Low" />
        </el-select>
        <el-input v-model="filters.cve_id" placeholder="CVE ID" clearable style="width:200px" @clear="fetchData" @keyup.enter="fetchData" />
        <el-button type="primary" @click="fetchData">搜索</el-button>
      </div>
      <el-table :data="vulns" stripe border>
        <el-table-column prop="cve_id" label="CVE ID" width="150" />
        <el-table-column prop="severity" label="严重程度" width="100">
          <template #default="{ row }"><el-tag :type="severityType(row.severity)">{{ row.severity }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="cvss_score" label="CVSS" width="80" />
        <el-table-column prop="affected_service" label="服务" width="150" />
        <el-table-column prop="affected_version" label="版本" width="120" />
        <el-table-column prop="cve_description" label="描述" show-overflow-tooltip />
        <el-table-column label="操作" width="150">
          <template #default="{ row }">
            <el-button size="small" @click="viewDetail(row)">详情</el-button>
            <el-button v-if="!row.is_false_positive" size="small" type="warning" @click="markFP(row)">误报</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-drawer v-model="drawerVisible" title="漏洞详情" size="50%">
      <el-descriptions v-if="currentVuln" :column="1" border>
        <el-descriptions-item label="CVE ID">{{ currentVuln.cve_id }}</el-descriptions-item>
        <el-descriptions-item label="严重程度">{{ currentVuln.severity }}</el-descriptions-item>
        <el-descriptions-item label="CVSS评分">{{ currentVuln.cvss_score }}</el-descriptions-item>
        <el-descriptions-item label="影响服务">{{ currentVuln.affected_service }}</el-descriptions-item>
        <el-descriptions-item label="影响版本">{{ currentVuln.affected_version }}</el-descriptions-item>
        <el-descriptions-item label="描述">{{ currentVuln.cve_description }}</el-descriptions-item>
        <el-descriptions-item label="修复建议">{{ currentVuln.remediation || '-' }}</el-descriptions-item>
      </el-descriptions>
    </el-drawer>

    <el-dialog v-model="showAutoConfig" title="自动漏洞扫描配置" width="500px">
      <el-form label-width="120px">
        <el-form-item label="启用自动扫描">
          <el-switch v-model="autoConfig.enabled" />
        </el-form-item>
        <el-form-item v-if="autoConfig.enabled" label="扫描间隔">
          <el-input-number v-model="autoConfig.interval_hours" :min="1" :max="720" />
          <span style="margin-left:8px;color:#909399">小时</span>
        </el-form-item>
        <el-alert v-if="autoConfig.enabled" type="info" :closable="false" style="margin-top:8px">
          将每隔 {{ autoConfig.interval_hours }} 小时自动增量更新漏洞库并扫描所有在线资产。
        </el-alert>
      </el-form>
      <template #footer>
        <el-button @click="showAutoConfig=false">取消</el-button>
        <el-button type="primary" :loading="savingConfig" @click="saveAutoConfig">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import { getVulns, markFalsePositive, scanAllVulns, updateVulnDBFull, updateVulnDBIncremental, getUpdateProgress, getVulnDBStatus, configureAutoScan } from '../api/vulns'
import { ElMessage } from 'element-plus'

const vulns = ref([])
const dbStatus = ref(null)
const filters = reactive({ severity: '', cve_id: '' })
const drawerVisible = ref(false)
const currentVuln = ref(null)
const scanningAll = ref(false)
const updating = ref(false)
const updateProgress = reactive({ percent: 0, message: '' })
const showAutoConfig = ref(false)
const savingConfig = ref(false)
const autoConfig = reactive({ enabled: false, interval_hours: 24 })
let progressTimer = null

const severityType = (s) => ({ Critical: 'danger', High: 'warning', Medium: '', Low: 'info' }[s] || 'info')

const fetchData = async () => {
  const res = await getVulns(filters)
  vulns.value = res.data.items || res.data || []
}

const fetchStatus = async () => {
  try {
    const res = await getVulnDBStatus()
    dbStatus.value = res.data
    autoConfig.enabled = res.data.auto_scan_enabled
    autoConfig.interval_hours = res.data.auto_scan_interval_hours
  } catch (e) { console.error(e) }
}

const viewDetail = (row) => { currentVuln.value = row; drawerVisible.value = true }

const markFP = async (row) => {
  await markFalsePositive(row.id)
  ElMessage.success('已标记为误报')
  fetchData()
}

const handleScanAll = async () => {
  scanningAll.value = true
  try {
    const res = await scanAllVulns()
    ElMessage.success(`扫描完成：${res.data.scanned_assets} 个资产，发现 ${res.data.found_cves} 个漏洞`)
    fetchData()
    fetchStatus()
  } catch (e) { ElMessage.error('全量扫描失败') }
  finally { scanningAll.value = false }
}

const startProgressPolling = () => {
  if (progressTimer) return
  progressTimer = setInterval(async () => {
    try {
      const res = await getUpdateProgress()
      updateProgress.percent = res.data.percent || 0
      updateProgress.message = res.data.message || ''
      if (res.data.percent >= 100) {
        stopProgressPolling()
        updating.value = false
        fetchStatus()
      }
    } catch (e) { /* ignore */ }
  }, 2000)
}

const stopProgressPolling = () => {
  if (progressTimer) {
    clearInterval(progressTimer)
    progressTimer = null
  }
}

const handleFullUpdate = async () => {
  updating.value = true
  updateProgress.percent = 0
  updateProgress.message = '启动全量更新...'
  try {
    await updateVulnDBFull()
    ElMessage.info('全量更新已启动')
    startProgressPolling()
  } catch (e) {
    ElMessage.error('启动全量更新失败')
    updating.value = false
  }
}

const handleIncrementalUpdate = async () => {
  updating.value = true
  updateProgress.percent = 0
  updateProgress.message = '启动增量更新...'
  try {
    await updateVulnDBIncremental()
    ElMessage.info('增量更新已启动')
    startProgressPolling()
  } catch (e) {
    ElMessage.error('启动增量更新失败')
    updating.value = false
  }
}

const saveAutoConfig = async () => {
  savingConfig.value = true
  try {
    await configureAutoScan(autoConfig)
    ElMessage.success(autoConfig.enabled ? `已启用自动扫描，间隔${autoConfig.interval_hours}小时` : '已停用自动扫描')
    showAutoConfig.value = false
    fetchStatus()
  } catch (e) { ElMessage.error('保存配置失败') }
  finally { savingConfig.value = false }
}

onMounted(() => { fetchData(); fetchStatus() })
onUnmounted(() => { stopProgressPolling() })
</script>
