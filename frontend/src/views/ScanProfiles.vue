<template>
  <div>
    <el-card>
      <template #header>
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span>扫描策略管理</span>
          <el-button type="primary" @click="openCreate">
            <el-icon style="margin-right:4px"><Plus /></el-icon>新建策略
          </el-button>
        </div>
      </template>

      <el-table :data="profiles" stripe border>
        <el-table-column prop="name" label="名称" width="140" />
        <el-table-column prop="description" label="描述" min-width="200" show-overflow-tooltip />
        <el-table-column label="端口发现" width="120">
          <template #default="{ row }">
            <el-tag size="small" :type="row.port_scan?.mode === 'full' ? 'danger' : 'info'">
              {{ portModeLabel(row.port_scan) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="服务识别" width="80" align="center">
          <template #default="{ row }">
            <el-icon v-if="row.service_detect?.enabled" style="color:#67C23A"><Check /></el-icon>
            <el-icon v-else style="color:#909399"><Close /></el-icon>
          </template>
        </el-table-column>
        <el-table-column label="脚本扫描" width="80" align="center">
          <template #default="{ row }">
            <el-icon v-if="row.script_scan?.enabled" style="color:#E6A23C"><Check /></el-icon>
            <el-icon v-else style="color:#909399"><Close /></el-icon>
          </template>
        </el-table-column>
        <el-table-column label="OS识别" width="80" align="center">
          <template #default="{ row }">
            <el-icon v-if="row.os_detect?.enabled" style="color:#E6A23C"><Check /></el-icon>
            <el-icon v-else style="color:#909399"><Close /></el-icon>
          </template>
        </el-table-column>
        <el-table-column label="默认" width="70" align="center">
          <template #default="{ row }">
            <el-icon v-if="row.is_default" style="color:#409EFF"><Star /></el-icon>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="220" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="viewDetail(row)">详情</el-button>
            <el-button size="small" type="primary" @click="openEdit(row)" :disabled="row.is_builtin">编辑</el-button>
            <el-button size="small" :type="row.is_default ? 'info' : 'success'" @click="handleSetDefault(row)" :disabled="row.is_default">设为默认</el-button>
            <el-button size="small" type="danger" @click="handleDelete(row)" :disabled="row.is_builtin">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- Create/Edit Dialog -->
    <el-dialog v-model="formVisible" :title="isEdit ? '编辑扫描策略' : '新建扫描策略'" width="750px" :close-on-click-modal="false">
      <el-form :model="form" :rules="formRules" ref="formRef" label-width="110px">
        <el-form-item label="策略名称" prop="name">
          <el-input v-model="form.name" placeholder="如：快速探测、深度扫描" />
        </el-form-item>
        <el-form-item label="描述" prop="description">
          <el-input v-model="form.description" type="textarea" :rows="2" placeholder="策略用途说明" />
        </el-form-item>

        <el-divider content-position="left">阶段1: 端口发现</el-divider>
        <el-form-item label="端口范围" prop="port_scan_mode">
          <el-radio-group v-model="form.port_scan.mode">
            <el-tooltip content="扫描最常用的1000个端口，速度快" placement="top">
              <el-radio-button value="top1000">Top1000</el-radio-button>
            </el-tooltip>
            <el-tooltip content="扫描1-65535全部端口，耗时极长" placement="top">
              <el-radio-button value="full">全端口</el-radio-button>
            </el-tooltip>
            <el-tooltip content="自定义端口范围，如 22,80,443,1-1000" placement="top">
              <el-radio-button value="custom">自定义</el-radio-button>
            </el-tooltip>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="form.port_scan.mode === 'top1000'" label="端口数量">
          <el-input-number v-model="form.port_scan.top_ports" :min="100" :max="65535" :step="100" />
          <span style="margin-left:8px;color:#909399;font-size:12px">扫描最常见的N个端口</span>
        </el-form-item>
        <el-form-item v-if="form.port_scan.mode === 'custom'" label="自定义端口" prop="custom_ports">
          <el-input v-model="form.port_scan.custom_ports" placeholder="22,80,443,1-1000" />
        </el-form-item>
        <el-form-item label="扫描模式">
          <el-radio-group v-model="form.port_scan.scan_mode">
            <el-tooltip content="多IP合并为一次nmap调用，效率最高" placement="top">
              <el-radio-button value="standard">标准</el-radio-button>
            </el-tooltip>
            <el-tooltip content="每个IP单独扫描，按IP分配进度" placement="top">
              <el-radio-button value="ip_sequential">逐IP</el-radio-button>
            </el-tooltip>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="并发数">
          <el-slider v-model="form.port_scan.max_concurrent" :min="1" :max="16" :step="1" show-stops :marks="{ 1:'1', 4:'4', 8:'8', 16:'16' }" style="width:350px" />
        </el-form-item>

        <el-divider content-position="left">阶段2: 服务版本识别</el-divider>
        <el-form-item label="启用">
          <el-switch v-model="form.service_detect.enabled" />
        </el-form-item>
        <template v-if="form.service_detect.enabled">
          <el-form-item label="探测强度">
            <el-slider v-model="form.service_detect.intensity" :min="0" :max="9" :step="1" show-stops style="width:350px" />
            <span style="margin-left:8px;color:#909399;font-size:12px">0=最轻, 9=最全, 推荐7</span>
          </el-form-item>
          <el-form-item label="全端口探测">
            <el-switch v-model="form.service_detect.all_ports" />
            <span style="margin-left:8px;color:#909399;font-size:12px">不跳过9100等打印端口 (--allports)</span>
          </el-form-item>
        </template>

        <el-divider content-position="left">阶段3: 脚本扫描 (NSE)</el-divider>
        <el-form-item label="启用">
          <el-switch v-model="form.script_scan.enabled" />
        </el-form-item>
        <template v-if="form.script_scan.enabled">
          <el-form-item label="脚本分类">
            <div style="width:100%">
              <div style="margin-bottom:8px;color:#606266;font-size:13px;font-weight:500">推荐（安全、通用）</div>
              <el-checkbox-group v-model="form.script_scan.categories">
                <el-tooltip v-for="cat in recommendedCategories" :key="cat.value" :content="cat.desc" placement="top">
                  <el-checkbox :value="cat.value" :label="cat.label">
                    <span>{{ cat.label }}</span>
                  </el-checkbox>
                </el-tooltip>
              </el-checkbox-group>
              <div style="margin:8px 0;color:#606266;font-size:13px;font-weight:500">高级（专业用途，可能影响目标）</div>
              <el-checkbox-group v-model="form.script_scan.categories">
                <el-tooltip v-for="cat in advancedCategories" :key="cat.value" :content="cat.desc" placement="top">
                  <el-checkbox :value="cat.value" :label="cat.label">
                    <span>{{ cat.label }}</span>
                  </el-checkbox>
                </el-tooltip>
              </el-checkbox-group>
            </div>
          </el-form-item>
          <el-form-item label="自定义脚本">
            <el-input v-model="form.script_scan.custom_scripts" placeholder="如：http-title,ssl-heartbleed（逗号分隔，可选）" />
          </el-form-item>
          <el-form-item label="脚本参数">
            <el-input v-model="form.script_scan.script_args" placeholder="如：user=foo,pass=bar（可选）" />
          </el-form-item>
        </template>

        <el-divider content-position="left">阶段4: OS识别</el-divider>
        <el-form-item label="启用">
          <el-switch v-model="form.os_detect.enabled" :disabled="form.os_detect.enabled && !capabilities.os_detect_available" />
          <span v-if="form.os_detect.enabled" style="margin-left:8px;color:#E6A23C;font-size:12px">⚠️ 需要 root 权限</span>
        </el-form-item>
        <el-alert
          v-if="form.os_detect.enabled && !capabilities.os_detect_available"
          type="warning"
          :closable="false"
          style="margin-bottom:12px"
        >
          <template #title>
            OS 识别当前不可用：{{ capabilities.os_detect_reason || '需要root权限' }}。
            请前往<router-link to="/settings" style="color:#E6A23C;text-decoration:underline">系统设置 → 扫描提权</router-link>配置 sudo 密码
          </template>
        </el-alert>
        <template v-if="form.os_detect.enabled">
          <el-form-item label="最大尝试">
            <el-input-number v-model="form.os_detect.max_tries" :min="1" :max="10" />
          </el-form-item>
          <el-form-item label="推测模式">
            <el-switch v-model="form.os_detect.scan_guess" />
            <span style="margin-left:8px;color:#909399;font-size:12px">即使不够自信也给出OS猜测 (--osscan-guess)</span>
          </el-form-item>
        </template>

        <el-divider content-position="left">超时与性能</el-divider>
        <el-form-item label="Nmap超时">
          <el-input-number v-model="form.timing.nmap_timeout_sec" :min="60" :max="86400" :step="60" />
          <span style="margin-left:8px;color:#909399;font-size:12px">单次nmap调用最大秒数</span>
        </el-form-item>
        <el-form-item label="主机超时">
          <el-input-number v-model="form.timing.host_timeout" :min="0" :max="3600" :step="10" />
          <span style="margin-left:8px;color:#909399;font-size:12px">0=自动，单台主机最大等待秒数</span>
        </el-form-item>
        <el-form-item label="脚本超时">
          <el-input-number v-model="form.timing.script_timeout_sec" :min="5" :max="600" :step="5" />
          <span style="margin-left:8px;color:#909399;font-size:12px">单个NSE脚本最大秒数</span>
        </el-form-item>
        <el-form-item label="重试次数">
          <el-input-number v-model="form.timing.max_retries" :min="0" :max="10" />
        </el-form-item>
        <el-form-item label="最小速率">
          <el-input-number v-model="form.timing.min_rate" :min="0" :max="5000" :step="50" />
          <span style="margin-left:8px;color:#909399;font-size:12px">每秒发包下限 (--min-rate)，0=自动</span>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="formVisible = false">取消</el-button>
        <el-button type="primary" :loading="formSubmitting" @click="submitForm">保存</el-button>
      </template>
    </el-dialog>

    <!-- Detail Dialog -->
    <el-dialog v-model="detailVisible" title="策略详情" width="700px">
      <el-descriptions v-if="detailData" :column="2" border>
        <el-descriptions-item label="名称">{{ detailData.name }}</el-descriptions-item>
        <el-descriptions-item label="描述">{{ detailData.description }}</el-descriptions-item>
        <el-descriptions-item label="默认策略">
          <el-tag :type="detailData.is_default ? 'success' : 'info'" size="small">{{ detailData.is_default ? '是' : '否' }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="内置策略">
          <el-tag :type="detailData.is_builtin ? 'warning' : 'info'" size="small">{{ detailData.is_builtin ? '是' : '否' }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="端口发现" :span="2">
          {{ portModeLabel(detailData.port_scan) }}{{ detailData.port_scan?.mode === 'top1000' ? ' (top ' + detailData.port_scan?.top_ports + ')' : '' }}
          {{ detailData.port_scan?.mode === 'custom' ? ': ' + detailData.port_scan?.custom_ports : '' }}
          &nbsp;|&nbsp; 模式: {{ detailData.port_scan?.scan_mode === 'standard' ? '标准' : '逐IP' }}
          &nbsp;|&nbsp; 并发: {{ detailData.port_scan?.max_concurrent }}
        </el-descriptions-item>
        <el-descriptions-item label="服务识别" :span="2">
          <template v-if="detailData.service_detect?.enabled">
            启用 (强度 {{ detailData.service_detect.intensity }}{{ detailData.service_detect.all_ports ? ', 全端口' : '' }})
          </template>
          <template v-else>未启用</template>
        </el-descriptions-item>
        <el-descriptions-item label="脚本扫描" :span="2">
          <template v-if="detailData.script_scan?.enabled">
            启用 ({{ (detailData.script_scan.categories || []).join(', ') }})
            <template v-if="detailData.script_scan.custom_scripts"> + {{ detailData.script_scan.custom_scripts }}</template>
          </template>
          <template v-else>未启用</template>
        </el-descriptions-item>
        <el-descriptions-item label="OS识别" :span="2">
          <template v-if="detailData.os_detect?.enabled">
            启用 (最多 {{ detailData.os_detect.max_tries }} 次{{ detailData.os_detect.scan_guess ? ', 推测模式' : '' }})
          </template>
          <template v-else>未启用</template>
        </el-descriptions-item>
        <el-descriptions-item label="Nmap超时">{{ detailData.timing?.nmap_timeout_sec }}秒</el-descriptions-item>
        <el-descriptions-item label="主机超时">{{ detailData.timing?.host_timeout || '自动' }}{{ detailData.timing?.host_timeout ? '秒' : '' }}</el-descriptions-item>
        <el-descriptions-item label="脚本超时">{{ detailData.timing?.script_timeout_sec }}秒</el-descriptions-item>
        <el-descriptions-item label="重试次数">{{ detailData.timing?.max_retries }}</el-descriptions-item>
      </el-descriptions>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { getScanProfiles, getScanProfile, createScanProfile, updateScanProfile, deleteScanProfile, setDefaultScanProfile, getScanCapabilities } from '../api/discovery'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Check, Close, Star } from '@element-plus/icons-vue'

const profiles = ref([])
const formVisible = ref(false)
const formSubmitting = ref(false)
const isEdit = ref(false)
const formRef = ref(null)
const detailVisible = ref(false)
const detailData = ref(null)

// Scan capabilities for OS detect availability
const capabilities = ref({ os_detect_available: true, os_detect_reason: null })

// NSE script categories
const recommendedCategories = [
  { value: 'default', label: 'default (默认)', desc: 'Nmap默认脚本集，基本安全检查' },
  { value: 'safe', label: 'safe (安全)', desc: '不会对目标造成影响的脚本' },
  { value: 'vuln', label: 'vuln (漏洞)', desc: '漏洞检测脚本，安全评估推荐' },
]
const advancedCategories = [
  { value: 'auth', label: 'auth (认证)', desc: '绕过或暴力破解认证' },
  { value: 'broadcast', label: 'broadcast (广播)', desc: '局域网广播发现' },
  { value: 'brute', label: 'brute (暴力)', desc: '暴力破解脚本，可能触发入侵检测' },
  { value: 'discovery', label: 'discovery (发现)', desc: '服务和资源发现' },
  { value: 'dos', label: 'dos (拒绝服务)', desc: '可能导致服务崩溃，危险！' },
  { value: 'exploit', label: 'exploit (利用)', desc: '漏洞利用脚本，高度侵入性' },
  { value: 'external', label: 'external (外部)', desc: '需要外部资源(如GeoIP)' },
  { value: 'fuzzer', label: 'fuzzer (模糊)', desc: '模糊测试，可能引发异常' },
  { value: 'intrusive', label: 'intrusive (侵入)', desc: '可能被目标记录或阻断' },
  { value: 'malware', label: 'malware (恶意)', desc: '恶意软件检测' },
  { value: 'version', label: 'version (版本)', desc: '高级版本检测' },
]

// Default form values
const defaultForm = () => ({
  name: '',
  description: '',
  port_scan: { mode: 'top1000', top_ports: 1000, custom_ports: '', scan_mode: 'standard', max_concurrent: 4 },
  service_detect: { enabled: false, intensity: 7, all_ports: false },
  script_scan: { enabled: false, categories: ['default', 'safe'], custom_scripts: '', script_args: '' },
  os_detect: { enabled: false, max_tries: 2, scan_guess: false },
  timing: { host_timeout: 0, nmap_timeout_sec: 3600, script_timeout_sec: 60, max_retries: 3, min_rate: 300, max_rtt_timeout_ms: 500, initial_rtt_timeout_ms: 200, max_scan_delay_ms: 10, phase_executor: 'grouped' },
})

const form = reactive(defaultForm())
const editId = ref(null)

const formRules = {
  name: [{ required: true, message: '请输入策略名称', trigger: 'blur' }],
}

const portModeLabel = (portScan) => {
  if (!portScan) return '-'
  const modeMap = { top1000: 'Top1000', full: '全端口', custom: '自定义' }
  return modeMap[portScan.mode] || portScan.mode || '-'
}

// ──── CRUD ────

const fetchProfiles = async () => {
  try {
    const res = await getScanProfiles()
    profiles.value = res.data || []
  } catch (e) {
    console.error('Failed to fetch profiles:', e)
  }
}

const openCreate = () => {
  isEdit.value = false
  editId.value = null
  Object.assign(form, defaultForm())
  formVisible.value = true
}

const openEdit = async (row) => {
  try {
    const res = await getScanProfile(row.id)
    const data = res.data
    isEdit.value = true
    editId.value = row.id
    form.name = data.name
    form.description = data.description || ''
    form.port_scan = { ...defaultForm().port_scan, ...data.port_scan }
    form.service_detect = { ...defaultForm().service_detect, ...data.service_detect }
    form.script_scan = { ...defaultForm().script_scan, ...data.script_scan }
    form.os_detect = { ...defaultForm().os_detect, ...data.os_detect }
    form.timing = { ...defaultForm().timing, ...data.timing }
    formVisible.value = true
  } catch (e) {
    ElMessage.error('获取策略详情失败')
  }
}

const submitForm = async () => {
  const valid = await formRef.value.validate().catch(() => false)
  if (!valid) return

  // Validate custom_ports when mode=custom
  if (form.port_scan.mode === 'custom' && !form.port_scan.custom_ports) {
    ElMessage.warning('自定义端口模式下必须指定端口范围')
    return
  }

  // Validate script categories not empty when enabled
  if (form.script_scan.enabled && !form.script_scan.categories.length) {
    ElMessage.warning('脚本扫描启用时至少选择一个分类')
    return
  }

  formSubmitting.value = true
  try {
    const payload = {
      name: form.name,
      description: form.description || null,
      port_scan: form.port_scan,
      service_detect: form.service_detect,
      script_scan: form.script_scan,
      os_detect: form.os_detect,
      timing: form.timing,
    }
    if (isEdit.value) {
      await updateScanProfile(editId.value, payload)
      ElMessage.success('策略已更新')
    } else {
      await createScanProfile(payload)
      ElMessage.success('策略已创建')
    }
    formVisible.value = false
    await fetchProfiles()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '操作失败')
  } finally { formSubmitting.value = false }
}

const viewDetail = async (row) => {
  try {
    const res = await getScanProfile(row.id)
    detailData.value = res.data
    detailVisible.value = true
  } catch (e) {
    ElMessage.error('获取详情失败')
  }
}

const handleSetDefault = async (row) => {
  try {
    await setDefaultScanProfile(row.id)
    ElMessage.success('已设为默认策略')
    await fetchProfiles()
  } catch (e) {
    ElMessage.error('设置失败')
  }
}

const handleDelete = async (row) => {
  try {
    await ElMessageBox.confirm(`确定要删除策略"${row.name}"吗？`, '删除确认', { type: 'warning' })
    await deleteScanProfile(row.id)
    ElMessage.success('已删除')
    await fetchProfiles()
  } catch (e) {
    if (e !== 'cancel') {
      ElMessage.error(e.response?.data?.detail || '删除失败')
    }
  }
}

onMounted(() => {
  fetchProfiles()
  fetchCapabilities()
})

const fetchCapabilities = async () => {
  try {
    const res = await getScanCapabilities()
    capabilities.value = res.data
  } catch (e) {
    // 忽略
  }
}
</script>

<style scoped>
</style>
