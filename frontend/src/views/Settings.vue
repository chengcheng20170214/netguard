<template>
  <div>
    <el-card>
      <template #header>
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span>系统设置</span>
          <el-button type="primary" size="small" @click="fetchSettings">刷新</el-button>
        </div>
      </template>
      <el-tabs v-model="activeTab">
        <el-tab-pane label="数据库与缓存" name="db">
          <el-form label-width="200px" style="max-width:700px">
            <el-form-item v-for="item in dbConfigs" :key="item.key" :label="item.description || item.key">
              <div style="display:flex;gap:8px;width:100%">
                <el-input v-model="item.real_value" :type="item.is_secret ? 'password' : 'text'" show-password-if-secret style="flex:1" />
                <el-button size="small" type="primary" @click="saveConfig(item)">保存</el-button>
                <el-button size="small" @click="resetConfig(item)">重置</el-button>
              </div>
            </el-form-item>
          </el-form>
        </el-tab-pane>
        <el-tab-pane label="认证与安全" name="auth">
          <el-form label-width="200px" style="max-width:700px">
            <el-form-item v-for="item in authConfigs" :key="item.key" :label="item.description || item.key">
              <div style="display:flex;gap:8px;width:100%">
                <el-input v-model="item.real_value" :type="item.is_secret ? 'password' : 'text'" style="flex:1" />
                <el-button size="small" type="primary" @click="saveConfig(item)">保存</el-button>
                <el-button size="small" @click="resetConfig(item)">重置</el-button>
              </div>
            </el-form-item>
          </el-form>
        </el-tab-pane>
        <el-tab-pane label="扫描器" name="scanner">
          <el-form label-width="200px" style="max-width:700px">
            <el-form-item v-for="item in scannerConfigs" :key="item.key" :label="item.description || item.key">
              <div style="display:flex;gap:8px;width:100%">
                <el-input v-model="item.real_value" :type="item.is_secret ? 'password' : 'text'" style="flex:1" />
                <el-button size="small" type="primary" @click="saveConfig(item)">保存</el-button>
                <el-button size="small" @click="resetConfig(item)">重置</el-button>
              </div>
            </el-form-item>
          </el-form>
        </el-tab-pane>
        <el-tab-pane label="扫描提权" name="privilege">
          <div style="max-width:700px">
            <!-- 能力概览 -->
            <el-descriptions title="扫描能力检测" :column="1" border style="margin-bottom:20px">
              <el-descriptions-item label="nmap 可用性">
                <el-tag :type="capabilities.nmap_available ? 'success' : 'danger'" size="small">
                  {{ capabilities.nmap_available ? '可用' : '不可用' }}
                </el-tag>
                <span v-if="capabilities.nmap_version" style="margin-left:8px;color:#909399;font-size:12px">
                  v{{ capabilities.nmap_version }}
                </span>
              </el-descriptions-item>
              <el-descriptions-item label="OS 识别能力">
                <el-tag :type="capabilities.os_detect_available ? 'success' : 'warning'" size="small">
                  {{ capabilities.os_detect_available ? '可用' : '不可用' }}
                </el-tag>
                <span v-if="capabilities.os_detect_reason" style="margin-left:8px;color:#E6A23C;font-size:12px">
                  {{ capabilities.os_detect_reason }}
                </span>
              </el-descriptions-item>
              <el-descriptions-item label="sudo 提权">
                <el-tag :type="capabilities.sudo_enabled ? 'success' : 'info'" size="small">
                  {{ capabilities.sudo_enabled ? '已启用' : '未启用' }}
                </el-tag>
                <span style="margin-left:8px;color:#909399;font-size:12px">
                  密码: {{ capabilities.sudo_configured ? '已配置' : '未配置' }}
                </span>
              </el-descriptions-item>
            </el-descriptions>

            <el-alert
              v-if="!capabilities.os_detect_available"
              title="OS 识别功能不可用"
              type="warning"
              :description="'当前服务以非 root 权限运行，nmap -O 无法执行。' + (capabilities.sudo_enabled ? '请配置 sudo 密码以提权执行。' : '请在下方启用 sudo 提权并配置密码。')"
              show-icon
              :closable="false"
              style="margin-bottom:20px"
            />

            <!-- sudo 配置表单 -->
            <el-form label-width="200px">
              <el-form-item label="启用 sudo 提权">
                <el-switch
                  v-model="sudoEnabled"
                  active-text="启用"
                  inactive-text="关闭"
                  @change="onSudoEnabledChange"
                />
                <div style="margin-left:12px;color:#909399;font-size:12px">
                  启用后，nmap OS 识别(-O)等需要 root 权限的操作将通过 sudo 提权执行
                </div>
              </el-form-item>

              <el-form-item label="sudo 密码">
                <div style="display:flex;gap:8px;width:100%">
                  <el-input
                    v-model="sudoPassword"
                    type="password"
                    show-password
                    placeholder="输入 sudo 密码"
                    style="flex:1"
                    :disabled="!sudoEnabled"
                  />
                  <el-button
                    size="small"
                    type="primary"
                    :disabled="!sudoEnabled || !sudoPassword"
                    :loading="sudoSaving"
                    @click="saveSudoPassword"
                  >
                    {{ capabilities.sudo_configured ? '更新密码' : '保存密码' }}
                  </el-button>
                  <el-button
                    size="small"
                    :disabled="!sudoEnabled || !capabilities.sudo_configured"
                    @click="verifySudoPasswordAction"
                  >
                    验证
                  </el-button>
                  <el-button
                    size="small"
                    type="danger"
                    :disabled="!capabilities.sudo_configured"
                    @click="removeSudoPassword"
                  >
                    删除
                  </el-button>
                </div>
              </el-form-item>
            </el-form>
          </div>
        </el-tab-pane>
        <el-tab-pane label="NVD 漏洞库" name="nvd">
          <el-form label-width="200px" style="max-width:700px">
            <el-form-item v-for="item in nvdConfigs" :key="item.key" :label="item.description || item.key">
              <div style="display:flex;gap:8px;width:100%">
                <el-input v-model="item.real_value" :type="item.is_secret ? 'password' : 'text'" style="flex:1" />
                <el-button size="small" type="primary" @click="saveConfig(item)">保存</el-button>
                <el-button size="small" @click="resetConfig(item)">重置</el-button>
              </div>
            </el-form-item>
          </el-form>
        </el-tab-pane>
        <el-tab-pane label="其他" name="other">
          <el-form label-width="200px" style="max-width:700px">
            <el-form-item v-for="item in otherConfigs" :key="item.key" :label="item.description || item.key">
              <div style="display:flex;gap:8px;width:100%">
                <el-input v-model="item.real_value" :type="item.is_secret ? 'password' : 'text'" style="flex:1" />
                <el-button size="small" type="primary" @click="saveConfig(item)">保存</el-button>
                <el-button size="small" @click="resetConfig(item)">重置</el-button>
              </div>
            </el-form-item>
          </el-form>
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { getSettings, updateSetting, resetSetting } from '../api/settings'
import { getScanCapabilities, setSudoPassword as apiSetSudoPassword, deleteSudoPassword as apiDeleteSudoPassword, verifySudoPassword as apiVerifySudoPassword, toggleSudoEnabled } from '../api/discovery'
import { ElMessage, ElMessageBox } from 'element-plus'

const configs = ref([])
const activeTab = ref('db')

// 扫描能力状态
const capabilities = ref({
  nmap_available: false,
  nmap_version: null,
  os_detect_available: false,
  os_detect_reason: null,
  sudo_configured: false,
  sudo_enabled: false,
})
const sudoEnabled = ref(false)
const sudoPassword = ref('')
const sudoSaving = ref(false)

const dbKeys = ['database_url', 'redis_url', 'celery_broker_url', 'celery_result_backend']
const authKeys = ['jwt_secret_key', 'jwt_algorithm', 'access_token_expire_minutes', 'refresh_token_expire_days']
const scannerKeys = ['nmap_path', 'scan_default_timeout', 'scan_max_concurrent']
const nvdKeys = ['nvd_api_key', 'nvd_api_url', 'nvd_rate_limit_interval']

const dbConfigs = computed(() => configs.value.filter(c => dbKeys.includes(c.key)))
const authConfigs = computed(() => configs.value.filter(c => authKeys.includes(c.key)))
const scannerConfigs = computed(() => configs.value.filter(c => scannerKeys.includes(c.key)))
const nvdConfigs = computed(() => configs.value.filter(c => nvdKeys.includes(c.key)))
const otherConfigs = computed(() => configs.value.filter(c => !dbKeys.includes(c.key) && !authKeys.includes(c.key) && !scannerKeys.includes(c.key) && !nvdKeys.includes(c.key)))

const fetchSettings = async () => {
  const res = await getSettings()
  configs.value = res.data.items || []
}

const fetchCapabilities = async () => {
  try {
    const res = await getScanCapabilities()
    capabilities.value = res.data
    sudoEnabled.value = res.data.sudo_enabled
  } catch (e) {
    console.warn('获取扫描能力失败', e)
  }
}

const onSudoEnabledChange = async (val) => {
  try {
    await toggleSudoEnabled(val)
    ElMessage.success(val ? 'sudo 提权已启用' : 'sudo 提权已关闭')
    await fetchCapabilities()
  } catch (e) {
    ElMessage.error('更新 sudo 启用状态失败')
    sudoEnabled.value = !val
  }
}

const saveSudoPassword = async () => {
  if (!sudoPassword.value) {
    ElMessage.warning('请输入 sudo 密码')
    return
  }
  sudoSaving.value = true
  try {
    await apiSetSudoPassword(sudoPassword.value)
    ElMessage.success('sudo 密码已保存')
    sudoPassword.value = ''
    await fetchCapabilities()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '保存 sudo 密码失败')
  } finally {
    sudoSaving.value = false
  }
}

const verifySudoPasswordAction = async () => {
  if (!sudoPassword.value) {
    ElMessage.warning('请输入 sudo 密码进行验证')
    return
  }
  try {
    const res = await apiVerifySudoPassword(sudoPassword.value)
    if (res.data.valid) {
      ElMessage.success(res.data.message || 'sudo 密码验证成功')
    } else {
      ElMessage.error(res.data.message || 'sudo 密码验证失败')
    }
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '验证失败')
  }
}

const removeSudoPassword = async () => {
  try {
    await ElMessageBox.confirm('确定删除已保存的 sudo 密码？删除后 OS 识别将无法通过 sudo 提权执行。', '确认删除', { type: 'warning' })
    await apiDeleteSudoPassword()
    ElMessage.success('sudo 密码已删除')
    await fetchCapabilities()
  } catch (e) {
    if (e !== 'cancel') {
      ElMessage.error('删除 sudo 密码失败')
    }
  }
}

const saveConfig = async (item) => {
  if (item.is_secret && item.real_value === '********') {
    ElMessage.warning('请输入新值，不能保存掩码')
    return
  }
  await updateSetting(item.key, item.real_value)
  ElMessage.success(item.description + ' 已保存')
  fetchSettings()
}

const resetConfig = async (item) => {
  await ElMessageBox.confirm('确定将 ' + (item.description || item.key) + ' 重置为默认值?', '确认重置')
  await resetSetting(item.key)
  ElMessage.success('已重置为默认值')
  fetchSettings()
}

onMounted(() => {
  fetchSettings()
  fetchCapabilities()
})
</script>
