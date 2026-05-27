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
import { ElMessage, ElMessageBox } from 'element-plus'

const configs = ref([])
const activeTab = ref('db')

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

onMounted(fetchSettings)
</script>
