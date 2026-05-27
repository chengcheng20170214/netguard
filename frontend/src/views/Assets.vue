<template>
  <div>
    <el-card>
      <template #header>
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span>资产列表</span>
          <div>
            <el-button size="small" @click="handleExport('json')">导出JSON</el-button>
            <el-button size="small" @click="handleExport('csv')">导出CSV</el-button>
          </div>
        </div>
      </template>
      <div style="margin-bottom:16px;display:flex;gap:12px">
        <el-input v-model="filters.ip" placeholder="搜索IP" clearable style="width:200px" @clear="fetchData" @keyup.enter="fetchData" />
        <el-input v-model="filters.group" placeholder="分组" clearable style="width:150px" @clear="fetchData" />
        <el-select v-model="filters.is_online" placeholder="状态" clearable style="width:120px" @change="fetchData">
          <el-option label="在线" :value="true" />
          <el-option label="离线" :value="false" />
        </el-select>
        <el-button type="primary" @click="fetchData">搜索</el-button>
      </div>
      <el-table :data="assets" stripe border>
        <el-table-column prop="ip" label="IP地址" width="150" />
        <el-table-column prop="hostname" label="主机名" width="150" />
        <el-table-column prop="mac" label="MAC" width="150" />
        <el-table-column prop="os" label="操作系统" width="150" show-overflow-tooltip />
        <el-table-column label="开放端口" min-width="250">
          <template #default="{ row }">
            <el-tag v-for="p in (row.current_ports || [])" :key="p.port" :type="isCriticalService(p.service) ? 'danger' : 'info'" size="small" style="margin-right:4px;margin-bottom:2px">{{ p.port }}/{{ p.service || '?' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="标签" width="150">
          <template #default="{ row }"><el-tag v-for="t in (row.tags||[])" :key="t" size="small" style="margin-right:4px">{{ t }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="group_name" label="分组" width="100" />
        <el-table-column label="状态" width="80">
          <template #default="{ row }"><el-tag :type="row.is_online?'success':'danger'" size="small">{{ row.is_online ? '在线' : '离线' }}</el-tag></template>
        </el-table-column>
        <el-table-column label="操作" width="180">
          <template #default="{ row }">
            <el-button size="small" @click="goDetail(row)">详情</el-button>
            <el-button size="small" type="danger" @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
    <el-card style="margin-top:20px">
      <template #header><span>近期变更</span></template>
      <el-table :data="recentChanges" stripe border size="small">
        <el-table-column prop="ip" label="IP" width="150" />
        <el-table-column prop="change_type" label="变更类型" width="120">
          <template #default="{ row }"><el-tag :type="changeTypeColor(row.change_type)" size="small">{{ changeTypeLabel(row.change_type) }}</el-tag></template>
        </el-table-column>
        <el-table-column label="变更详情" min-width="250">
          <template #default="{ row }">{{ formatChangeDetail(row) }}</template>
        </el-table-column>
        <el-table-column prop="severity" label="级别" width="80">
          <template #default="{ row }"><el-tag :type="severityColor(row.severity)" size="small">{{ severityLabel(row.severity) }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="detected_at" label="检测时间" width="180" />
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { getAssets, getAllChanges, deleteAsset, exportAssets } from '../api/assets'
import { ElMessage, ElMessageBox } from 'element-plus'

const router = useRouter()
const assets = ref([])
const recentChanges = ref([])
const filters = reactive({ ip: '', group: '', is_online: null })

const changeTypeLabel = (t) => ({ new_host: '新增主机', host_down: '主机下线', new_service: '新增服务', service_closed: '服务关闭', version_changed: '版本变更', os_changed: 'OS变更', mac_changed: 'MAC变更', hostname_changed: '主机名变更', ip_changed: 'IP变更' }[t] || t)
const changeTypeColor = (t) => ({ new_host: 'success', host_down: 'danger', new_service: '', service_closed: 'warning', version_changed: 'warning', os_changed: 'info', mac_changed: 'info', hostname_changed: 'info', ip_changed: 'warning' }[t] || 'info')
const severityColor = (s) => ({ info: '', warning: 'warning', critical: 'danger' }[s] || 'info')
const severityLabel = (s) => ({ info: '信息', warning: '警告', critical: '严重' }[s] || s)

const formatChangeDetail = (row) => {
  const d = row.detail || {}
  switch (row.change_type) {
    case 'new_service': return `端口 ${d.port}/${d.proto || 'tcp'} 服务: ${d.service || '未知'}`
    case 'service_closed': return `端口 ${d.port}/${d.proto || 'tcp'} 服务: ${d.service || '未知'}`
    case 'version_changed': return `端口 ${d.port} ${d.service || ''}: ${d.old_version || '?'} → ${d.new_version || '?'}`
    case 'os_changed': return `${d.old || '?'} → ${d.new || '?'}`
    case 'hostname_changed': return `${d.old || '?'} → ${d.new || '?'}`
    case 'mac_changed': return `${d.old || '?'} → ${d.new || '?'}`
    case 'ip_changed': return `${d.old || '?'} → ${d.new || '?'}`
    case 'new_host': return '新发现主机'
    case 'host_down': return '主机下线'
    default: return JSON.stringify(d)
  }
}

const fetchData = async () => {
  try {
    const [assetsRes, changesRes] = await Promise.all([getAssets(filters), getAllChanges({ limit: 20 })])
    assets.value = assetsRes.data.items || assetsRes.data || []
    recentChanges.value = changesRes.data.items || changesRes.data || []
  } catch (e) { console.error(e) }
}

const goDetail = (row) => { router.push('/assets/' + row.id) }

const handleDelete = async (row) => {
  await ElMessageBox.confirm('确定删除资产 ' + row.ip + '?', '确认')
  await deleteAsset(row.id)
  ElMessage.success('已删除')
  fetchData()
}

const isCriticalService = (svc) => ['ssh', 'mysql', 'rdp', 'redis', 'mongodb', 'mssql', 'postgresql', 'smb', 'vnc', 'telnet'].includes((svc || '').toLowerCase())

const handleExport = async (format) => {
  const res = await exportAssets(format)
  const url = URL.createObjectURL(res.data)
  const a = document.createElement('a')
  a.href = url
  a.download = 'assets.' + format
  a.click()
  URL.revokeObjectURL(url)
}

onMounted(fetchData)
</script>
