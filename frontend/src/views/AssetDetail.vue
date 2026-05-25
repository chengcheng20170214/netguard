<template>
  <div v-if="asset">
    <el-page-header @back="goBack" :content="asset.ip" />
    <el-card style="margin-top:16px">
      <el-descriptions :column="3" border>
        <el-descriptions-item label="IP">{{ asset.ip }}</el-descriptions-item>
        <el-descriptions-item label="MAC">{{ asset.mac || '-' }}</el-descriptions-item>
        <el-descriptions-item label="主机名">{{ asset.hostname || '-' }}</el-descriptions-item>
        <el-descriptions-item label="操作系统">{{ asset.os || '-' }}</el-descriptions-item>
        <el-descriptions-item label="分组">{{ asset.group_name || '-' }}</el-descriptions-item>
        <el-descriptions-item label="状态"><el-tag :type="asset.is_online?'success':'danger'">{{ asset.is_online ? '在线' : '离线' }}</el-tag></el-descriptions-item>
        <el-descriptions-item label="首次发现">{{ asset.first_seen }}</el-descriptions-item>
        <el-descriptions-item label="最后发现">{{ asset.last_seen }}</el-descriptions-item>
      </el-descriptions>
    </el-card>
    <el-tabs style="margin-top:16px">
      <el-tab-pane label="端口">
        <el-table :data="asset.current_ports || []" stripe border>
          <el-table-column prop="port" label="端口" width="100" />
          <el-table-column prop="proto" label="协议" width="100" />
          <el-table-column prop="service" label="服务" width="150" />
          <el-table-column prop="version" label="版本" />
        </el-table>
      </el-tab-pane>
      <el-tab-pane label="变更历史">
        <el-timeline>
          <el-timeline-item v-for="c in changes" :key="c.id" :timestamp="c.detected_at" :color="changeColor(c.change_type)">
            <el-tag :type="changeTypeColor(c.change_type)" size="small">{{ changeTypeLabel(c.change_type) }}</el-tag>
            <span style="margin-left:8px">{{ formatChangeDetail(c) }}</span>
          </el-timeline-item>
        </el-timeline>
      </el-tab-pane>
      <el-tab-pane label="漏洞">
        <el-table :data="vulns" stripe border>
          <el-table-column prop="cve_id" label="CVE" width="150" />
          <el-table-column prop="severity" label="严重程度" width="100">
            <template #default="{ row }"><el-tag :type="severityType(row.severity)">{{ row.severity }}</el-tag></template>
          </el-table-column>
          <el-table-column prop="cvss_score" label="CVSS" width="80" />
          <el-table-column prop="affected_service" label="服务" width="150" />
          <el-table-column prop="cve_description" label="描述" show-overflow-tooltip />
        </el-table>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getAsset, getAssetChanges } from '../api/assets'
import { getVulns } from '../api/vulns'

const route = useRoute()
const router = useRouter()
const asset = ref(null)
const changes = ref([])
const vulns = ref([])

const goBack = () => { router.push('/assets') }

const changeTypeLabel = (t) => ({ new_host: '新增主机', host_down: '主机下线', new_service: '新增服务', service_closed: '服务关闭', version_changed: '版本变更', os_changed: 'OS变更', mac_changed: 'MAC变更', hostname_changed: '主机名变更' }[t] || t)
const changeTypeColor = (t) => ({ new_host: 'success', host_down: 'danger', new_service: '', service_closed: 'warning', version_changed: 'warning', os_changed: 'info', mac_changed: 'info', hostname_changed: 'info' }[t] || 'info')
const changeColor = (t) => ({ new_host: '#67C23A', host_down: '#F56C6C', new_service: '#409EFF', service_closed: '#E6A23C', version_changed: '#E6A23C', mac_changed: '#909399', hostname_changed: '#909399' }[t] || '#909399')

const formatChangeDetail = (c) => {
  const d = c.detail || {}
  switch (c.change_type) {
    case 'new_service': return `端口 ${d.port}/${d.proto || 'tcp'} 服务: ${d.service || '未知'}`
    case 'service_closed': return `端口 ${d.port}/${d.proto || 'tcp'} 服务: ${d.service || '未知'}`
    case 'version_changed': return `端口 ${d.port} ${d.service || ''}: ${d.old_version || '?'} → ${d.new_version || '?'}`
    case 'os_changed': return `${d.old || '?'} → ${d.new || '?'}`
    case 'hostname_changed': return `${d.old || '?'} → ${d.new || '?'}`
    case 'mac_changed': return `${d.old || '?'} → ${d.new || '?'}`
    case 'new_host': return '新发现主机'
    case 'host_down': return '主机下线'
    default: return JSON.stringify(d)
  }
}
const severityType = (s) => ({ Critical: 'danger', High: 'warning', Medium: '', Low: 'info' }[s] || 'info')

onMounted(async () => {
  const id = route.params.id
  const [assetRes, changesRes, vulnsRes] = await Promise.all([
    getAsset(id), getAssetChanges(id), getVulns({ asset_id: id })
  ])
  asset.value = assetRes.data
  changes.value = changesRes.data.items || changesRes.data || []
  vulns.value = (vulnsRes.data.items || vulnsRes.data || []).filter(v => v.asset_id === parseInt(id))
})
</script>
