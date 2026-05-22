<template>
  <div>
    <el-card>
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
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { getVulns, markFalsePositive } from '../api/vulns'
import { ElMessage } from 'element-plus'

const vulns = ref([])
const filters = reactive({ severity: '', cve_id: '' })
const drawerVisible = ref(false)
const currentVuln = ref(null)

const severityType = (s) => ({ Critical: 'danger', High: 'warning', Medium: '', Low: 'info' }[s] || 'info')

const fetchData = async () => {
  const res = await getVulns(filters)
  vulns.value = res.data.items || res.data || []
}

const viewDetail = (row) => { currentVuln.value = row; drawerVisible.value = true }

const markFP = async (row) => {
  await markFalsePositive(row.id)
  ElMessage.success('已标记为误报')
  fetchData()
}

onMounted(fetchData)
</script>
