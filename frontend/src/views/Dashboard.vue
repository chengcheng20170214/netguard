<template>
  <div>
    <el-row :gutter="20" class="stats-row">
      <el-col :span="6"><el-card shadow="hover"><el-statistic title="资产总数" :value="stats.totalAssets" /></el-card></el-col>
      <el-col :span="6"><el-card shadow="hover"><el-statistic title="在线资产" :value="stats.onlineAssets" /></el-card></el-col>
      <el-col :span="6"><el-card shadow="hover"><el-statistic title="漏洞数量" :value="stats.vulns" /></el-card></el-col>
      <el-col :span="6"><el-card shadow="hover"><el-statistic title="近期变更" :value="stats.recentChanges" /></el-card></el-col>
    </el-row>
    <el-row :gutter="20" style="margin-top:20px">
      <el-col :span="12"><el-card><div ref="vulnChartRef" style="height:300px"></div></el-card></el-col>
      <el-col :span="12"><el-card><div ref="changeChartRef" style="height:300px"></div></el-card></el-col>
    </el-row>
    <el-card style="margin-top:20px">
      <template #header><span>最近扫描</span></template>
      <el-table :data="recentScans" stripe border size="small">
        <el-table-column prop="name" label="名称" />
        <el-table-column prop="targets" label="目标" show-overflow-tooltip />
        <el-table-column prop="scan_mode" label="模式" width="120" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }"><el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="180" />
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, nextTick } from 'vue'
import * as echarts from 'echarts'
import { getScans } from '../api/discovery'
import { getAssets, getAllChanges } from '../api/assets'
import { getVulns } from '../api/vulns'

const stats = reactive({ totalAssets: 0, onlineAssets: 0, vulns: 0, recentChanges: 0 })
const recentScans = ref([])
const vulnChartRef = ref(null)
const changeChartRef = ref(null)

const statusType = (s) => ({ pending: 'info', running: 'warning', completed: 'success', failed: 'danger', cancelled: 'info' }[s] || 'info')
const statusLabel = (s) => ({ pending: '等待中', running: '扫描中', completed: '已完成', failed: '失败', cancelled: '已取消' }[s] || s)

onMounted(async () => {
  try {
    const [assetsRes, vulnsRes, changesRes, scansRes] = await Promise.all([
      getAssets({ limit: 1 }), getVulns({ limit: 1 }), getAllChanges({ limit: 1 }), getScans({ limit: 10 })
    ])
    const assetData = assetsRes.data
    stats.totalAssets = assetData.total || 0
    stats.onlineAssets = (assetData.items || []).filter(a => a.is_online).length
    stats.vulns = vulnsRes.data.total || 0
    stats.recentChanges = changesRes.data.total || 0
    recentScans.value = scansRes.data.items || []
  } catch (e) { console.error(e) }

  await nextTick()
  if (vulnChartRef.value) {
    const chart = echarts.init(vulnChartRef.value)
    chart.setOption({
      title: { text: '漏洞严重程度分布', left: 'center' },
      tooltip: { trigger: 'item' },
      series: [{ type: 'pie', radius: ['40%', '70%'], data: [
        { value: 5, name: '严重', itemStyle: { color: '#F56C6C' } },
        { value: 12, name: '高危', itemStyle: { color: '#E6A23C' } },
        { value: 28, name: '中危', itemStyle: { color: '#409EFF' } },
        { value: 45, name: '低危', itemStyle: { color: '#67C23A' } }
      ] }]
    })
  }
  if (changeChartRef.value) {
    const chart2 = echarts.init(changeChartRef.value)
    chart2.setOption({
      title: { text: '资产变更趋势(近7天)', left: 'center' },
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', data: ['周一', '周二', '周三', '周四', '周五', '周六', '周日'] },
      yAxis: { type: 'value' },
      series: [{ data: [5, 8, 3, 12, 7, 2, 9], type: 'line', smooth: true, areaStyle: {} }]
    })
  }
})
</script>

<style scoped>
.stats-row .el-card { text-align: center; }
</style>
