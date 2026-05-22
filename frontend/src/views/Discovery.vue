<template>
  <div>
    <el-card>
      <template #header><span>新建扫描任务</span></template>
      <el-form :model="scanForm" :rules="scanRules" ref="scanFormRef" label-width="100px">
        <el-form-item label="任务名称" prop="name">
          <el-input v-model="scanForm.name" placeholder="输入扫描任务名称" />
        </el-form-item>
        <el-form-item label="扫描目标" prop="targets">
          <el-input v-model="scanForm.targets" type="textarea" :rows="3" placeholder="输入IP或网段，每行一个" />
        </el-form-item>
        <el-form-item label="扫描模式" prop="scan_mode">
          <el-radio-group v-model="scanForm.scan_mode">
            <el-radio-button value="quick">快速扫描</el-radio-button>
            <el-radio-button value="standard">标准扫描</el-radio-button>
            <el-radio-button value="stealth_light">隐蔽-轻度</el-radio-button>
            <el-radio-button value="stealth_medium">隐蔽-中度</el-radio-button>
            <el-radio-button value="stealth_deep">隐蔽-深度</el-radio-button>
            <el-radio-button value="custom">自定义</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-alert v-if="scanForm.scan_mode && scanForm.scan_mode.startsWith('stealth')" type="warning" :closable="false" style="margin-bottom:16px">
          隐蔽模式扫描速度极慢，可能需要数小时完成，但可有效避免防火墙和IDS检测
        </el-alert>
        <el-form-item label="扫描方法" prop="scan_methods">
          <el-checkbox-group v-model="scanForm.scan_methods">
            <el-checkbox value="nmap_syn">SYN扫描</el-checkbox>
            <el-checkbox value="nmap_connect">全连接扫描</el-checkbox>
            <el-checkbox value="nmap_udp">UDP扫描</el-checkbox>
            <el-checkbox value="nmap_service">服务识别</el-checkbox>
            <el-checkbox value="nmap_os">OS识别</el-checkbox>
            <el-checkbox value="nmap_script">脚本扫描</el-checkbox>
            <el-checkbox value="masscan">Masscan</el-checkbox>
            <el-checkbox value="fping">fping</el-checkbox>
            <el-checkbox value="arp_scan">ARP扫描</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item label="端口范围">
          <el-input v-model="scanForm.ports" placeholder="可选，如 1-1000 或 22,80,443" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="submitting" @click="handleSubmit">开始扫描</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card style="margin-top:20px">
      <template #header><span>扫描历史</span></template>
      <el-table :data="scanStore.scans" stripe border>
        <el-table-column prop="name" label="名称" width="150" />
        <el-table-column prop="targets" label="目标" show-overflow-tooltip />
        <el-table-column prop="scan_mode" label="模式" width="120">
          <template #default="{ row }">{{ modeLabel(row.scan_mode) }}</template>
        </el-table-column>
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
    </el-card>

    <el-dialog v-model="detailVisible" title="扫描详情" width="80%">
      <el-table v-if="scanStore.currentScan" :data="scanStore.results" stripe border>
        <el-table-column prop="ip" label="IP" width="150" />
        <el-table-column prop="hostname" label="主机名" width="150" />
        <el-table-column prop="os" label="操作系统" width="150" />
        <el-table-column label="开放端口" min-width="200">
          <template #default="{ row }">
            <span v-for="p in (row.ports || [])" :key="p.port" style="margin-right:8px">{{ p.port }}/{{ p.service || p.proto }}</span>
          </template>
        </el-table-column>
      </el-table>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { useScanStore } from '../stores/scan'
import { ElMessage } from 'element-plus'

const scanStore = useScanStore()
const scanFormRef = ref(null)
const submitting = ref(false)
const detailVisible = ref(false)

const scanForm = reactive({ name: '', targets: '', scan_mode: 'standard', scan_methods: ['nmap_syn', 'nmap_service'], ports: '' })
const scanRules = {
  name: [{ required: true, message: '请输入任务名称', trigger: 'blur' }],
  targets: [{ required: true, message: '请输入扫描目标', trigger: 'blur' }],
  scan_mode: [{ required: true, message: '请选择扫描模式', trigger: 'change' }]
}

const modeLabel = (m) => ({ quick: '快速', standard: '标准', stealth_light: '隐蔽-轻度', stealth_medium: '隐蔽-中度', stealth_deep: '隐蔽-深度', custom: '自定义' }[m] || m)
const statusType = (s) => ({ pending: 'info', running: 'warning', completed: 'success', failed: 'danger', cancelled: 'info' }[s] || 'info')
const statusLabel = (s) => ({ pending: '等待中', running: '扫描中', completed: '已完成', failed: '失败', cancelled: '已取消' }[s] || s)

const handleSubmit = async () => {
  const valid = await scanFormRef.value.validate().catch(() => false)
  if (!valid) return
  submitting.value = true
  try {
    await scanStore.createScan(scanForm)
    scanForm.name = ''
    scanForm.targets = ''
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '创建失败')
  } finally { submitting.value = false }
}

const viewDetail = async (row) => {
  await scanStore.fetchScanDetail(row.id)
  detailVisible.value = true
}

const handleCancel = async (row) => {
  try { await scanStore.cancelScan(row.id) } catch (e) { ElMessage.error('取消失败') }
}

onMounted(() => { scanStore.fetchScans() })
</script>
