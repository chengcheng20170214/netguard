<template>
  <div class="app-container" v-if="token">
    <el-container>
      <el-aside width="220px" class="app-sidebar">
        <div class="logo">
          <div class="logo-name">NetGuard</div>
          <div class="logo-version">v{{ appVersion }}</div>
        </div>
        <el-menu :default-active="$route.path" router background-color="#1d1e2c" text-color="#bfcbd9" active-text-color="#409eff">
          <el-menu-item index="/">
            <el-icon><Monitor /></el-icon>
            <span>仪表盘</span>
          </el-menu-item>
          <el-menu-item index="/host-discovery">
            <el-icon><Search /></el-icon>
            <span>主机发现</span>
          </el-menu-item>
          <el-menu-item index="/service-discovery">
            <el-icon><Connection /></el-icon>
            <span>服务发现</span>
          </el-menu-item>
          <el-menu-item index="/assets">
            <el-icon><Files /></el-icon>
            <span>资产管理</span>
          </el-menu-item>
          <el-menu-item index="/vulns">
            <el-icon><Warning /></el-icon>
            <span>漏洞检测</span>
          </el-menu-item>
          <el-menu-item v-if="user && user.role === 'admin'" index="/users">
            <el-icon><User /></el-icon>
            <span>用户管理</span>
          </el-menu-item>
          <el-menu-item v-if="user && user.role === 'admin'" index="/settings">
            <el-icon><Setting /></el-icon>
            <span>系统设置</span>
          </el-menu-item>
        </el-menu>
      </el-aside>
      <el-container>
        <el-header class="app-header">
          <span class="header-title">网络资产扫描系统</span>
          <div class="header-right">
            <span class="user-info">{{ user?.username }} ({{ roleLabel }})</span>
            <el-button type="danger" size="small" @click="handleLogout">退出</el-button>
          </div>
        </el-header>
        <el-main class="app-main">
          <router-view />
        </el-main>
      </el-container>
    </el-container>
  </div>
  <router-view v-else />
</template>

<script setup>
import { computed, ref, onMounted } from 'vue'
import { useAuthStore } from './stores/auth'
import { Monitor, Search, Files, Warning, User, Setting, Connection } from '@element-plus/icons-vue'
import api from './api/index'

const authStore = useAuthStore()
const token = computed(() => authStore.token)
const user = computed(() => authStore.user)
const appVersion = ref('...')

const fetchVersion = async () => {
  try {
    const res = await api.get('/health')
    appVersion.value = res.data.version || '—'
  } catch (e) {
    appVersion.value = '—'
  }
}

onMounted(() => { fetchVersion() })

const roleLabel = computed(() => {
  const map = { admin: '管理员', auditor: '审计员', guest: '访客' }
  return map[user.value?.role] || user.value?.role
})

const handleLogout = () => { authStore.logout() }
</script>
