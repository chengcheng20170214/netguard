import { defineStore } from 'pinia'
import { createScan as createScanApi, getScans as getScansApi, getScanDetail as getScanDetailApi, cancelScan as cancelScanApi } from '../api/discovery'
import { ElMessage } from 'element-plus'

export const useScanStore = defineStore('scan', {
  state: () => ({
    scans: [],
    currentScan: null,
    results: [],
    ws: null
  }),
  actions: {
    async createScan(data) {
      const res = await createScanApi(data)
      ElMessage.success('扫描任务已创建')
      await this.fetchScans()
      return res.data
    },
    async fetchScans(params) {
      const res = await getScansApi(params)
      this.scans = res.data.items || res.data
    },
    async fetchScanDetail(id) {
      const res = await getScanDetailApi(id)
      this.currentScan = res.data
      this.results = res.data.results || []
    },
    async cancelScan(id) {
      await cancelScanApi(id)
      ElMessage.success('扫描任务已取消')
      await this.fetchScans()
    },
    connectScanWs(taskId) {
      if (this.ws) this.ws.close()
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const host = window.location.host
      this.ws = new WebSocket(protocol + "//" + host + "/api/ws/scan/" + taskId)
      this.ws.onmessage = (event) => {
        const data = JSON.parse(event.data)
        if (this.currentScan && this.currentScan.id === taskId) {
          this.currentScan.progress = data.progress
          this.currentScan.status = data.status
        }
      }
      this.ws.onclose = () => { this.ws = null }
    },
    disconnectScanWs() {
      if (this.ws) {
        this.ws.close()
        this.ws = null
      }
    }
  }
})
