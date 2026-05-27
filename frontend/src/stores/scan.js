import { defineStore } from 'pinia'
import { createScan as createScanApi, getScans as getScansApi, getScanDetail as getScanDetailApi, cancelScan as cancelScanApi, updateScan as updateScanApi } from '../api/discovery'
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
    async updateScan(id, data) {
      const res = await updateScanApi(id, data)
      ElMessage.success('扫描任务已更新')
      await this.fetchScans()
      return res.data
    },
    connectScanWs(taskId) {
      if (this.ws) this.ws.close()
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const host = window.location.host
      const token = localStorage.getItem('token') || ''
      this.ws = new WebSocket(protocol + "//" + host + "/api/scans/ws/scan/" + taskId + "?token=" + encodeURIComponent(token))
      this.ws.onmessage = (event) => {
        const data = JSON.parse(event.data)
        if (this.currentScan && this.currentScan.id === taskId) {
          this.currentScan.progress = data.progress
          this.currentScan.status = data.status
          if (data.scan_log) {
            this.currentScan.scan_log = data.scan_log
          }
          if (data.result_summary) {
            this.currentScan.result_summary = data.result_summary
            if (data.result_summary.new_results && data.result_summary.new_results.length > 0) {
              for (const r of data.result_summary.new_results) {
                const exists = this.results.find(e => e.id === r.id)
                if (!exists) {
                  this.results.push(r)
                } else {
                  const idx = this.results.indexOf(exists)
                  const mergedPorts = [...(exists.ports || []), ...(r.ports || [])]
                  const uniquePorts = []
                  const seen = new Set()
                  for (const p of mergedPorts) {
                    const key = p.port + '/' + (p.proto || 'tcp')
                    if (!seen.has(key)) {
                      seen.add(key)
                      uniquePorts.push(p)
                    }
                  }
                  this.results[idx] = { ...exists, ...r, ports: uniquePorts }
                }
              }
            }
          }
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
