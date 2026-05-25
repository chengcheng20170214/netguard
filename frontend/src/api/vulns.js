import api from './index'

export const getVulns = (params) => api.get('/vulns', { params })
export const getVuln = (id) => api.get("/vulns/" + id)
export const markFalsePositive = (id) => api.put("/vulns/" + id + "/false-positive")
export const scanVulns = (assetId) => api.post('/vulns/scan', { asset_id: assetId })
export const scanAllVulns = () => api.post('/vulns/scan-all')
export const updateVulnDBFull = () => api.post('/vulns/update-db/full')
export const updateVulnDBIncremental = () => api.post('/vulns/update-db/incremental')
export const getUpdateProgress = () => api.get('/vulns/update-db/progress')
export const getVulnDBStatus = () => api.get('/vulns/db-status')
export const configureAutoScan = (config) => api.put('/vulns/auto-scan', config)
