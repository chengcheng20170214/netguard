import api from './index'

export const getVulns = (params) => api.get('/vulns', { params })
export const getVuln = (id) => api.get("/vulns/" + id)
export const markFalsePositive = (id) => api.put("/vulns/" + id + "/false-positive")
export const scanVulns = (assetId) => api.post('/vulns/scan', { asset_id: assetId })
