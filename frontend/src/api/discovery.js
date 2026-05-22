import api from './index'

export const createScan = (data) => api.post('/scans', data)
export const getScans = (params) => api.get('/scans', { params })
export const getScanDetail = (id) => api.get("/scans/" + id)
export const cancelScan = (id) => api.post("/scans/" + id + "/cancel")
