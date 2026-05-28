import api from './index'

// Legacy endpoints (backward compat)
export const createScan = (data) => api.post('/scans', data)
export const getScans = (params) => api.get('/scans', { params })
export const getScanDetail = (id) => api.get("/scans/" + id)
export const cancelScan = (id) => api.post("/scans/" + id + "/cancel")
export const updateScan = (id, data) => api.put("/scans/" + id, data)
export const activateScan = (id) => api.post("/scans/" + id + "/activate")
export const deactivateScan = (id) => api.post("/scans/" + id + "/deactivate")
export const deleteScan = (id) => api.delete("/scans/" + id)
export const rescanScan = (id) => api.post("/scans/" + id + "/rescan")

// Host discovery
export const createHostScan = (data) => api.post('/host-scans', data)
export const getHostScans = (params) => api.get('/host-scans', { params })
export const getHostScanDetail = (id) => api.get('/host-scans/' + id)
export const cancelHostScan = (id) => api.post('/host-scans/' + id + '/cancel')
export const activateHostScan = (id) => api.post('/host-scans/' + id + '/activate')
export const deactivateHostScan = (id) => api.post('/host-scans/' + id + '/deactivate')
export const updateHostScan = (id, data) => api.put('/host-scans/' + id, data)
export const deleteHostScan = (id) => api.delete('/host-scans/' + id)
export const rescanHostScan = (id) => api.post('/host-scans/' + id + '/rescan')

// Service discovery
export const createServiceScan = (data) => api.post('/service-scans', data)
export const getServiceScans = (params) => api.get('/service-scans', { params })
export const getServiceScanDetail = (id) => api.get('/service-scans/' + id)
export const cancelServiceScan = (id) => api.post('/service-scans/' + id + '/cancel')
export const activateServiceScan = (id) => api.post('/service-scans/' + id + '/activate')
export const deactivateServiceScan = (id) => api.post('/service-scans/' + id + '/deactivate')
export const updateServiceScan = (id, data) => api.put('/service-scans/' + id, data)
export const deleteServiceScan = (id) => api.delete('/service-scans/' + id)
export const rescanServiceScan = (id) => api.post('/service-scans/' + id + '/rescan')
