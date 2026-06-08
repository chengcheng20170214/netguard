import api from './index'

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

// Scan profiles (扫描策略)
export const getScanProfiles = (params) => api.get('/scan-profiles', { params })
export const getScanProfilesBrief = () => api.get('/scan-profiles', { params: { brief: true } })
export const getScanProfile = (id) => api.get('/scan-profiles/' + id)
export const createScanProfile = (data) => api.post('/scan-profiles', data)
export const updateScanProfile = (id, data) => api.put('/scan-profiles/' + id, data)
export const deleteScanProfile = (id) => api.delete('/scan-profiles/' + id)
export const setDefaultScanProfile = (id) => api.put('/scan-profiles/' + id + '/default')

// Scan capabilities (扫描能力检测 & sudo 配置)
export const getScanCapabilities = () => api.get('/scan/capabilities')
export const setSudoPassword = (password) => api.put('/scan/capabilities/sudo-password', { password })
export const deleteSudoPassword = () => api.delete('/scan/capabilities/sudo-password')
export const verifySudoPassword = () => api.post('/scan/capabilities/verify-sudo')
export const toggleSudoEnabled = (enabled) => api.put('/scan/capabilities/sudo-enabled', null, { params: { enabled } })
