import api from './index'

export const getAssets = (params) => api.get('/assets', { params })
export const getAsset = (id) => api.get("/assets/" + id)
export const updateAsset = (id, data) => api.put("/assets/" + id, data)
export const deleteAsset = (id) => api.delete("/assets/" + id)
export const getAssetChanges = (id, params) => api.get("/assets/" + id + "/changes", { params })
export const getAssetSnapshots = (id) => api.get("/assets/" + id + "/snapshots")
export const getAllChanges = (params) => api.get('/assets/changes', { params })
export const exportAssets = (format) => api.post('/assets/export', { format }, { responseType: 'blob' })
export const importAssets = (file) => {
  const formData = new FormData()
  formData.append('file', file)
  return api.post('/assets/import', formData, { headers: { 'Content-Type': 'multipart/form-data' } })
}
export const getKnownServices = (params) => api.get('/assets/services/', { params })
export const createKnownService = (data) => api.post('/assets/services/', data)
export const deleteKnownService = (id) => api.delete('/assets/services/' + id)
export const getAssetTargets = () => api.get('/assets/targets')
export const seedKnownServices = () => api.post('/assets/services/seed')
