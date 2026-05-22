import api from './index'

export const getSettings = () => api.get('/settings')
export const getSetting = (key) => api.get("/settings/" + key)
export const updateSetting = (key, value) => api.put("/settings/" + key, { value })
export const resetSetting = (key) => api.post("/settings/" + key + "/reset")
