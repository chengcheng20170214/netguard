import api from './index'

export const login = (username, password) => api.post('/auth/login', { username, password })
export const register = (data) => api.post('/auth/register', data)
export const refreshToken = (refresh_token) => api.post('/auth/refresh', { refresh_token })
export const getMe = () => api.get('/auth/me')
