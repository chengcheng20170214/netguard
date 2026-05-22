import { defineStore } from 'pinia'
import { login as loginApi, register as registerApi, getMe } from '../api/auth'
import { ElMessage } from 'element-plus'
import router from '../router'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: localStorage.getItem('token') || '',
    user: JSON.parse(localStorage.getItem('user') || 'null')
  }),
  actions: {
    async login(username, password) {
      const res = await loginApi(username, password)
      this.token = res.data.access_token
      localStorage.setItem('token', this.token)
      if (res.data.refresh_token) {
        localStorage.setItem('refreshToken', res.data.refresh_token)
      }
      await this.fetchUser()
      router.push('/')
    },
    async register(data) {
      await registerApi(data)
      ElMessage.success('用户创建成功')
    },
    async fetchUser() {
      const res = await getMe()
      this.user = res.data
      localStorage.setItem('user', JSON.stringify(res.data))
    },
    logout() {
      this.token = ''
      this.user = null
      localStorage.removeItem('token')
      localStorage.removeItem('refreshToken')
      localStorage.removeItem('user')
      router.push('/login')
    }
  }
})
